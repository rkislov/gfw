package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

func (m Method) NAS(id string) string {
	return "gfw/" + id + "/" + strings.ReplaceAll(m.Arguments(), " ", "/")
}

func (s *Store) ServeRadius(conn *net.UDPConn, key string) {
	type reply struct {
		packet  []byte
		expires time.Time
	}
	var mu sync.Mutex
	cache := map[[32]byte]reply{}
	slots := make(chan struct{}, 8)
	for {
		buf := make([]byte, 4096)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.IsLoopback() {
			continue
		}
		req := buf[:n]
		user, pass, nas, ok := parseRadius(req, []byte(key))
		if !ok {
			continue
		}
		id := sha256.Sum256(append([]byte(from.String()), req...))
		mu.Lock()
		now := time.Now()
		if old, ok := cache[id]; ok && now.Before(old.expires) {
			mu.Unlock()
			if old.packet != nil {
				_, _ = conn.WriteToUDP(old.packet, from)
			}
			continue
		}
		if len(cache) >= 1024 {
			for k, v := range cache {
				if !now.Before(v.expires) {
					delete(cache, k)
				}
			}
		}
		if len(cache) >= 1024 {
			mu.Unlock()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			mu.Unlock()
			continue
		}
		cache[id] = reply{expires: now.Add(30 * time.Second)}
		mu.Unlock()
		go func() {
			defer func() { <-slots }()
			code := byte(3)
			parts := strings.Split(nas, "/")
			if len(parts) == 5 && parts[0] == "gfw" {
				method, e := parseMethod(parts[2], parts[3], parts[4])
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				// Charon validates the certificate in a separate IKE authentication round.
				if e == nil && s.verifyVPN(ctx, VPNRequest{Grant: "ipsec:" + parts[1], Username: user, Secret: pass, Method: method}, true) {
					code = 2
				}
			}
			packet := radiusReply(req, []byte(key), code)
			mu.Lock()
			cache[id] = reply{packet: packet, expires: time.Now().Add(30 * time.Second)}
			mu.Unlock()
			_, _ = conn.WriteToUDP(packet, from)
		}()
	}
}

func parseRadius(req, key []byte) (user, password, nas string, ok bool) {
	if len(req) < 20 || req[0] != 1 || int(binary.BigEndian.Uint16(req[2:4])) != len(req) {
		return
	}
	var encrypted []byte
	var macAt int
	for i := 20; i < len(req); {
		if len(req)-i < 2 {
			return
		}
		size := int(req[i+1])
		if size < 2 || size > len(req)-i {
			return
		}
		value := req[i+2 : i+size]
		switch req[i] {
		case 1:
			if user != "" || len(value) == 0 {
				return
			}
			user = string(value)
		case 2:
			if encrypted != nil || len(value) < 16 || len(value) > 128 || len(value)%16 != 0 {
				return
			}
			encrypted = value
		case 32:
			if nas != "" || len(value) == 0 {
				return
			}
			nas = string(value)
		case 80:
			if macAt != 0 || len(value) != 16 {
				return
			}
			macAt = i + 2
		}
		i += size
	}
	if user == "" || nas == "" || macAt == 0 || encrypted == nil {
		return
	}
	h := hmac.New(md5.New, key)
	h.Write(req[:macAt])
	h.Write(make([]byte, 16))
	h.Write(req[macAt+16:])
	if !hmac.Equal(req[macAt:macAt+16], h.Sum(nil)) {
		return
	}
	previous := req[4:20]
	plain := make([]byte, len(encrypted))
	defer clear(plain)
	for offset := 0; offset < len(encrypted); offset += 16 {
		hash := md5.New()
		hash.Write(key)
		hash.Write(previous)
		mask := hash.Sum(nil)
		previous = encrypted[offset : offset+16]
		for j := range 16 {
			plain[offset+j] = previous[j] ^ mask[j]
		}
	}
	value := bytes.TrimRight(plain, "\x00")
	if bytes.IndexByte(value, 0) >= 0 {
		return
	}
	return user, string(value), nas, true
}

func radiusReply(req, key []byte, code byte) []byte {
	out := make([]byte, 38)
	out[0], out[1], out[20], out[21] = code, req[1], 80, 18
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:20], req[4:20])
	h := hmac.New(md5.New, key)
	h.Write(out)
	copy(out[22:], h.Sum(nil))
	hash := md5.New()
	hash.Write(out)
	hash.Write(key)
	copy(out[4:20], hash.Sum(nil))
	return out
}
