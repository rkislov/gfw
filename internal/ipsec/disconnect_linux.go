//go:build linux

package ipsec

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rkislov/gfw/internal/vpncred"
	"github.com/strongswan/govici/vici"
)

func (l *Linux) Disconnect(tunnel Tunnel, id uint32, user string) error {
	if id == 0 || !l.daemon.alive() || !l.loaded[tunnel.ID] {
		return vpncred.ErrSessionGone
	}
	dialer := net.Dialer{Timeout: time.Second}
	session, err := vici.NewSession(
		vici.WithSocketPath(filepath.Join(l.daemon.dir, "vici")),
		vici.WithDialContext(dialer.DialContext),
	)
	if err != nil {
		return err
	}
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	name := ikeName(tunnel)
	idText := strconv.FormatUint(uint64(id), 10)
	query, err := vici.MarshalMessage(map[string]string{"ike": name, "ike-id": idText})
	if err != nil {
		return err
	}
	var matched bool
	for event, err := range session.CallStreaming(ctx, "list-sas", "list-sa", query) {
		if err != nil {
			return err
		}
		sa, ok := event.Get(name).(*vici.Message)
		if !ok || sa.Get("uniqueid") != idText || sa.Get("state") != "ESTABLISHED" {
			continue
		}
		// strongSwan omits remote-eap-id when it equals remote-id.
		identity, _ := sa.Get("remote-eap-id").(string)
		if identity == "" {
			identity, _ = sa.Get("remote-id").(string)
		}
		matched = identity == user
	}
	if !matched {
		return vpncred.ErrSessionGone
	}

	command, err := vici.MarshalMessage(map[string]string{"ike-id": idText, "force": "yes", "loglevel": "-1"})
	if err != nil {
		return err
	}
	reply, err := session.Call(ctx, "terminate", command)
	if reply != nil && reply.Get("matches") == "0" {
		return vpncred.ErrSessionGone
	}
	if err != nil {
		return err
	}
	if reply.Get("success") != "yes" || reply.Get("terminated") != "1" {
		return errors.New("strongSwan не подтвердил завершение выбранного IKE-сеанса")
	}
	return nil
}
