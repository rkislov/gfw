package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/rkislov/gfw/internal/agent"
	"github.com/rkislov/gfw/internal/agentclient"
	"github.com/rkislov/gfw/internal/identity"
	"github.com/rkislov/gfw/internal/ipsec"
	"github.com/rkislov/gfw/internal/openvpn"
)

type portalProfile struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Endpoint string           `json:"endpoint,omitempty"`
	Networks []string         `json:"networks,omitempty"`
	Auth     *identity.Method `json:"auth,omitempty"`
	Ready    bool             `json:"ready"`
	ovpn     openvpn.Profile
	ike      ipsec.Tunnel
}

func (s *Server) portalProfiles(ctx context.Context, u identity.User) []portalProfile {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ovpn agent.OpenVPNState
	var wg agent.WireGuardState
	var ike agent.IPsecState
	loaded := map[string]bool{}
	profiles := make([]portalProfile, 0, len(u.Grants))
	for _, grant := range u.Grants {
		parts := strings.Split(grant, ":")
		p := portalProfile{ID: grant, Name: grant}
		if len(parts) < 2 || s.AgentSocket == "" {
			profiles = append(profiles, p)
			continue
		}
		switch parts[0] {
		case "openvpn":
			if !loaded[parts[0]] {
				_ = agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/openvpn", nil, &ovpn)
			}
			for _, i := range ovpn.Confirmed.Instances {
				if !ovpn.Enabled || !i.Enabled || i.ID != parts[1] || i.Mode != "server" {
					continue
				}
				for _, c := range i.Clients {
					if c.Username != u.Name {
						continue
					}
					endpoint := i.PublicEndpoint
					if endpoint == "" {
						endpoint = i.BindAddress
					}
					p.Name, p.Endpoint, p.Networks, p.Auth = i.Name, endpoint, i.ClientRoutes, i.Auth
					p.ovpn = openvpn.Profile{ID: i.ID, Name: i.Name, Remote: endpoint, Port: i.Port, Protocol: i.Protocol, ServerCertificateID: i.CertificateID, ClientCertificateID: c.CertificateID, Auth: i.Auth, Routes: i.ClientRoutes}
					p.Ready = s.PKI != nil && openvpn.ValidateProfile(p.ovpn) == nil
				}
			}
		case "wireguard":
			if !loaded[parts[0]] {
				_ = agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/wireguard", nil, &wg)
			}
			for _, t := range wg.Confirmed.Tunnels {
				if !wg.Enabled || !t.Enabled || t.ID != parts[1] || len(parts) != 3 {
					continue
				}
				for _, peer := range t.Peers {
					if peer.Enabled && peer.ID == parts[2] {
						p.Name, p.Endpoint, p.Networks = t.Name+" / "+peer.Name, t.ClientEndpoint, peer.ClientRoutes
						p.Ready = peer.KeyRef != "" && t.ClientEndpoint != "" && len(peer.ClientAddresses) > 0 && len(peer.ClientRoutes) > 0
					}
				}
			}
		case "ipsec":
			if !loaded[parts[0]] {
				_ = agentclient.Call(ctx, s.AgentSocket, "GET", "/v1/ipsec", nil, &ike)
			}
			for _, t := range ike.Confirmed.Tunnels {
				if ike.Enabled && t.Enabled && t.ID == parts[1] && t.Auth != nil && (!t.Auth.Certificate || t.ClientUser == u.Name) {
					p.Name, p.Endpoint, p.Networks, p.Auth = t.Name, t.PublicEndpoint, t.LocalNetworks, t.Auth
					p.ike, p.Ready = t, s.PKI != nil
				}
			}
		}
		loaded[parts[0]] = true
		profiles = append(profiles, p)
	}
	return profiles
}

func (s *Server) portalState(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if ok {
		respond(w, 200, map[string]any{"user": u, "profiles": s.portalProfiles(r.Context(), u)})
	}
}

func (s *Server) portalExport(w http.ResponseWriter, r *http.Request) {
	u, ok := s.portalUser(w, r)
	if !ok {
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if decode(w, r, &in) != nil || !identity.Grant.MatchString(in.ID) {
		fail(w, 400, "некорректный идентификатор профиля")
		return
	}
	if !u.HasGrant(in.ID) {
		fail(w, 404, "профиль недоступен")
		return
	}
	u.Grants = []string{in.ID}
	p := s.portalProfiles(r.Context(), u)[0]
	if !p.Ready {
		fail(w, 404, "профиль недоступен")
		return
	}
	current, err := s.identity.User(r.Context(), u.Name)
	if err != nil || current.Revision != u.Revision || current.Disabled {
		fail(w, 403, "назначения изменились, войдите заново")
		return
	}
	if err = s.Store.LogAuditActor(r.Context(), u.Name, "portal.export:"+p.ID, 0); err != nil {
		s.internal(w, err)
		return
	}
	var file []byte
	var name string
	parts := strings.Split(in.ID, ":")
	switch parts[0] {
	case "openvpn":
		var profile string
		profile, err = s.PKI.ExportOpenVPN(p.ovpn)
		file, name = []byte(profile), "gfw-openvpn.ovpn"
	case "wireguard":
		var out struct {
			Profile string `json:"profile"`
		}
		err = agentclient.Call(r.Context(), s.AgentSocket, "POST", "/v1/wireguard/export", map[string]string{"tunnel_id": parts[1], "peer_id": parts[2]}, &out)
		file, name = []byte(out.Profile), "gfw-wireguard.conf"
	case "ipsec":
		file, err = s.PKI.ExportIPsec(p.ike, u.Name)
		name = "gfw-ikev2.zip"
	}
	if err != nil {
		fail(w, 422, "не удалось выдать профиль: "+err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(file)
}
