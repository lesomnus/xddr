package xddr

import (
	"fmt"
)

// ICE represents an ICE (Interactive Connectivity Establishment) URI.
// See RFC 7064 and 7065.
//
// Examples:
//
//	stun:example.com
//	stuns:example.com:5349
//	turn:example.com?transport=udp
//	turns:example.com:443?transport=tcp
type ICE string

func (ICE) _urlLike() {}

func (v ICE) Sanitize() (ICE, error) {
	u, err := URL(v).Sanitize()
	if err != nil {
		return "", err
	}

	s, _, a, p, q, f := u.split()
	if a.Userinfo() != "" || p != "" || f != "" {
		return "", fmt.Errorf("ICE URI must not have userinfo, path, or fragment")
	}

	switch s {
	case "stun", "stuns":
		if q != "" {
			return "", fmt.Errorf("STUN URI must not have query")
		}
	case "turn", "turns":
		for k, v := range u.QueryParams() {
			if k != "transport" {
				return "", fmt.Errorf("TURN URI query can only have 'transport' parameter, got %q", k)
			}
			if v != "udp" && v != "tcp" {
				return "", fmt.Errorf("TURN URI 'transport' parameter must be 'udp' or 'tcp', got %q", v)
			}
		}
	default:
		return "", fmt.Errorf("unexpected scheme %q", s)
	}

	port := a.Port()
	port = v.mapPort(s, port)

	a, err = a.WithPort(port)
	if err != nil {
		return "", err
	}

	return ICE(u.build(s, false, a, "", q, "")), nil
}

func (v ICE) mapPort(scheme string, port int) int {
	switch scheme {
	case "stun", "turn":
		if port == 3478 {
			return -1
		}
	case "stuns", "turns":
		if port == 5349 {
			return -1
		}
	}

	return port
}

func (v ICE) Scheme() string {
	return URL(v).Scheme()
}

func (v ICE) Authority() Authority {
	return URL(v).Authority()
}

func (v ICE) Host() Host {
	return URL(v).Host()
}

// Port returns the port of the URI.
// If the port is not present, default port of the scheme is returned.
func (v ICE) Port() int {
	port := URL(v).Authority().Port()
	if port > 0 {
		return port
	}

	scheme := URL(v).Scheme()
	switch scheme {
	case "stun", "turn":
		return 3478
	case "stuns", "turns":
		return 5349
	}

	// Invalid ICE.
	return -1
}

// Transport returns the value of the "transport" query parameter, or "" if absent.
func (v ICE) Transport() string {
	for k, w := range URL(v).QueryParams() {
		if k == "transport" {
			return w
		}
	}
	return ""
}

func (v ICE) WithHost(host string) (ICE, error) {
	return transWithErr[ICE](URL(v).WithHost(host))
}

func (v ICE) WithHostX(host string) ICE {
	return must(v.WithHost(host))
}

func (v ICE) WithPort(port int) (ICE, error) {
	s := URL(v).Scheme()
	port = v.mapPort(s, port)

	u, err := URL(v).WithPort(port)
	if err != nil {
		return "", err
	}
	return ICE(u), nil
}

func (v ICE) WithPortX(port int) ICE {
	return must(v.WithPort(port))
}

type ICELocal string

func (ICELocal) _localLike() {}

func (v ICELocal) Sanitize() (ICELocal, error) {
	return transWithErr[ICELocal](TCPUDPLocal(v).Sanitize())
}

func (v ICELocal) WithHost(host string) (ICELocal, error) {
	return transWithErr[ICELocal](TCPUDPLocal(v).WithHost(host))
}

func (v ICELocal) WithHostX(host string) ICELocal {
	return must(v.WithHost(host))
}

func (v ICELocal) WithPort(port int) (ICELocal, error) {
	return transWithErr[ICELocal](TCPUDPLocal(v).WithPort(port))
}

func (v ICELocal) WithPortX(port int) ICELocal {
	return must(v.WithPort(port))
}

func (v ICELocal) Network() string {
	return Local(v).Network()
}

// Address returns the address part as an [Authority] since the host may be
// an IP address, a hostname, or empty (all interfaces).
func (v ICELocal) Address() Authority {
	return Authority(Local(v).Address())
}

func (v ICELocal) IsStream() bool {
	return isStream(NetworkOf(v))
}

func (v ICELocal) IsDgram() bool {
	return isDgram(NetworkOf(v))
}
