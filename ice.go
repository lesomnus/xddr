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

	u.build(s, false, a, "", q, "")
	return ICE(u), nil
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

func (v ICE) WithPort(port int) (ICE, error) {
	s := URL(v).Scheme()
	port = v.mapPort(s, port)

	u, err := URL(v).WithPort(port)
	if err != nil {
		return "", err
	}
	return ICE(u), nil
}

type ICELocal string

func (ICELocal) _localLike() {}

func (v ICELocal) Sanitize() (ICELocal, error) {
	return transWithErr[ICELocal](TCPUDPLocal(v).Sanitize())
}

func (v ICELocal) Network() string {
	return Local(v).Network()
}

func (v ICELocal) Address() IPPort {
	return IPPort(Local(v).Address())
}

func (v ICELocal) IsStream() bool {
	return isStream(NetworkOf(v))
}

func (v ICELocal) IsDgram() bool {
	return isDgram(NetworkOf(v))
}
