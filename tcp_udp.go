package xddr

import (
	"errors"
	"fmt"
)

type TCPLocal string

func (v TCPLocal) _localLike() {}

func (v TCPLocal) Sanitize() (TCPLocal, error) {
	w, err := ipBaseLocal{"tcp"}.Sanitize(string(v))
	if err != nil {
		return "", err
	}
	return TCPLocal(w), nil
}

type UDPLocal string

func (v UDPLocal) _localLike() {}

func (v UDPLocal) Sanitize() (UDPLocal, error) {
	w, err := ipBaseLocal{"udp"}.Sanitize(string(v))
	if err != nil {
		return "", err
	}
	return UDPLocal(w), nil
}

type TCPUDPLocal string

func (v TCPUDPLocal) Sanitize() (TCPUDPLocal, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("empty local address")
	}

	net, _ := Local(s).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
		w, err := TCPLocal(s).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUDPLocal(w), nil

	case "udp", "udp4", "udp6":
		w, err := UDPLocal(s).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUDPLocal(w), nil

	default:
		return "", fmt.Errorf("not a TCP or UDP local address: %s", net)
	}
}

func (v TCPUDPLocal) WithHost(host string) (TCPUDPLocal, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}
	if host[0] == '.' || host[0] == '/' {
		return TCPUDPLocal("unix:" + host), nil
	}

	net, addr := Local(v).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	default:
		return "", errors.New("not a TCP or UDP local address")
	}

	a, err := Authority(addr).WithHost(host)
	if err != nil {
		return "", err
	}

	h := a.Host()
	switch {
	case h.IsIPv4():
		net = net[:3] + "4:"
	case h.IsIPv6():
		net = net[:3] + "6:"
	default:
		net = net[:3] + ":"
	}

	return TCPUDPLocal(net + string(a)), nil
}

func (v TCPUDPLocal) WithPort(port int) (TCPUDPLocal, error) {
	net, addr := Local(v).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	default:
		return "", errors.New("not a TCP or UDP local address")
	}

	a, err := Authority(addr).WithPort(port)
	if err != nil {
		return "", err
	}

	return TCPUDPLocal(net + ":" + string(a)), nil
}
