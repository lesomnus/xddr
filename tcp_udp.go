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

func (v TCPLocal) WithHost(host string) (TCPLocal, error) {
	return transWithErr[TCPLocal](TCPUDPLocal(v).WithHost(host))
}

func (v TCPLocal) WithHostX(host string) TCPLocal {
	return must(v.WithHost(host))
}

func (v TCPLocal) WithPort(port int) (TCPLocal, error) {
	return transWithErr[TCPLocal](TCPUDPLocal(v).WithPort(port))
}

func (v TCPLocal) WithPortX(port int) TCPLocal {
	return must(v.WithPort(port))
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

func (v UDPLocal) WithHost(host string) (UDPLocal, error) {
	return transWithErr[UDPLocal](TCPUDPLocal(v).WithHost(host))
}

func (v UDPLocal) WithHostX(host string) UDPLocal {
	return must(v.WithHost(host))
}

func (v UDPLocal) WithPort(port int) (UDPLocal, error) {
	return transWithErr[UDPLocal](TCPUDPLocal(v).WithPort(port))
}

func (v UDPLocal) WithPortX(port int) UDPLocal {
	return must(v.WithPort(port))
}

// TCPUDPLocal is a [TCPLocal] or a [UDPLocal].
type TCPUDPLocal string

func (TCPUDPLocal) _localLike() {}

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

func (v TCPUDPLocal) WithHostX(host string) TCPUDPLocal {
	return must(v.WithHost(host))
}

func (v TCPUDPLocal) WithPort(port int) (TCPUDPLocal, error) {
	if port < 0 {
		return "", errors.New("port number out of range")
	}

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

func (v TCPUDPLocal) WithPortX(port int) TCPUDPLocal {
	return must(v.WithPort(port))
}
