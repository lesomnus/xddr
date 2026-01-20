package xddr

import "errors"

// TCPLocal or UnixLocal
type TCPUnixLocal string

func (v TCPUnixLocal) Sanitize() (TCPUnixLocal, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("empty local address")
	}

	switch s[0] {
	case ':', '[':
		w, err := TCPLocal(s).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUnixLocal(w), nil

	case '.', '/':
		w, err := UnixLocal(s).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUnixLocal("unix:" + w), nil
	}

	net, _ := Local(v).Split()
	switch net {
	case "", "tcp", "tcp4", "tcp6":
		w, err := TCPLocal(v).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUnixLocal(w), nil

	case "unix":
		w, err := UnixLocal(v).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUnixLocal(w), nil

	default:
		// "<host>:<port>"?
		w, err := TCPLocal(s).Sanitize()
		if err != nil {
			return "", err
		}
		return TCPUnixLocal(w), nil
	}
}

func (v TCPUnixLocal) WithHost(host string) (TCPUnixLocal, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}
	if host[0] == '.' || host[0] == '/' {
		return TCPUnixLocal("unix:" + host), nil
	}

	net, addr := Local(v).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
	default:
		return "", errors.New("not a TCP local address")
	}

	a, err := Authority(addr).WithHost(host)
	if err != nil {
		return "", err
	}

	h := a.Host()
	switch {
	case h.IsIPv4():
		net = "tcp4:"
	case h.IsIPv6():
		net = "tcp6:"
	default:
		net = "tcp:"
	}

	return TCPUnixLocal(net + string(a)), nil
}

func (v TCPUnixLocal) WithPort(port int) (TCPUnixLocal, error) {
	net, addr := Local(v).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
	default:
		return "", errors.New("not a TCP local address")
	}

	a, err := Authority(addr).WithPort(port)
	if err != nil {
		return "", err
	}

	return TCPUnixLocal(net + ":" + string(a)), nil
}
