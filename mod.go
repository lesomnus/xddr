package xddr

import "errors"

// tcp or unix.
type reliableLocal interface {
	~string
	_reliableLocal()
}

func reliableWithHost[T reliableLocal](v T, host string) (T, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}
	if host[0] == '.' || host[0] == '/' {
		return T("unix:" + host), nil
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

	return T(net + string(a)), nil
}

func reliableWithPort[T reliableLocal](v T, port int) (T, error) {
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

	return T(net + ":" + string(a)), nil
}
