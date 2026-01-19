package xddr

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Local represents a local network address which is usable for net package.
//
// Syntax:
//
//	<network>:<address>
//
// Examples:
//
//	:80
//	tcp:80
//	tcp4::80
//	tcp:0.0.0.0:443
//	udp:[::]:53
//	unix:/var/run/socket.sock
type Local string

func (v Local) Split() (network, address string) {
	network, address, _ = strings.Cut(string(v), ":")
	return
}

func (v Local) Network() string {
	w, _ := v.Split()
	return w
}

func (v Local) Address() string {
	_, w := v.Split()
	return w
}

type LocalLike interface {
	~string
	_localLike()
}

func NetworkOf[T LocalLike](v T) string {
	return Local(v).Network()
}

func AddressOf[T LocalLike](v T) string {
	return Local(v).Address()
}

func Listen[T LocalLike](v T) (net.Listener, error) {
	n, a := Local(v).Split()
	return net.Listen(n, a)
}

type TCPLocal string

func (v TCPLocal) _localLike() {}

func (v TCPLocal) Sanitize() (TCPLocal, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("empty TCP local address")
	}

	net, addr := Local(s).Split()
	if net == "" {
		// ":<port>"?
		if _, err := strconv.Atoi(addr); err != nil {
			return "", errors.New("invalid TCP local address")
		}
		return TCPLocal("tcp::" + addr), nil
	}

	switch net {
	case "tcp", "tcp4", "tcp6":
	default:
		// "<host>:<port>"?
		net = "tcp"
		addr = s
	}

	a, err := Authority(addr).Sanitize()
	if err != nil {
		return "", err
	}

	h := a.Host()
	switch {
	case h == "":
		switch net {
		case "tcp4":
			h = "0.0.0.0"
		case "tcp6":
			h = "[::]"
		}

	case h.IsIPv4():
		if net == "tcp6" {
			return "", errors.New("invalid TCP local address: IPv4 address with tcp6 network")
		}
		net = "tcp4"

	case h.IsIPv6():
		if net == "tcp4" {
			return "", errors.New("invalid TCP local address: IPv6 address with tcp4 network")
		}
		net = "tcp6"

	default:
		// unreachable?
		return "", errors.New("invalid TCP local address: host is not an IP address")
	}
	return TCPLocal(fmt.Sprintf("%s:%s:%d", net, h, a.Port())), nil
}

type UnixLocal string

func (v UnixLocal) Sanitize() (UnixLocal, error) {
	net, addr := Local(v).Split()
	if net == "" {
		net = "unix"
	}

	// Validate filepath?

	return UnixLocal(net + ":" + addr), nil
}
