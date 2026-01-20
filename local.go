package xddr

import (
	"net"
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

func isStream(net string) bool {
	switch net {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
		return true
	default:
		return false
	}
}

func isDgram(net string) bool {
	switch net {
	case "udp", "udp4", "udp6", "unixgram":
		return true
	default:
		return false
	}
}

func Listen[T LocalLike](v T) (net.Listener, error) {
	n, a := Local(v).Split()
	return net.Listen(n, a)
}

func ListenPacket[T LocalLike](v T) (net.PacketConn, error) {
	n, a := Local(v).Split()
	return net.ListenPacket(n, a)
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
