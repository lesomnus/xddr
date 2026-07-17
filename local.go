package xddr

import (
	"errors"
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

func (Local) _localLike() {}

// Sanitize validates and normalizes the local address based on its network.
// Unlike more specific types such as [TCPLocal], it does not infer a network
// from the address; the network must be given explicitly.
func (v Local) Sanitize() (Local, error) {
	net, _ := v.Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
		return transWithErr[Local](TCPLocal(v).Sanitize())
	case "udp", "udp4", "udp6":
		return transWithErr[Local](UDPLocal(v).Sanitize())
	case "unix", "unixgram", "unixpacket":
		return transWithErr[Local](UnixLocal(v).Sanitize())
	}

	return "", errors.New("unknown network: " + net)
}

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

// UnixLocal represents a local address of a Unix domain socket.
//
// Syntax:
//
//	[<network>:]<path>
//
// Examples:
//
//	/var/run/socket.sock
//	./relative.sock
//	unix:/var/run/socket.sock
//	unixgram:/var/run/socket.sock
type UnixLocal string

func (UnixLocal) _localLike() {}

func (v UnixLocal) Sanitize() (UnixLocal, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("empty local address")
	}

	net, addr, ok := strings.Cut(s, ":")
	switch {
	case !ok:
		// No ':' at all; the whole value is the path.
		net, addr = "unix", s
	case net == "unix", net == "unixgram", net == "unixpacket":
		// ok
	default:
		// ':' is a part of the path.
		net, addr = "unix", s
	}
	if addr == "" {
		return "", errors.New("empty socket path")
	}

	// Validate filepath?

	return UnixLocal(net + ":" + addr), nil
}
