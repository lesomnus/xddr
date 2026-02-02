package xddr

import (
	"errors"
	"strconv"
	"strings"
)

// GRPC represents a URL-like gRPC target.
//
// See https://grpc.io/docs/guides/custom-name-resolution/
//
// Examples:
//
//	dns:///grpc.io:50051
//	unix:///run/containerd/containerd.sock
//	xds:///wallet.grpcwallet.io
//	ipv4:198.51.100.123:50051
//
// Note that scheme is not limited to "dns", "unix", or "xds".
// Any scheme is allowed as long as it looks like a valid URL scheme.
type GRPC string

func (v GRPC) _urlLike() {}

func (v GRPC) Sanitize() (GRPC, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("empty gRPC address")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		// There is scheme.
	} else if i := strings.Index(s, ":"); i < 0 {
		// No scheme, add default.
		s = "dns:///" + s
	} else {
		j := strings.IndexAny(s[i:], "/?#")
		maybe_port := ""
		if j < 0 {
			maybe_port = s[i+1:]
		} else {
			maybe_port = s[i+1 : i+j]
		}

		if _, err := strconv.Atoi(maybe_port); err != nil {
			// Not a port, it is assumed that there is a scheme and URL is opaque.
		} else {
			// It is a port, add default scheme.
			s = "dns:///" + s
		}
	}

	u, err := URL(s).Sanitize()
	if err != nil {
		return "", err
	}

	s, h, a, p, q, f := u.split()
	switch s {
	case "dns", "unix", "xds":
		h = true
	}

	return GRPC(u.build(s, h, a, p, q, f)), nil
}

func (v GRPC) Authority() Authority {
	return URL(v).Authority()
}

func (v GRPC) Host() Host {
	a := v.Authority()
	return a.Host()
}

func (v GRPC) Port() int {
	a := v.Authority()
	return a.Port()
}

func (v GRPC) Local() Local {
	u := URL(v)
	s, _, a, p, _, _ := u.split()
	switch s {
	case "dns":
		return Local("tcp4:" + a.HostPort())
	case "unix":
		return Local("unix:" + p)
	}

	return Local(s + ":" + u.Opaque())
}

type GRPCLocal string

func (v GRPCLocal) _localLike() {}

func (v GRPCLocal) Sanitize() (GRPCLocal, error) {
	return transWithErr[GRPCLocal](TCPUnixLocal(v).Sanitize())
}

func (v GRPCLocal) WithHost(host string) (GRPCLocal, error) {
	return transWithErr[GRPCLocal](TCPUnixLocal(v).WithHost(host))
}

func (v GRPCLocal) WithPort(port int) (GRPCLocal, error) {
	return transWithErr[GRPCLocal](TCPUnixLocal(v).WithPort(port))
}

func (v GRPCLocal) AsURL() GRPC {
	net, addr := Local(v).Split()
	switch net {
	case "tcp", "tcp4", "tcp6":
		_, host, port := Authority(addr).split()
		switch host {
		case "":
			switch net {
			case "tcp", "tcp4":
				host = "127.0.0.1"
			case "tcp6":
				host = "::1"
			}
		case "0.0.0.0":
			host = "127.0.0.1"
		case "[::]":
			host = "[::1]"
		}
		return GRPC("dns:///" + host + ":" + port)

	case "unix":
		return GRPC("unix://" + addr)
	}

	return GRPC("dns://" + addr)
}
