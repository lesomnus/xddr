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
	} else if s[0] == '[' {
		// Bracketed IPv6 endpoint, add default scheme.
		s = "dns:///" + s
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

	if scheme, rest, ok := strings.Cut(s, ":"); ok {
		if w, err := sanitizeScheme(scheme); err == nil {
			scheme = w
		}
		switch scheme {
		case "dns", "xds":
			// <scheme>:[//<authority>/]<endpoint> where endpoint is <host>[:<port>].
			// The endpoint is sanitized as an Authority since it may contain a
			// bracketed IPv6 address, which the URL path does not allow.
			a := ""
			ep := rest
			if after, ok := strings.CutPrefix(rest, "//"); ok {
				if i := strings.Index(after, "/"); i < 0 {
					// Authority-style target such as "dns://grpc.io:50051"; keep as is.
					a, ep = after, ""
				} else {
					a, ep = after[:i], after[i+1:]
				}
			}
			if a == "" && ep == "" {
				return "", errors.New("missing endpoint")
			}
			if a != "" {
				w, err := Authority(a).Sanitize()
				if err != nil {
					return "", err
				}
				a = string(w)
			}
			if ep != "" {
				w, err := Authority(ep).Sanitize()
				if err != nil {
					return "", err
				}
				ep = string(w)
			}
			if ep == "" {
				return GRPC(scheme + "://" + a), nil
			}
			return GRPC(scheme + "://" + a + "/" + ep), nil
		}
	}

	u, err := URL(s).Sanitize()
	if err != nil {
		return "", err
	}

	s, h, a, p, q, f := u.split()
	if s == "unix" {
		// "unix:///absolute/path" or "unix:relative/path".
		h = a == ""
	}

	return GRPC(u.build(s, h, a, p, q, f)), nil
}

func (v GRPC) Scheme() string {
	return URL(v).Scheme()
}

// Authority returns the name-resolver authority of the gRPC target, i.e. the
// [authority] in the gRPC name resolution syntax scheme://[authority]/endpoint.
// An empty result means no explicit resolver was given, i.e. the default resolver.
//
// It is the counterpart of [GRPC.Endpoint], which reads the endpoint from the
// path. Note the ambiguity of the authority-style target "dns://host:port"
// (no path): there the authority doubles as the endpoint, so Authority and
// Endpoint return the same value. Bare and path-style inputs avoid this;
// Sanitize normalizes "host:port" to "dns:///host:port", keeping the authority
// empty.
func (v GRPC) Authority() Authority {
	return URL(v).Authority()
}

// Endpoint returns the target endpoint of the gRPC target.
// Note that for targets like "dns://resolver/host:port", the endpoint
// resides in the URL path, not in the URL authority, according to the
// gRPC name resolution syntax:
//
//	scheme://[authority]/endpoint
//
// If the path is empty, the URL authority is assumed to be the endpoint,
// so "dns://host:port" and "dns:///host:port" result the same endpoint.
// For "unix" scheme, it returns an empty Authority since a socket path
// is not a host-port pair; use [GRPC.Local] instead.
func (v GRPC) Endpoint() Authority {
	s, _, a, p, _, _ := URL(v).split()
	if s == "unix" {
		return ""
	}
	if p != "" {
		return Authority(p[1:])
	}
	return a
}

func (v GRPC) Host() Host {
	return v.Endpoint().Host()
}

func (v GRPC) Port() int {
	return v.Endpoint().Port()
}

func (v GRPC) WithHost(host string) (GRPC, error) {
	s, h, a, p, q, f := URL(v).split()
	if s == "unix" {
		return "", errors.New("unix target does not have a host")
	}
	if p != "" {
		ep, err := Authority(p[1:]).WithHost(host)
		if err != nil {
			return "", err
		}
		return GRPC(URL(v).build(s, h, a, "/"+string(ep), q, f)), nil
	}

	return transWithErr[GRPC](URL(v).WithHost(host))
}

func (v GRPC) WithHostX(host string) GRPC {
	return must(v.WithHost(host))
}

func (v GRPC) WithPort(port int) (GRPC, error) {
	s, h, a, p, q, f := URL(v).split()
	if s == "unix" {
		return "", errors.New("unix target does not have a port")
	}
	if p != "" {
		ep, err := Authority(p[1:]).WithPort(port)
		if err != nil {
			return "", err
		}
		return GRPC(URL(v).build(s, h, a, "/"+string(ep), q, f)), nil
	}

	return transWithErr[GRPC](URL(v).WithPort(port))
}

func (v GRPC) WithPortX(port int) GRPC {
	return must(v.WithPort(port))
}

func (v GRPC) Local() Local {
	u := URL(v)
	s, _, _, _, _, _ := u.split()
	switch s {
	case "dns", "xds":
		ep := v.Endpoint()
		net := "tcp"
		switch h := ep.Host(); {
		case h.IsIPv4():
			net = "tcp4"
		case h.IsIPv6():
			net = "tcp6"
		}
		return Local(net + ":" + ep.HostPort())

	case "ipv4":
		return Local("tcp4:" + string(v.Endpoint()))

	case "ipv6":
		return Local("tcp6:" + string(v.Endpoint()))

	case "unix":
		return Local("unix:" + u.Opaque())
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

func (v GRPCLocal) WithHostX(host string) GRPCLocal {
	return must(v.WithHost(host))
}

func (v GRPCLocal) WithPort(port int) (GRPCLocal, error) {
	return transWithErr[GRPCLocal](TCPUnixLocal(v).WithPort(port))
}

func (v GRPCLocal) WithPortX(port int) GRPCLocal {
	return must(v.WithPort(port))
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
				host = "[::1]"
			}
		case "0.0.0.0":
			host = "127.0.0.1"
		case "[::]":
			host = "[::1]"
		}
		return GRPC("dns:///" + host + ":" + port)

	case "unix":
		if strings.HasPrefix(addr, "/") {
			return GRPC("unix://" + addr)
		}
		// Relative path.
		return GRPC("unix:" + addr)
	}

	return GRPC("dns://" + addr)
}
