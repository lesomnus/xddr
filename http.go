package xddr

import "errors"

type HTTP string

func (v HTTP) _urlLike() {}

func (v HTTP) Sanitize() (HTTP, error) {
	u, err := URL(v).Sanitize()
	if err != nil {
		return "", err
	}

	s, _, a, p, f, q := u.split()
	if s != "http" && s != "https" {
		return "", errors.New("scheme is not http or https")
	}

	port := a.Port()
	port = v.mapPort(s, port)

	a, err = a.WithPort(port)
	if err != nil {
		return "", err
	}

	return HTTP(u.build(s, true, a, p, q, f)), nil
}

func (v HTTP) mapPort(scheme string, port int) int {
	if scheme == "http" && port == 80 {
		return -1
	}
	if scheme == "https" && port == 443 {
		return -1
	}

	return port
}

func (v HTTP) Port() int {
	port := URL(v).Authority().Port()
	if port > 0 {
		return port
	}

	scheme := URL(v).Scheme()
	if scheme == "http" {
		return 80
	}
	if scheme == "https" {
		return 443
	}

	// Invalid HTTP.
	return -1
}

func (v HTTP) WithPort(port int) (HTTP, error) {
	s := URL(v).Scheme()
	port = v.mapPort(s, port)

	u, err := URL(v).WithPort(port)
	if err != nil {
		return "", err
	}
	return HTTP(u), nil
}

type HTTPLocal string

func (v HTTPLocal) _localLike() {}

func (v HTTPLocal) Sanitize() (HTTPLocal, error) {
	return transWithErr[HTTPLocal](TCPUnixLocal(v).Sanitize())
}

func (v HTTPLocal) WithHost(host string) (HTTPLocal, error) {
	return transWithErr[HTTPLocal](TCPUnixLocal(v).WithHost(host))
}

func (v HTTPLocal) WithPort(port int) (HTTPLocal, error) {
	return transWithErr[HTTPLocal](TCPUnixLocal(v).WithPort(port))
}

func (v HTTPLocal) AsURL() HTTP {
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
		return HTTP("http://" + host + ":" + port)

	case "unix":
		return HTTP("unix://" + addr)
	}

	return HTTP("http://" + addr)
}
