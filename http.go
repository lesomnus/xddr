package xddr

import "errors"

type HTTP string

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
