package xddr

import (
	"errors"
	"strconv"
	"strings"
)

// Host represents a host component of Authority, and is a union of IPv4, IPv6, or Domain.
// Since Host is a part of Authority, IPv6 address must be enclosed in square brackets.
//
// Examples:
//
//	127.0.0.1
//	[::1]
//	example.com
type Host string

func (v Host) Sanitize() (Host, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("host is empty")
	}
	if s[0] == '[' || strings.Contains(s, ":") {
		w, err := IPv6(s).Sanitize()
		if err != nil {
			return "", err
		}
		return Host("[" + w + "]"), nil
	}
	if w, err := IPv4(s).Sanitize(); err == nil {
		return Host(w), nil
	}

	w, err := Domain(s).Sanitize()
	if err == nil {
		return Host(w), nil
	}
	return "", err
}

func (v Host) IPv4() (IPv4, bool) {
	ok := v.IsIPv4()
	if ok {
		return IPv4(v), true
	}
	return "", false
}

func (v Host) IPv6() (IPv6, bool) {
	ok := v.IsIPv6()
	if ok {
		return IPv6(v), true
	}
	return "", false
}

func (v Host) Domain() (Domain, bool) {
	ok := v.IsDomain()
	if ok {
		return Domain(v), true
	}
	return "", false
}

func (v Host) IsIPv4() bool {
	_, err := IPv4(v).Sanitize()
	return err == nil
}

func (v Host) IsIPv6() bool {
	return v != "" && v[0] == '['
}

func (v Host) IsDomain() bool {
	return !v.IsIPv4() && !v.IsIPv6()
}

// HostPort represents a host and port pair, where host is a union of IPv4, IPv6, or Domain.
//
// Examples:
//
//	127.0.0.1:443
//	[::1]:443
//	example.com:443
type HostPort string

func (v HostPort) Sanitize() (HostPort, error) {
	s := string(v)
	if s == "" {
		return "", errors.New("hostport is empty")
	}

	i := strings.LastIndex(s, ":")
	if j := strings.Index(s, "]"); i < 0 || (j >= 0 && i < j) {
		return "", errors.New("missing ':' separator for port")
	}

	h, err := Host(s[:i]).Sanitize()
	if err != nil {
		return "", err
	}

	p := s[i+1:]
	if p == "" {
		return "", errors.New("port is empty")
	}

	n, err := strconv.Atoi(p)
	if err != nil {
		return "", errors.New("port is not a valid number")
	}
	if !(0 <= n && n <= 65535) {
		return "", errors.New("port number out of range")
	}

	return HostPort(string(h) + ":" + strconv.Itoa(n)), nil
}

func (v HostPort) split() (host, port string) {
	s := string(v)
	i := strings.LastIndex(s, ":")
	if j := strings.Index(s, "]"); i < 0 || (j >= 0 && i < j) {
		return s, ""
	}

	return s[:i], s[i+1:]
}

func (v HostPort) Split() (Host, int) {
	h, p := v.split()
	if p == "" {
		return Host(h), -1
	}

	n, _ := strconv.Atoi(p)
	return Host(h), n
}

func (v HostPort) Host() Host {
	h, _ := v.Split()
	return h
}

func (v HostPort) Port() int {
	_, p := v.Split()
	return p
}

func (v HostPort) WithHost(host string) (HostPort, error) {
	w, err := Host(host).Sanitize()
	if err != nil {
		return "", err
	}

	_, p := v.split()
	if p == "" {
		return HostPort(w), nil
	}
	return HostPort(string(w) + ":" + p), nil
}

func (v HostPort) WithHostX(host string) HostPort {
	return must(v.WithHost(host))
}

func (v HostPort) WithPort(port int) (HostPort, error) {
	if !(0 <= port && port <= 65535) {
		return "", errors.New("port number out of range")
	}

	h, _ := v.split()
	return HostPort(h + ":" + strconv.Itoa(port)), nil
}

func (v HostPort) WithPortX(port int) HostPort {
	return must(v.WithPort(port))
}
