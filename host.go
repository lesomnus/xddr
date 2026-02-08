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
	if v == "" {
		return false
	}

	es := strings.SplitN(string(v), ".", 5)
	if len(es) != 4 {
		return false
	}
	for _, e := range es {
		if e == "" {
			return false
		}
		if len(e) > 1 && e[0] == '0' {
			return false
		}

		n, err := strconv.Atoi(e)
		if err != nil {
			return false
		}
		if n < 0 || n > 255 {
			return false
		}
	}
	return true
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

	return HostPort(string(h) + ":" + p), nil
}

func (v HostPort) Split() (Host, int, error) {
	s := string(v)
	i := strings.LastIndex(s, ":")

	h := Host(s[:i])
	p := s[i+1:]

	n, _ := strconv.Atoi(p)
	return h, n, nil
}
