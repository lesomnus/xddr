package xddr

import "strings"

// Union of IPv4, IPv6, or Domain.
type Host string

func (v Host) Sanitize() (Host, error) {
	s := string(v)
	if strings.Contains(s, ":") {
		w, err := IPv6(s).Sanitize()
		if err != nil {
			return "", err
		}
		return Host(w), nil
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
