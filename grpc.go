package xddr

import (
	"strconv"
	"strings"
)

type GRPC string

func (v GRPC) Sanitize() (GRPC, error) {
	s := string(v)
	if i := strings.Index(s, "://"); i >= 0 {
		// There is scheme.
	} else if i := strings.Index(s, ":"); i < 0 {
		// No scheme, add default.
		s = "dns://" + s
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
			s = "dns://" + s
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
