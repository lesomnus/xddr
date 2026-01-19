package xddr

import (
	"fmt"
	"strconv"
	"strings"
)

// Authority represents the authority component of a URL.
// However, it allows empty host, which is used to represent all interfaces for local use.
//
// Syntax:
//
//	[<userinfo>@](<host>[:<port>] | :<port>)
//
// Examples:
//
//	:80
//	127.0.0.1:80
//	[::1]:80
//	localhost:80
//	user:pass@host:80
type Authority string

func (Authority) sanitizeUserinfo(s string) (string, error) {
	var r strings.Builder
	r.Grow(len(s))

	for i := 0; i < len(s); i++ {
		n, err := sanitizeCharTo(&r, s[i:], isUrlPchar)
		if err != nil {
			return "", errPos(i, err)
		}
		if n == 0 {
			return "", errPosF(i, "invalid character %q in userinfo", s[i])
		}

		i += n - 1
	}

	return r.String(), nil
}

func (v Authority) Sanitize() (Authority, error) {
	s := string(v)
	pos := 0

	var r strings.Builder
	r.Grow(len(s))

	hostport := s
	if i := strings.Index(s, "@"); i == 0 {
		// Remove empty userinfo.
		hostport = s[1:]
		pos++
	} else if i > 0 {
		userinfo := s[:i]
		hostport = s[i+1:]

		// §3.2.1. User Information
		w, err := v.sanitizeUserinfo(userinfo)
		if err != nil {
			return "", accPosErr(err, pos)
		}

		r.WriteString(w)
		r.WriteByte('@')
		pos++
	}

	host := hostport
	port := ""
	if hostport == "" {
		return "", errPosF(pos, "missing host")
	} else if hostport[0] == '[' {
		if i := strings.Index(hostport, "]"); i+1 < len("[::]") {
			return "", errPosF(pos, "invalid IPv6 address format")
		} else if len(hostport) > i+1 && hostport[i+1] == ':' {
			host = hostport[:i+1]
			port = hostport[i+1:]
		}
	} else if i := strings.LastIndex(hostport, ":"); i >= 0 {
		host = hostport[:i]
		port = hostport[i:]
	}

	// §3.2.2. Host
	if host == "" {
		// port only
	} else if host[0] == '[' {
		w, err := IPv6(host[1 : len(host)-1]).Sanitize()
		if err != nil {
			return "", errPosF(pos+1+posOf(err), "invalid IPv6 address: %w", err)
		}

		pos += len(host) + 1
		host = fmt.Sprintf("[%s]", string(w))
	} else if w, err := IPv4(host).Sanitize(); err == nil {
		pos += len(host)
		host = string(w)
	} else if w, err := Domain(host).Sanitize(); err == nil {
		pos += len(host)
		host = string(w)
	} else {
		return "", errPosF(pos+posOf(err), "invalid host: %w", err)
	}
	r.WriteString(host)

	// §3.2.3. Port
	if port != "" {
		if port == ":" {
			return "", errPosF(pos, "missing port number")
		}
		port = port[1:]
		pos++

		p := port
		for i := 0; i < len(p); i++ {
			c := p[i]
			if c != '0' {
				break
			}

			port = p[i+1:]
			pos++
		}
		for i := 0; i < len(port); i++ {
			c := port[i]
			if !isDigit(c) {
				return "", errPosF(pos+i, "invalid character %q in port", c)
			}
		}

		// pos += len(port)
		r.WriteString(":")
		r.WriteString(port)
	}

	return Authority(r.String()), nil
}

func (v Authority) String() string {
	s := string(v)

	i := strings.Index(s, "@")
	if i < 0 {
		return s
	}

	userinfo := s[:i]
	j := strings.Index(userinfo, ":")
	if j < 0 {
		return s
	}

	return s[:j+1] + "****" + s[i:]
}

func (v Authority) split() (userinfo, host, port string) {
	s := string(v)

	if i := strings.Index(s, "@"); i >= 0 {
		userinfo, s = s[:i], s[i+1:]
	}
	if s == "" {
		return
	}

	if s[0] == '[' {
		i := strings.Index(s, "]")
		if i < 0 {
			return
		}

		host = s[:i+1]
		if len(s) > i+1 {
			port = s[i+2:]
		}
		return
	}

	host, port, _ = strings.Cut(s, ":")
	return
}

func (v Authority) Userinfo() string {
	s := string(v)
	before, _, ok := strings.Cut(s, "@")
	if !ok {
		return ""
	}

	return before
}

func (v Authority) Username() string {
	s := v.Userinfo()

	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func (v Authority) Password() string {
	s := v.Userinfo()

	if i := strings.LastIndex(s, ":"); i >= 0 {
		return s[i+1:]
	} else {
		return ""
	}
}

func (v Authority) HostPort() string {
	s := string(v)
	before, after, ok := strings.Cut(s, "@")
	if ok {
		return after
	}

	return before
}

func (v Authority) Host() Host {
	_, host, _ := v.split()
	return Host(host)
}

func (v Authority) Port() int {
	_, _, port := v.split()
	if port == "" {
		return -1
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return n
}

func (v Authority) build(userinfo, host, port string) Authority {
	var r strings.Builder
	if userinfo != "" {
		r.WriteString(userinfo)
		r.WriteByte('@')
	}
	r.WriteString(host)
	if port != "" {
		r.WriteByte(':')
		r.WriteString(port)
	}
	return Authority(r.String())
}

func (v Authority) WithUserinfo(userinfo string) (Authority, error) {
	w, err := v.sanitizeUserinfo(userinfo)
	if err != nil {
		return "", err
	}

	_, h, p := v.split()
	return v.build(w, h, p), nil
}

func (v Authority) WithHost(host string) (Authority, error) {
	w, err := Host(host).Sanitize()
	if err != nil {
		return "", err
	}

	u, _, p := v.split()
	return v.build(u, string(w), p), nil
}

func (v Authority) WithPort(port int) (Authority, error) {
	u, h, p := v.split()
	if port < 0 {
		p = ""
	} else {
		p = strconv.Itoa(port)
	}

	return v.build(u, h, p), nil
}
