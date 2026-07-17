package xddr

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IP represents union of IPv4 and IPv6 addresses.
//
// Examples:
//
//	(empty string) - unspecified IP address
//	0.0.0.0
//	127.0.0.1
//	::
//	::1
//	::ffff:192.168.0.1
//	2001:0db8:85a3::8a2e:370:7334
type IP string

func (v IP) Sanitize() (IP, error) {
	s := string(v)
	switch {
	case s == "":
		// Unspecified IP
		return "", nil
	case strings.Contains(s, ":"):
		// Note that ":" is tested first since an IPv4-mapped IPv6 address
		// such as "::ffff:192.0.2.128" contains "." as well.
		return transWithErr[IP](IPv6(s).Sanitize())
	case strings.Contains(s, "."):
		return transWithErr[IP](IPv4(s).Sanitize())
	default:
		return "", errors.New("invalid IP address")
	}
}

func (v IP) V4() (IPv4, bool) {
	if v == "" {
		return "0.0.0.0", true
	}
	if strings.Contains(string(v), ":") {
		return "", false
	}
	if strings.Contains(string(v), ".") {
		return IPv4(v), true
	}
	return "", false
}

func (v IP) V6() (IPv6, bool) {
	if v == "" {
		return "::", true
	}
	if strings.Contains(string(v), ":") {
		return IPv6(v), true
	}
	return "", false
}

func (v IP) Bytes() []byte {
	if ipv4, ok := v.V4(); ok {
		b4 := ipv4.Bytes()
		return b4[:]
	}
	if ipv6, ok := v.V6(); ok {
		b6 := ipv6.Bytes()
		return b6[:]
	}
	return nil
}

func (v IP) IsUnspecified() bool {
	if ipv4, ok := v.V4(); ok {
		return ipv4.IsUnspecified()
	}
	if ipv6, ok := v.V6(); ok {
		return ipv6.IsUnspecified()
	}
	return false
}

func (v IP) IsLoopback() bool {
	if ipv4, ok := v.V4(); ok {
		return ipv4.IsLoopback()
	}
	if ipv6, ok := v.V6(); ok {
		return ipv6.IsLoopback()
	}
	return false
}

func (v IP) IsPrivate() bool {
	if ipv4, ok := v.V4(); ok {
		return ipv4.IsPrivate()
	}
	if ipv6, ok := v.V6(); ok {
		return ipv6.IsPrivate()
	}
	return false
}

// IPPort represents an IP and port pair.
// IPv6 address is enclosed in square brackets to be distinguishable from the port separator.
//
// Examples:
//
//	:80 - unspecified IP address
//	127.0.0.1:80
//	[::1]:80
type IPPort string

func (v IPPort) Sanitize() (IPPort, error) {
	s := string(v)
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", errors.New("missing ':' separator for port")
	}
	if j := strings.Index(s, "]"); j >= 0 && i < j {
		// IPv6 without port
		return "", errors.New("missing ':' separator for port")
	}

	ip := IP(s[:i])
	port := s[i+1:]

	if ip_, err := ip.Sanitize(); err != nil {
		return "", err
	} else {
		ip = ip_
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("invalid port number: %w", err)
	} else if !(0 <= n && n <= 65535) {
		return "", errors.New("port number must be between 0 and 65535")
	}

	h := string(ip)
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	return IPPort(h + ":" + strconv.Itoa(n)), nil
}

func (v IPPort) split() (ip, port string) {
	s := string(v)
	i := strings.LastIndex(s, ":")
	if j := strings.Index(s, "]"); i < 0 || (j >= 0 && i < j) {
		return s, ""
	}

	return s[:i], s[i+1:]
}

func (v IPPort) Split() (IP, int) {
	ip, p := v.split()
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		ip = ip[1 : len(ip)-1]
	}
	if p == "" {
		return IP(ip), -1
	}

	n, _ := strconv.Atoi(p)
	return IP(ip), n
}

func (v IPPort) IP() IP {
	ip, _ := v.Split()
	return ip
}

func (v IPPort) Port() int {
	_, port := v.Split()
	return port
}

func (v IPPort) WithIP(ip string) (IPPort, error) {
	w, err := IP(ip).Sanitize()
	if err != nil {
		return "", err
	}

	h := string(w)
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}

	_, p := v.split()
	if p == "" {
		return IPPort(h), nil
	}
	return IPPort(h + ":" + p), nil
}

func (v IPPort) WithIPX(ip string) IPPort {
	return must(v.WithIP(ip))
}

func (v IPPort) WithPort(port int) (IPPort, error) {
	if !(0 <= port && port <= 65535) {
		return "", errors.New("port number must be between 0 and 65535")
	}

	ip, _ := v.split()
	return IPPort(ip + ":" + strconv.Itoa(port)), nil
}

func (v IPPort) WithPortX(port int) IPPort {
	return must(v.WithPort(port))
}

type IPwithCIDR string

func (v IPwithCIDR) Sanitize() (IPwithCIDR, error) {
	s := string(v)
	i := strings.LastIndex(s, "/")
	if i < 0 {
		return "", errors.New("missing '/' separator for CIDR")
	}
	if i == 0 {
		return "", errors.New("missing IP address before '/'")
	}

	ip := IP(s[:i])
	ns := s[i+1:]

	n, err := strconv.Atoi(ns)
	if err != nil {
		return "", errors.New("invalid network size")
	}

	switch {
	case strings.Contains(s, "."):
		ipv4, err := IPv4(ip).Sanitize()
		if err != nil {
			return "", err
		}
		if !(0 <= n && n <= 32) {
			return "", errors.New("network size must be between 0 and 32 for IPv4")
		}
		return IPwithCIDR(string(ipv4) + "/" + strconv.Itoa(n)), nil

	case strings.Contains(s, ":"):
		ipv6, err := IPv6(ip).Sanitize()
		if err != nil {
			return "", err
		}
		if !(0 <= n && n <= 128) {
			return "", errors.New("network size must be between 0 and 128 for IPv6")
		}
		return IPwithCIDR(string(ipv6) + "/" + strconv.Itoa(n)), nil

	default:
		return "", errors.New("invalid IP address")
	}
}

func (v IPwithCIDR) Split() (IP, int) {
	s := string(v)
	i := strings.LastIndex(s, "/")

	n, _ := strconv.Atoi(s[i+1:])

	return IP(s[:i]), n
}

func (v IPwithCIDR) IP() IP {
	ip, _ := v.Split()
	return ip
}

// Size returns the network size, i.e. the number after the '/'.
func (v IPwithCIDR) Size() int {
	_, n := v.Split()
	return n
}

func (v IPwithCIDR) Bytes() []byte {
	return v.IP().Bytes()
}

func (v IPwithCIDR) IsUnspecified() bool {
	return v.IP().IsUnspecified()
}

func (v IPwithCIDR) IsLoopback() bool {
	return v.IP().IsLoopback()
}

func (v IPwithCIDR) IsPrivate() bool {
	return v.IP().IsPrivate()
}

type IPv4 string

func (v IPv4) Sanitize() (IPv4, error) {
	es := strings.SplitN(string(v), ".", 5)
	if len(es) != 4 {
		return "", fmt.Errorf("must have 4 fields")
	}

	for i, e := range es {
		if e == "" {
			return "", errPosF(i, "empty")
		}
		if len(e) > 1 && e[0] == '0' {
			return "", errPosF(i, "leading zeros not allowed")
		}

		n, err := strconv.Atoi(e)
		if err != nil {
			return "", errPosF(i, "not a valid number")
		}
		if n < 0 || n > 255 {
			return "", errPosF(i, "must be between 0 and 255, got %d", n)
		}
	}

	return v, nil
}

func (v IPv4) Bytes() [4]byte {
	s := string(v)

	var b [4]byte
	es := strings.SplitN(s, ".", 5)
	l := min(len(es), 4)
	for i := 0; i < l; i++ {
		n, _ := strconv.Atoi(es[i])
		b[i] = byte(n)
	}

	return b
}

func (v IPv4) IsUnspecified() bool {
	return v == "0.0.0.0"
}

func (v IPv4) IsLoopback() bool {
	// 127.0.0.0/8
	return strings.HasPrefix(string(v), "127.")
}

func (v IPv4) IsPrivate() bool {
	b := v.Bytes()
	switch {
	case b[0] == 10:
		// 10.0.0.0/8
		return true
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
		// 172.16.0.0/12
		return true
	case b[0] == 192 && b[1] == 168:
		// 192.168.0.0/16
		return true
	default:
		return false
	}
}

type IPv6 string

func (v IPv6) Sanitize() (IPv6, error) {
	if v == "" {
		return "", fmt.Errorf("empty IPv6 address")
	}
	if v[0] == '[' {
		if v[len(v)-1] != ']' {
			return "", fmt.Errorf("missing closing ']'")
		}
		v = v[1 : len(v)-1]
	}

	es := strings.SplitN(string(v), ":", 9)
	if len(es) > 8 {
		return "", fmt.Errorf("must have at most 8 blocks")
	}
	if len(es) < 3 {
		return "", fmt.Errorf("must have at least 2 colons")
	}

	// A dotted-quad tail such as "::ffff:192.0.2.128" occupies the last two blocks.
	dotted := ""
	if e := es[len(es)-1]; strings.Contains(e, ".") {
		if _, err := IPv4(e).Sanitize(); err != nil {
			return "", fmt.Errorf("invalid IPv4-mapped IPv6 address: %w", err)
		}
		dotted = e
	}

	b := [8]uint16{}

	i := 0 // nth block currently being processed.
	j := 0 // nth block of input currently being processed.
	c := 0 // current run of zero blocks.
	l := 0 // longest run of zero blocks.
	t := 0 // tail index of longest run of zero blocks.
	has_ellipsis := false
	put := func(n uint16) {
		if n == 0 {
			c++
		} else {
			if c > l {
				l = c
				t = i
			}
			c = 0
			b[i] = n
		}
		i++
	}
	for ; j < len(es); j++ {
		e := es[j]
		if e == "" {
			if j == len(es)-1 {
				// "::" at the end
				if es[j-1] != "" {
					return "", fmt.Errorf("single ':' at the end is not allowed")
				}

				has_ellipsis = true
				c++
				break
			}
			if i != j {
				return "", fmt.Errorf("only one '::' allowed")
			}

			k := 9 - len(es) // length of current omitted zero blocks
			if dotted != "" {
				k--
			}
			if j == 0 {
				// "::" at the beginning
				if es[1] != "" {
					return "", fmt.Errorf("single ':' at the beginning is not allowed")
				}
				j++ // skip the next empty block
				k++ // already counted one empty block
			}
			has_ellipsis = true
			i += k
			c += k
			continue
		}
		if strings.Contains(e, ".") {
			if j != len(es)-1 {
				return "", fmt.Errorf("[%d]: IPv4-mapped address must be at the end", j)
			}
			if i > 6 {
				return "", fmt.Errorf("must have at most 8 blocks")
			}

			b4 := IPv4(e).Bytes()
			put(uint16(b4[0])<<8 | uint16(b4[1]))
			put(uint16(b4[2])<<8 | uint16(b4[3]))
			continue
		}
		if len(e) > 4 {
			return "", fmt.Errorf("[%d]: block too long", j)
		}

		n, err := strconv.ParseUint(e, 16, 16)
		if err != nil {
			return "", fmt.Errorf("[%d]: not a valid hex number", j)
		}
		put(uint16(n))
	}
	if !has_ellipsis && i != 8 {
		return "", fmt.Errorf("must have 8 blocks")
	}
	if c > l {
		l = c
		t = 8
	}
	if l < 2 {
		// do not shorten
		l = 0
		t = 8
	}

	if dotted != "" && b[5] == 0xffff && b[0]|b[1]|b[2]|b[3]|b[4] == 0 {
		// IPv4-mapped IPv6 address; keep the mixed notation.
		return IPv6("::ffff:" + dotted), nil
	}

	bs := make([]byte, 0, len("hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:"))

	// Shortening the longest run of zero blocks.
	i = 0
	h := t - l // head index of longest run of zero blocks.
	if h == 0 {
		bs = append(bs, "::"...)
		i = l
	}
	for ; i < 8; i++ {
		if i == h {
			bs = append(bs, ':')
			i += l - 1
			continue
		}
		s := fmt.Sprintf("%x:", b[i])
		bs = append(bs, s...)
	}
	if l > 0 && h+l == 8 {
		// The shortened run reaches the last block so the value ends with "::".
		return IPv6(bs), nil
	}
	return IPv6(bs[:len(bs)-1]), nil
}

func (v IPv6) Bytes() [16]byte {
	s := string(v)

	es := strings.SplitN(s, ":", 9)

	b := [16]byte{}
	l := min(len(es), 8)
	dotted := l > 0 && strings.Contains(es[l-1], ".")
	j := 0 // byte index being processed.
	for i := range l {
		e := es[i]
		if e == "" {
			if i == 0 || i == l-1 {
				j += 2
				continue
			}
			k := 9 - len(es)
			if dotted {
				// A dotted-quad tail occupies two blocks.
				k--
			}
			j += (k * 2)
			continue
		}
		if i == l-1 && dotted {
			b4 := IPv4(e).Bytes()
			copy(b[j:], b4[:])
			break
		}

		n, _ := strconv.ParseUint(e, 16, 16)
		b[j] = byte(n >> 8)
		b[j+1] = byte(n & 0xff)
		j += 2
	}

	return b
}

func (v IPv6) IsLoopback() bool {
	return v.Bytes() == [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
}

func (v IPv6) IsPrivate() bool {
	b := v.Bytes()
	switch {
	case b[0]&0b11111110 == 0xfc:
		// fc00::/7
		return true
	default:
		return false
	}
}

func (v IPv6) IsUnspecified() bool {
	return v == "::"
}

type ipBaseLocal struct {
	// net must be either "tcp" or "udp"
	net string
}

func (x ipBaseLocal) Sanitize(v string) (string, error) {
	if v == "" {
		return "", errors.New("empty local address")
	}

	netX := x.net
	net4 := x.net + "4"
	net6 := x.net + "6"

	net, addr := Local(v).Split()
	if net == "" {
		// ":<port>"?
		if _, err := strconv.Atoi(addr); err != nil {
			return "", errors.New("invalid local address")
		}
		return netX + "::" + addr, nil
	}

	switch net {
	case netX, net4, net6:
	default:
		// "<host>:<port>"?
		net = netX
		addr = v
	}

	a, err := Authority(addr).Sanitize()
	if err != nil {
		return "", err
	}
	if a.Userinfo() != "" {
		return "", errors.New("invalid local address: userinfo not allowed")
	}
	if a.Port() < 0 {
		return "", errors.New("invalid local address: missing port")
	}

	h := a.Host()
	switch {
	case h == "":
		switch net {
		case net4:
			h = "0.0.0.0"
		case net6:
			h = "[::]"
		}

	case h.IsIPv4():
		if net == net6 {
			return "", errors.New("invalid local address: IPv4 address with IPv6 network")
		}
		net = net4

	case h.IsIPv6():
		if net == net4 {
			return "", errors.New("invalid local address: IPv6 address with IPv4 network")
		}
		net = net6
	default:
		// Hostname; keep the network as is.
	}
	return net + ":" + string(h) + ":" + strconv.Itoa(a.Port()), nil
}
