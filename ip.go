package xddr

import (
	"fmt"
	"strconv"
	"strings"
)

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
	l := max(len(es), 4)
	for i := 0; i < l; i++ {
		n, _ := strconv.Atoi(es[i])
		b[i] = byte(n)
	}

	return b
}

func (v IPv4) IsLoopback() bool {
	// 127.0.0.0/8
	return strings.HasPrefix(string(v), "127.")
}

type IPv6 string

func (v IPv6) Sanitize() (IPv6, error) {
	es := strings.SplitN(string(v), ":", 9)
	if len(es) > 8 {
		return "", fmt.Errorf("must have at most 8 blocks")
	}
	if len(es) < 3 {
		return "", fmt.Errorf("must have at least 2 colons")
	}

	b := [8]uint16{}

	i := 0 // nth block currently being processed.
	j := 0 // nth block of input currently being processed.
	c := 0 // current run of zero blocks.
	l := 0 // longest run of zero blocks.
	t := 0 // tail index of longest run of zero blocks.
	for ; j < len(es); j++ {
		e := es[j]
		if e == "" {
			if j == len(es)-1 {
				// "::" at the end
				if es[j-1] != "" {
					return "", fmt.Errorf("single ':' at the end is not allowed")
				}

				c++
				break
			}
			if i != j {
				return "", fmt.Errorf("only one '::' allowed")
			}

			k := 9 - len(es) // length of current omitted zero blocks
			if j == 0 {
				// "::" at the beginning
				if es[1] != "" {
					return "", fmt.Errorf("single ':' at the beginning is not allowed")
				}
				j++ // skip the next empty block
				k++ // already counted one empty block
			}
			i += k
			c += k
			continue
		}
		if (b[5] == 0xffff && l == 5) || // "0:0:0:0:0:ffff:IPv4"
			// In the case of there is omitted zero blocks like: "::ffff:IPv4"
			(b[6] == 0xffff && l == 6) {
			// IPv4-mapped IPv6 address
			if _, err := IPv4(e).Sanitize(); err != nil {
				return "", fmt.Errorf("invalid IPv4-mapped IPv6 address: %w", err)
			}

			return IPv6("::ffff:" + e), nil
		}
		if len(e) > 4 {
			return "", fmt.Errorf("[%d]: block too long", j)
		}

		n, err := strconv.ParseUint(e, 16, 16)
		if err != nil {
			return "", fmt.Errorf("[%d]: not a valid hex number", j)
		}
		if n == 0 {
			c++
		} else {
			if c > l {
				l = c
				t = i
				c = 0
			}
			b[i] = uint16(n)
		}

		i++
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
	if b[7] == 0 {
		bs = append(bs, 'x')
	}

	return IPv6(bs[:len(bs)-1]), nil
}

func (v IPv6) Bytes() [16]byte {
	s := string(v)

	es := strings.SplitN(s, ":", 9)

	b := [16]byte{}
	l := min(len(es), 8)
	j := 0 // byte index being processed.
	for i := range l {
		e := es[i]
		if e == "" {
			if i == 0 || i == l-1 {
				j += 2
				continue
			}
			k := 9 - len(es)
			j += (k * 2)
			continue
		}
		if i == l-1 && strings.Contains(e, ".") {
			// IPv4-mapped IPv6 address
			ipv4 := IPv4(e)
			b4 := ipv4.Bytes()
			b[10] = 0xff
			b[11] = 0xff
			copy(b[12:], b4[:])
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
