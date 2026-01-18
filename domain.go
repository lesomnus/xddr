package xddr

import (
	"fmt"
	"iter"
	"strings"
)

type Domain string

// Sanitize validates and normalizes the domain name so that it can be used in a URL.
// Still, it does not conform to IDNA, UTS #46 or punycode.
func (v Domain) Sanitize() (Domain, error) {
	if v == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	n := 0     // nth label
	l := 0     // length of current label
	u := false // there is uppercase letter
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '.' {
			if l == 0 && i != len(v)-1 {
				return "", errPosF(i, "empty label")
			}
			l = 0
			n++
			continue
		}
		if l >= 63 {
			return "", errPosF(i, "label too long")
		}

		// first character of a label
		if 'a' <= c && c <= 'z' {
			// ok
		} else if 'A' <= c && c <= 'Z' {
			u = true
		} else if '0' <= c && c <= '9' {
			// ok
		} else if c == '-' {
			if l == 0 {
				return "", errPosF(i, "label cannot start with a hyphen")
			}
		} else {
			return "", errPosF(i, "invalid character %q", c)
		}

		l++
	}
	if u {
		return Domain(strings.ToLower(string(v))), nil
	}

	return v, nil
}

func (v Domain) Labels() iter.Seq[string] {
	return strings.SplitSeq(string(v), ".")
}
