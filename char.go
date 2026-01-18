package xddr

import "strings"

func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func upper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func lowerAlpha(c byte) (byte, bool) {
	if 'a' <= c && c <= 'z' {
		return c, true
	}
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A'), true
	}
	return 0, false
}

func upperAlpha(c byte) (byte, bool) {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A'), true
	}
	if 'A' <= c && c <= 'Z' {
		return c, true
	}
	return 0, false
}

func isAlpha(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// unhex converts a hexadecimal character into its value.
func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func sanitizeCharTo(r *strings.Builder, s string, test func(byte) bool) (int, error) {
	c := s[0]
	if test(c) {
		r.WriteByte(c)
		return 1, nil
	}
	if c == '%' {
		b, _, err := percent_decode(s)
		if err != nil {
			return 0, err
		}
		if test(b) {
			r.WriteByte(b)
		} else {
			r.WriteByte('%')
			r.WriteByte(upper(s[1]))
			r.WriteByte(upper(s[2]))
		}
		return 3, nil
	}

	return 0, nil
}
