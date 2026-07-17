package xddr

import (
	"errors"
	"fmt"
	"iter"
	"strings"
)

// URL represents a WEAK Uniform Resource Locator as defined in RFC 3986.
// Note that if scheme separator "://" is present, authority is expected to be present as well
// according to RFC 3986 but this type does not enforce that.
// Meaning that opaque part is treated as normal URL so `http:example.com` is valid URL.
//
// Syntax:
//
//	url = <scheme>:[//][<authority>][<path>][?<query>][#<fragment>]
//
// Example:
//
//	scheme         authority          path          query            fragment
//	|---|   |----------------------||------| |-----------------| |---------------|
//	https://user:pass@localhost:1234/foo/bar?key=value&answer=42#anchor-to-section
//	        |--------------------------------------------------------------------|
//	        |-------| |-------| |--|      Opaque
//	        userinfo     host   port
type URL string

func (URL) _urlLike() {}

// sanitizeScheme validates and normalizes a URL scheme to lowercase.
func sanitizeScheme(s string) (string, error) {
	if s == "" {
		return "", errors.New("missing scheme")
	}

	var r strings.Builder
	r.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if c, ok := lowerAlpha(b); ok {
			r.WriteByte(c)
			continue
		}
		if i > 0 && (isDigit(b) || b == '+' || b == '-' || b == '.') {
			r.WriteByte(b)
			continue
		}

		return "", errPosF(i, "invalid character %q in scheme", b)
	}

	return r.String(), nil
}

func (v URL) Sanitize() (URL, error) {
	s := string(v)
	pos := 0
	last := 0

	var r strings.Builder
	r.Grow(len(s))

	read_until_any := func(p string) (string, bool) {
		i := strings.IndexAny(s, p)
		if i < 0 {
			return s, false
		}

		t := s[:i]
		s = s[i:]
		pos += i
		return t, true
	}

	// §3.1. Scheme
	if scheme, ok := read_until_any(":"); !ok {
		return "", errors.New("missing scheme separator ':'")
	} else if w, err := sanitizeScheme(scheme); err != nil {
		return "", err
	} else {
		r.WriteString(w)
	}

	if _, ok := strings.CutPrefix(s[1:], "//"); ok {
		s = s[3:]
		r.WriteString("://")
		pos += len("://")
	} else {
		s = s[1:]
		r.WriteString(":")
		pos += len(":")
	}
	last = pos
	if s == "" {
		return URL(r.String()), nil
	}

	// §3.2. Authority
	authority, has_rest := read_until_any("/?#")
	if authority != "" {
		authority, err := Authority(authority).Sanitize()
		if err != nil {
			return "", accPosErr(err, last)
		}

		r.WriteString(string(authority))

		if !has_rest {
			return URL(r.String()), nil
		}
	}

	// §3.3. Path
	for {
		v, ok := read_until_any("/?#")
		for i := 0; i < len(v); i++ {
			n, err := sanitizeCharTo(&r, v[i:], isUrlPchar)
			if err != nil {
				return "", accPosErr(err, last+i)
			}
			if n == 0 {
				return "", errPosF(last+i, "invalid character %q in path", v[i])
			}

			i += n - 1
		}
		last += len(v)

		if !ok {
			return URL(r.String()), nil
		} else if s[0] == '/' {
			r.WriteByte('/')
			s = s[1:]
			last++
		} else {
			break
		}
	}
	if s == "" {
		return URL(r.String()), nil
	}

	// §3.4. Query
	if s[0] == '?' {
		s = s[1:]
		last++

		// An empty query is dropped.
		v, _ := read_until_any("#")
		if v != "" {
			r.WriteByte('?')
			for i := 0; i < len(v); i++ {
				n, err := sanitizeCharTo(&r, v[i:], func(c byte) bool {
					return isUrlPchar(c) || c == '/' || c == '?'
				})
				if err != nil {
					return "", accPosErr(err, last+i)
				}
				if n == 0 {
					return "", errPosF(last+i, "invalid character %q in query", v[i])
				}

				i += n - 1
			}
			last += len(v)
		}
	}
	if s == "" {
		return URL(r.String()), nil
	}

	// §3.5. Fragment
	if s[0] == '#' {
		s = s[1:]
		last++

		// An empty fragment is dropped.
		v, _ := read_until_any("#")
		if v != "" {
			r.WriteByte('#')
			for i := 0; i < len(v); i++ {
				n, err := sanitizeCharTo(&r, v[i:], func(b byte) bool {
					return isUrlPchar(b) || b == '/' || b == '?'
				})
				if err != nil {
					return "", accPosErr(err, last+i)
				}
				if n == 0 {
					return "", errPosF(last+i, "invalid character %q in fragment", v[i])
				}

				i += n - 1
			}
			last += len(v)
		}
	}

	return URL(r.String()), nil
}

func (v URL) split() (scheme string, h bool, authority Authority, path, query, fragment string) {
	s := string(v)

	if i := strings.Index(s, ":"); i >= 0 {
		scheme = s[:i]
		s = s[i+1:]
		s, h = strings.CutPrefix(s, "//")
	}
	if i := strings.IndexAny(s, "/?#"); i < 0 {
		authority = Authority(s)
		return
	} else {
		authority = Authority(s[:i])
		s = s[i:]
	}
	if i := strings.IndexAny(s, "?#"); i < 0 {
		path = s
		return
	} else {
		path = s[:i]
		s = s[i:]
	}
	if i := strings.Index(s, "#"); i < 0 {
		query = s[1:]
		return
	} else if i == 0 {
		fragment = s[1:]
	} else {
		query = s[1:i]
		fragment = s[i+1:]
	}

	return
}

func (v URL) Scheme() string {
	s := string(v)
	i := strings.Index(s, ":")
	if i < 0 {
		return s
	}
	return s[:i]
}

func (v URL) Authority() Authority {
	_, _, w, _, _, _ := v.split()
	return Authority(w)
}

func (v URL) Userinfo() string {
	return v.Authority().Userinfo()
}

func (v URL) Username() string {
	return v.Authority().Username()
}

func (v URL) Password() string {
	return v.Authority().Password()
}

func (v URL) Host() Host {
	a := v.Authority()
	return a.Host()
}

func (v URL) Port() int {
	a := v.Authority()
	return a.Port()
}

func (v URL) Path() string {
	_, _, _, w, _, _ := v.split()
	return w
}

func (v URL) Query() string {
	_, _, _, _, w, _ := v.split()
	return w
}

// Iterate over query parameters as defined by application/x-www-form-urlencoded.
// See https://url.spec.whatwg.org/#urlencoded-parsing
func (v URL) QueryParams() iter.Seq2[string, string] {
	q := v.Query()
	if q == "" {
		return func(yield func(string, string) bool) {}
	}

	p := ""
	return func(yield func(string, string) bool) {
		for q != "" {
			i := strings.Index(q, "&")
			if i < 0 {
				p = q
				q = ""
			} else {
				p = q[:i]
				q = q[i+1:]
			}

			if p == "" {
				continue
			}

			k, v, _ := strings.Cut(p, "=")
			if !yield(k, v) {
				return
			}
		}
	}
}

func (v URL) Fragment() string {
	s := string(v)
	i := strings.Index(s, "#")
	if i < 0 {
		return ""
	}
	return s[i+1:]
}

func (v URL) Target() string {
	h := v.Host()
	switch h {
	case "0.0.0.0":
		h = "127.0.0.1"
	case "[::]":
		h = "[::1]"
	}

	w, err := v.WithHost(string(h))
	if err != nil {
		return string(v)
	}
	return string(w)
}

func (v URL) Opaque() string {
	s := string(v)
	i := strings.Index(s, ":")
	if i < 0 {
		return ""
	}

	s = s[i+1:]
	s, _ = strings.CutPrefix(s, "//")
	return s
}

func (v URL) build(s string, h bool, a Authority, p, q, f string) URL {
	// "://" + "?" + "#"
	l := len(s) + len(a) + len(p) + len(q) + len(f) + 5

	var r strings.Builder
	r.Grow(l)

	r.WriteString(s)
	r.WriteString(":")
	if h {
		r.WriteString("//")
	}
	r.WriteString(string(a))
	r.WriteString(p)
	if q != "" {
		r.WriteString("?")
		r.WriteString(q)
	}
	if f != "" {
		r.WriteString("#")
		r.WriteString(f)
	}

	return URL(r.String())
}

func (v URL) WithScheme(scheme string) (URL, error) {
	w, err := sanitizeScheme(scheme)
	if err != nil {
		return "", err
	}

	s := string(v)
	i := strings.Index(s, ":")
	if i < 0 {
		return URL(w + ":" + s), nil
	}
	if s[:i] == w {
		return v, nil
	}
	return URL(w + s[i:]), nil
}

func (v URL) WithSchemeX(scheme string) URL {
	return must(v.WithScheme(scheme))
}

func (v URL) WithAuthority(authority string) (URL, error) {
	w, err := Authority(authority).Sanitize()
	if err != nil {
		return "", err
	}

	s, h, _, p, q, f := v.split()
	return v.build(s, h, w, p, q, f), nil
}

func (v URL) WithAuthorityX(authority string) URL {
	return must(v.WithAuthority(authority))
}

func (v URL) WithUserinfo(userinfo string) (URL, error) {
	s, h, a, p, q, f := v.split()
	a, err := a.WithUserinfo(userinfo)
	if err != nil {
		return "", err
	}

	return v.build(s, h, a, p, q, f), nil
}

func (v URL) WithUserinfoX(userinfo string) URL {
	return must(v.WithUserinfo(userinfo))
}

func (v URL) WithHost(host string) (URL, error) {
	s, h, a, p, q, f := v.split()
	a, err := a.WithHost(host)
	if err != nil {
		return "", err
	}

	return v.build(s, h, a, p, q, f), nil
}

func (v URL) WithHostX(host string) URL {
	return must(v.WithHost(host))
}

func (v URL) WithPort(port int) (URL, error) {
	s, h, a, p, q, f := v.split()
	a, err := a.WithPort(port)
	if err != nil {
		return "", err
	}

	return v.build(s, h, a, p, q, f), nil
}

func (v URL) WithPortX(port int) URL {
	return must(v.WithPort(port))
}

func (v URL) WithPath(path string) (URL, error) {
	s, h, a, _, q, f := v.split()
	return v.build(s, h, a, path, q, f), nil
}

func (v URL) WithPathX(path string) URL {
	return must(v.WithPath(path))
}

func (v URL) WithQuery(query string) (URL, error) {
	s, h, a, p, _, f := v.split()
	return v.build(s, h, a, p, query, f), nil
}

func (v URL) WithQueryX(query string) URL {
	return must(v.WithQuery(query))
}

func (v URL) WithFragment(fragment string) (URL, error) {
	s, h, a, p, q, _ := v.split()
	return v.build(s, h, a, p, q, fragment), nil
}

func (v URL) WithFragmentX(fragment string) URL {
	return must(v.WithFragment(fragment))
}

func isUrlUnreserved(c byte) bool {
	const url_chars_unreserved_symbols = "-._~"
	return isAlpha(c) || isDigit(c) || strings.Contains(url_chars_unreserved_symbols, string(c))
}

func isUrlPchar(c byte) bool {
	const url_chars_sub_delims = "!$&'()*+,;="
	return isUrlUnreserved(c) || strings.Contains(url_chars_sub_delims, string(c)) || c == ':' || c == '@'
}

func percent_decode(s string) (b byte, rest string, err error) {
	if len(s) < 3 {
		return 0, s, fmt.Errorf("incomplete percent-encoding")
	}
	if s[0] != '%' {
		panic("invalid call to percent_decode")
	}

	rest = s[3:]

	hi, ok := unhex(s[1])
	if !ok {
		return 0, s, errors.New("invalid percent-encoding")
	}

	lo, ok := unhex(s[2])
	if !ok {
		return 0, s, errors.New("invalid percent-encoding")
	}

	b = (hi << 4) | lo
	return
}

// URLLike is a constraint for string types that are syntactically a [URL].
//
// Note that the helpers below interpret the value using the plain URL grammar;
// scheme-specific semantics are not applied.
// For example, [PortOf] returns the port written in the authority (-1 if absent)
// and does not resolve scheme default ports like [HTTP.Port] does,
// and [GRPC] keeps its target endpoint in the path, which [HostOf] does not look at.
// Prefer the concrete type's own methods when they exist.
type URLLike interface {
	~string
	_urlLike()
}

func SchemeOf[T URLLike](v T) string {
	return URL(v).Scheme()
}

func AuthorityOf[T URLLike](v T) Authority {
	return URL(v).Authority()
}

func HostOf[T URLLike](v T) Host {
	return URL(v).Host()
}

// PortOf returns the port written in the authority component, or -1 if absent.
// It does not resolve scheme default ports; use the concrete type's Port method for that.
func PortOf[T URLLike](v T) int {
	return URL(v).Port()
}

func WithHost[T URLLike](v T, host string) (T, error) {
	u, err := URL(v).WithHost(host)
	if err != nil {
		return v, err
	}
	return T(u), nil
}

func WithHostX[T URLLike](v T, host string) T {
	return must(WithHost(v, host))
}
