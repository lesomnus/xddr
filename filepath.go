package xddr

import "strings"

// Filepath represents a [URL]-style file path in a filesystem so
// path must be URL but it is allowed to not have authority.
//
// Example:
//
//	file:/absolute/path.txt
//	file:./relative/path.txt
//	file:../relative/path.txt
//	file:///absolute/path.txt
//	file://./relative/path.txt
//	file://../relative/path.txt
type Filepath string

func (v Filepath) Sanitize() (Filepath, error) {
	s := string(v)
	if s == "" {
		return "file://.", nil
	}

	scheme, rest, ok := strings.Cut(s, ":")
	if !ok {
		rest = scheme
		scheme = ""
	}
	path, has_authority := strings.CutPrefix(rest, "//")
	if scheme == "" {
		scheme = "file"
	}

	starts_with_parent := strings.HasPrefix(path, "..")
	if starts_with_parent {
		path = "./" + path
	}

	u, err := URL(scheme + "://z/" + path).Sanitize()
	if err != nil {
		return "", err
	}

	p := u.Path()[1:]
	if starts_with_parent {
		p = strings.TrimPrefix(p, "./")
	}
	if p == "" {
		p = "/"
	}

	r := scheme + ":"
	if has_authority {
		r += "//"
	}
	r += p
	return Filepath(r), nil
}

func (v Filepath) split() (scheme string, h bool, path, query, fragment string) {
	s := string(v)

	scheme, s, _ = strings.Cut(s, ":")
	s, h = strings.CutPrefix(s, "//")
	if i := strings.IndexAny(path, "?#"); i < 0 {
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

func (v Filepath) Scheme() string {
	s := string(v)
	i := strings.Index(s, ":")
	if i < 0 {
		return s
	}
	return s[:i]
}

func (v Filepath) Path() string {
	_, _, w, _, _ := v.split()
	return w
}

func (v Filepath) Query() string {
	_, _, _, _, w := v.split()
	return w
}

func (v Filepath) Fragment() string {
	s := string(v)
	i := strings.Index(s, "#")
	if i < 0 {
		return ""
	}
	return s[i+1:]
}

func (v Filepath) build(s string, h bool, p, q, f string) Filepath {
	// "://" + "?" + "#"
	l := len(s) + len(p) + len(q) + len(f) + 5

	var r strings.Builder
	r.Grow(l)

	r.WriteString(s)
	r.WriteString(":")
	if h {
		r.WriteString("//")
	}
	r.WriteString(p)
	if q != "" {
		r.WriteString("?")
		r.WriteString(q)
	}
	if f != "" {
		r.WriteString("#")
		r.WriteString(f)
	}

	return Filepath(r.String())
}

func (v Filepath) WithPath(path string) (Filepath, error) {
	s, h, _, q, f := v.split()
	return v.build(s, h, path, q, f), nil
}
