package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestURL(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.URL
			normalized xddr.URL

			scheme    string
			authority xddr.Authority
			path      string
			query     string
			fragment  string
		}{
			// Opaque.
			{
				"scheme:",
				"scheme:",
				"scheme", "", "", "", ""},
			{
				"scheme:?",
				"scheme:",
				"scheme", "", "", "", ""},
			{
				"scheme:#",
				"scheme:",
				"scheme", "", "", "", ""},
			{
				"scheme:?#",
				"scheme:",
				"scheme", "", "", "", ""},

			// Hierarchical.
			{
				"scheme://",
				"scheme://",
				"scheme", "", "", "", ""},
			{
				"scheme://?",
				"scheme://",
				"scheme", "", "", "", ""},
			{
				"scheme://#",
				"scheme://",
				"scheme", "", "", "", ""},
			{
				"scheme://?#",
				"scheme://",
				"scheme", "", "", "", ""},

			// Authority.
			{
				"scheme:host:80",
				"scheme:host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme:host:80?",
				"scheme:host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme:host:80#",
				"scheme:host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme:host:80?#",
				"scheme:host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme://host:80",
				"scheme://host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme://host:80?",
				"scheme://host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme://host:80#",
				"scheme://host:80",
				"scheme", "host:80", "", "", ""},
			{
				"scheme://host:80?#",
				"scheme://host:80",
				"scheme", "host:80", "", "", ""},

			// Path.
			{
				"scheme:/",
				"scheme:/",
				"scheme", "", "/", "", ""},
			{
				"scheme:/?",
				"scheme:/",
				"scheme", "", "/", "", ""},
			{
				"scheme:/#",
				"scheme:/",
				"scheme", "", "/", "", ""},
			{
				"scheme:/?#",
				"scheme:/",
				"scheme", "", "/", "", ""},
			{
				"scheme:///",
				"scheme:///",
				"scheme", "", "/", "", ""},
			{
				"scheme:///?",
				"scheme:///",
				"scheme", "", "/", "", ""},
			{
				"scheme:///#",
				"scheme:///",
				"scheme", "", "/", "", ""},
			{
				"scheme:///?#",
				"scheme:///",
				"scheme", "", "/", "", ""},

			{
				"scheme:/path/foo",
				"scheme:/path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:/path/foo?",
				"scheme:/path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:/path/foo#",
				"scheme:/path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:/path/foo?#",
				"scheme:/path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:///path/foo",
				"scheme:///path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:///path/foo?",
				"scheme:///path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:///path/foo#",
				"scheme:///path/foo",
				"scheme", "", "/path/foo", "", ""},
			{
				"scheme:///path/foo?#",
				"scheme:///path/foo",
				"scheme", "", "/path/foo", "", ""},

			// Number of slashes matters.
			{
				"dns:/path/foo:443",
				"dns:/path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:/path/foo:443?",
				"dns:/path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:/path/foo:443#",
				"dns:/path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:/path/foo:443?#",
				"dns:/path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns://path/foo:443",
				"dns://path/foo:443",
				"dns", "path", "/foo:443", "", ""},
			{
				"dns://path/foo:443?",
				"dns://path/foo:443",
				"dns", "path", "/foo:443", "", ""},
			{
				"dns://path/foo:443#",
				"dns://path/foo:443",
				"dns", "path", "/foo:443", "", ""},
			{
				"dns://path/foo:443?#",
				"dns://path/foo:443",
				"dns", "path", "/foo:443", "", ""},
			{
				"dns:///path/foo:443",
				"dns:///path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:///path/foo:443?",
				"dns:///path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:///path/foo:443#",
				"dns:///path/foo:443",
				"dns", "", "/path/foo:443", "", ""},
			{
				"dns:///path/foo:443?#",
				"dns:///path/foo:443",
				"dns", "", "/path/foo:443", "", ""},

			// Query.
			{
				"scheme:?query",
				"scheme:?query",
				"scheme", "", "", "query", ""},
			{
				"scheme:?query#",
				"scheme:?query",
				"scheme", "", "", "query", ""},
			{
				"scheme://?query",
				"scheme://?query",
				"scheme", "", "", "query", ""},
			{
				"scheme://?query#",
				"scheme://?query",
				"scheme", "", "", "query", ""},

			// Fragment.
			{
				"scheme:#fragment",
				"scheme:#fragment",
				"scheme", "", "", "", "fragment"},
			{
				"scheme:?#fragment",
				"scheme:#fragment",
				"scheme", "", "", "", "fragment"},
			{
				"scheme://#fragment",
				"scheme://#fragment",
				"scheme", "", "", "", "fragment"},
			{
				"scheme://?#fragment#",
				"scheme://#fragment",
				"scheme", "", "", "", "fragment"},

			// Complex.
			// - opaque: authority and followings
			{
				"scheme:host:80/",
				"scheme:host:80/",
				"scheme", "host:80", "/", "", ""},
			{
				"scheme:host:80/path/foo",
				"scheme:host:80/path/foo",
				"scheme", "host:80", "/path/foo", "", ""},
			{
				"scheme:host:80?query",
				"scheme:host:80?query",
				"scheme", "host:80", "", "query", ""},
			{
				"scheme:host:80#fragment",
				"scheme:host:80#fragment",
				"scheme", "host:80", "", "", "fragment"},
			{
				"scheme:host:80/?query",
				"scheme:host:80/?query",
				"scheme", "host:80", "/", "query", ""},
			{
				"scheme:host:80/#fragment",
				"scheme:host:80/#fragment",
				"scheme", "host:80", "/", "", "fragment"},
			{
				"scheme:host:80/?query#fragment",
				"scheme:host:80/?query#fragment",
				"scheme", "host:80", "/", "query", "fragment"},
			{
				"scheme:host:80/path/foo?query",
				"scheme:host:80/path/foo?query",
				"scheme", "host:80", "/path/foo", "query", ""},
			{
				"scheme:host:80/path/foo#fragment",
				"scheme:host:80/path/foo#fragment",
				"scheme", "host:80", "/path/foo", "", "fragment"},
			{
				"scheme:host:80/path/foo?query#fragment",
				"scheme:host:80/path/foo?query#fragment",
				"scheme", "host:80", "/path/foo", "query", "fragment"},

			{
				"scheme:host:80/?query#fragment",
				"scheme:host:80/?query#fragment",
				"scheme", "host:80", "/", "query", "fragment"},
			{
				"scheme:host:80/path/foo?query#fragment",
				"scheme:host:80/path/foo?query#fragment",
				"scheme", "host:80", "/path/foo", "query", "fragment"},

			// - opaque: path and followings
			{
				"scheme:/path/foo?query",
				"scheme:/path/foo?query",
				"scheme", "", "/path/foo", "query", ""},
			{
				"scheme:/path/foo#fragment",
				"scheme:/path/foo#fragment",
				"scheme", "", "/path/foo", "", "fragment"},
			{
				"scheme:/path/foo?query",
				"scheme:/path/foo?query",
				"scheme", "", "/path/foo", "query", ""},
			{
				"scheme:/path/foo#fragment",
				"scheme:/path/foo#fragment",
				"scheme", "", "/path/foo", "", "fragment"},
			{
				"scheme:/path/foo?query#fragment",
				"scheme:/path/foo?query#fragment",
				"scheme", "", "/path/foo", "query", "fragment"},

			// - opaque: query and fragment
			{
				"scheme:?query#fragment",
				"scheme:?query#fragment",
				"scheme", "", "", "query", "fragment"},

			// - hierarchical: authority and followings
			{
				"scheme://host:80/",
				"scheme://host:80/",
				"scheme", "host:80", "/", "", ""},
			{
				"scheme://host:80/path/foo",
				"scheme://host:80/path/foo",
				"scheme", "host:80", "/path/foo", "", ""},
			{
				"scheme://host:80?query",
				"scheme://host:80?query",
				"scheme", "host:80", "", "query", ""},
			{
				"scheme://host:80#fragment",
				"scheme://host:80#fragment",
				"scheme", "host:80", "", "", "fragment"},
			{
				"scheme://host:80/?query",
				"scheme://host:80/?query",
				"scheme", "host:80", "/", "query", ""},
			{
				"scheme://host:80/#fragment",
				"scheme://host:80/#fragment",
				"scheme", "host:80", "/", "", "fragment"},
			{
				"scheme://host:80/?query#fragment",
				"scheme://host:80/?query#fragment",
				"scheme", "host:80", "/", "query", "fragment"},
			{
				"scheme://host:80/path/foo?query",
				"scheme://host:80/path/foo?query",
				"scheme", "host:80", "/path/foo", "query", ""},
			{
				"scheme://host:80/path/foo#fragment",
				"scheme://host:80/path/foo#fragment",
				"scheme", "host:80", "/path/foo", "", "fragment"},
			{
				"scheme://host:80/path/foo?query#fragment",
				"scheme://host:80/path/foo?query#fragment",
				"scheme", "host:80", "/path/foo", "query", "fragment"},

			{
				"scheme://host:80/?query#fragment",
				"scheme://host:80/?query#fragment",
				"scheme", "host:80", "/", "query", "fragment"},
			{
				"scheme://host:80/path/foo?query#fragment",
				"scheme://host:80/path/foo?query#fragment",
				"scheme", "host:80", "/path/foo", "query", "fragment"},

			// - hierarchical: path and followings
			{
				"scheme:///path/foo?query",
				"scheme:///path/foo?query",
				"scheme", "", "/path/foo", "query", ""},
			{
				"scheme:///path/foo#fragment",
				"scheme:///path/foo#fragment",
				"scheme", "", "/path/foo", "", "fragment"},
			{
				"scheme:///path/foo?query",
				"scheme:///path/foo?query",
				"scheme", "", "/path/foo", "query", ""},
			{
				"scheme:///path/foo#fragment",
				"scheme:///path/foo#fragment",
				"scheme", "", "/path/foo", "", "fragment"},
			{
				"scheme:///path/foo?query#fragment",
				"scheme:///path/foo?query#fragment",
				"scheme", "", "/path/foo", "query", "fragment"},

			// - hierarchical: query and fragment
			{
				"scheme://?query#fragment",
				"scheme://?query#fragment",
				"scheme", "", "", "query", "fragment"},

			// Percent encoded.
			{
				"scheme:///%41%42%43/%44%45%46",
				"scheme:///ABC/DEF",
				"scheme", "", "/ABC/DEF", "", "",
			},
			{ // Reserved characters are not decoded.
				"scheme:///%41%42%43%2F%44%45%46",
				"scheme:///ABC%2FDEF",
				"scheme", "", "/ABC%2FDEF", "", "",
			},
			{ // Normalize lowercase hex digits into uppercase.
				"scheme:///%41%42%43%2f%44%45%46",
				"scheme:///ABC%2FDEF",
				"scheme", "", "/ABC%2FDEF", "", "",
			},
			{ // Encoded sub-delims are not decoded since it changes the structure.
				"scheme:///%21?a%3Db%26c=d",
				"scheme:///%21?a%3Db%26c=d",
				"scheme", "", "/%21", "a%3Db%26c=d", "",
			},

			// IP
			{
				"scheme://127.0.0.1",
				"scheme://127.0.0.1",
				"scheme", "127.0.0.1", "", "", ""},
			{
				"scheme://127.0.0.1/?#",
				"scheme://127.0.0.1/",
				"scheme", "127.0.0.1", "/", "", ""},
			{
				"scheme://127.0.0.1:80/?#",
				"scheme://127.0.0.1:80/",
				"scheme", "127.0.0.1:80", "/", "", ""},
			{
				"scheme://[::1]",
				"scheme://[::1]",
				"scheme", "[::1]", "", "", ""},
			{
				"scheme://[::1]/?#",
				"scheme://[::1]/",
				"scheme", "[::1]", "/", "", ""},
			{
				"scheme://[::1]:80/?#",
				"scheme://[::1]:80/",
				"scheme", "[::1]:80", "/", "", ""},

			// Filepath-like.
			// Use [Filepath] to parse filepath to get convenient results.
			// This test is just to show how [URL] handles such inputs.
			{
				"file:./relative/path",
				"file:./relative/path",
				"file", ".", "/relative/path", "", ""},
			{
				"file:./../relative/path",
				"file:./../relative/path",
				"file", ".", "/../relative/path", "", ""},
			{
				"file:/absolute/path",
				"file:/absolute/path",
				"file", "", "/absolute/path", "", ""},
			{
				"file://./relative/path",
				"file://./relative/path",
				"file", ".", "/relative/path", "", ""},
			{
				"file://./../relative/path",
				"file://./../relative/path",
				"file", ".", "/../relative/path", "", ""},
			{
				"file:///./absolute/path",
				"file:///./absolute/path",
				"file", "", "/./absolute/path", "", ""},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
				AssertEq(t, v.Scheme(), tc.scheme)
				AssertEq(t, v.Authority(), tc.authority)
				AssertEq(t, v.Path(), tc.path)
				AssertEq(t, v.Query(), tc.query)
				AssertEq(t, v.Fragment(), tc.fragment)
			})
		}

		for _, tc := range [][]string{
			{"missing scheme",
				"http",
				"example.com",
				"http//example.com",
				"answer42",
				":",
				"://example.com",
			},
			{"invalid character", // in scheme
				"ht^tp:",
				"42:",
			},
			{"missing host",
				"http://@",
				"http://@",
			},
			{"missing port number",
				"http://example.com:",
			},
			{"invalid character", // in port
				"http://example.com:80a",
				"http://example.com:0x42",
			},
			{"invalid character", // in path
				"http://example.com/foo/ bar",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("URL(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.URL(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("QueryParams", func(t *testing.T) {
		type kv struct {
			key, value string
		}

		for _, tc := range []struct {
			given  xddr.URL
			params []kv
		}{
			{
				"scheme:?",
				[]kv{},
			},
			{
				"scheme:?&",
				[]kv{},
			},
			{
				"scheme:?&&",
				[]kv{},
			},
			{
				"scheme:?=",
				[]kv{
					{"", ""},
				},
			},
			{
				"scheme:?k",
				[]kv{
					{"k", ""},
				},
			},
			{
				"scheme:?=v",
				[]kv{
					{"", "v"},
				},
			},
			{
				"scheme:?k=v",
				[]kv{
					{"k", "v"},
				},
			},
			{
				"scheme:?&&&k=v",
				[]kv{
					{"k", "v"},
				},
			},
			{
				"scheme:?foo=bar&baz=qux",
				[]kv{
					{"foo", "bar"},
					{"baz", "qux"},
				},
			},
			{
				"scheme:?&&&foo=bar&&&baz=qux&",
				[]kv{
					{"foo", "bar"},
					{"baz", "qux"},
				},
			},
			{
				"scheme:?&&&foo=bar&&&baz=qux&&&",
				[]kv{
					{"foo", "bar"},
					{"baz", "qux"},
				},
			},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				expected := tc.params
				params := []kv{}
				for k, v := range tc.given.QueryParams() {
					params = append(params, kv{k, v})
				}

				if len(params) != len(expected) {
					t.Fatalf("expected %d params, got %d", len(expected), len(params))
				}
				for i, p := range params {
					if p.key != expected[i].key || p.value != expected[i].value {
						t.Errorf("expected (%q, %q), got (%q, %q) at %d",
							expected[i].key, expected[i].value,
							p.key, p.value, i,
						)
					}
				}
			})
		}
	})
	t.Run("WithScheme", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.URL
			value string
			want  xddr.URL
		}{
			{"http:", "https", "https:"},
			{"http://", "https", "https://"},
			{"http:host/path?query#fragment", "https", "https:host/path?query#fragment"},
			{"http://host/path?query#fragment", "https", "https://host/path?query#fragment"},

			// Scheme is normalized to lowercase.
			{"http://host", "HTTPS", "https://host"},

			// Value without a scheme.
			{"", "http", "http:"},
			{"example.com", "http", "http:example.com"},
		} {
			t.Run(fmt.Sprintf("URL(%q).WithScheme(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithScheme(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}

		_, err := xddr.URL("http://host").WithScheme("42")
		AssertErrorContains(t, err, "invalid character")

		_, err = xddr.URL("http://host").WithScheme("")
		AssertErrorContains(t, err, "missing scheme")
	})
	t.Run("WithAuthority", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.URL
			value string
			want  xddr.URL
		}{
			{"scheme:", "host:80", "scheme:host:80"},
			{"scheme://", "host:80", "scheme://host:80"},
			{"scheme:foo", "host:80", "scheme:host:80"},
			{"scheme://foo", "host:80", "scheme://host:80"},
			{"scheme:user:pass@foo", "host:80", "scheme:host:80"},
			{"scheme://user:pass@foo", "host:80", "scheme://host:80"},
			{"scheme:/path", "host:80", "scheme:host:80/path"},
			{"scheme:///path", "host:80", "scheme://host:80/path"},
		} {
			t.Run(fmt.Sprintf("URL(%q).WithAuthority(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithAuthority(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.URL
			value string
			want  xddr.URL
		}{
			{"scheme:user:pass@foo:80", "host", "scheme:user:pass@host:80"},
		} {
			t.Run(fmt.Sprintf("URL(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
	t.Run("WithPort", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.URL
			value int
			want  xddr.URL
		}{
			{"scheme:user:pass@foo:80", 443, "scheme:user:pass@foo:443"},
		} {
			t.Run(fmt.Sprintf("URL(%q).WithPort(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithPort(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
}

func TestURLLike(t *testing.T) {
	t.Run("SchemeOf", func(t *testing.T) {
		AssertEq(t, xddr.SchemeOf(xddr.URL("scheme://example.com")), "scheme")
		AssertEq(t, xddr.SchemeOf(xddr.HTTP("https://example.com")), "https")
		AssertEq(t, xddr.SchemeOf(xddr.GRPC("dns:///grpc.io:50051")), "dns")
		AssertEq(t, xddr.SchemeOf(xddr.ICE("stun:example.com")), "stun")
	})
	t.Run("HostOf", func(t *testing.T) {
		AssertEq(t, xddr.HostOf(xddr.URL("scheme://a.b:8080/p")), xddr.Host("a.b"))
		AssertEq(t, xddr.HostOf(xddr.HTTP("http://a.b:8080/p")), xddr.Host("a.b"))
		AssertEq(t, xddr.HostOf(xddr.ICE("stun:example.com")), xddr.Host("example.com"))

		// Note that generic helpers interpret the value using the plain URL
		// grammar: a GRPC target like "dns:///host:port" keeps its endpoint
		// in the path, so its URL authority (thus its host) is empty.
		// Use [xddr.GRPC.Host] instead.
		AssertEq(t, xddr.HostOf(xddr.GRPC("dns:///grpc.io:50051")), xddr.Host(""))
	})
	t.Run("AuthorityOf", func(t *testing.T) {
		AssertEq(t, xddr.AuthorityOf(xddr.HTTP("http://u:p@h:1/x")), xddr.Authority("u:p@h:1"))
	})
	t.Run("PortOf", func(t *testing.T) {
		AssertEq(t, xddr.PortOf(xddr.HTTP("http://h:8080")), 8080)

		// PortOf returns the port as written; it does not resolve
		// scheme default ports like [xddr.HTTP.Port] does.
		AssertEq(t, xddr.PortOf(xddr.HTTP("http://h")), -1)
	})
	t.Run("WithHost", func(t *testing.T) {
		v := xddr.HTTP("http://example.com/path")
		w, err := xddr.WithHost(v, "example.org")
		if err != nil {
			t.Fatalf("WithHost failed: %v", err)
		}
		expected := xddr.HTTP("http://example.org/path")
		if w != expected {
			t.Fatalf("WithHost = %v, want %v", w, expected)
		}

		u, err := xddr.WithHost(xddr.URL("scheme://a/p"), "b")
		AssertNoError(t, err)
		AssertEq(t, u, xddr.URL("scheme://b/p"))

		AssertEq(t, xddr.WithHostX(xddr.ICE("stun:example.com"), "example.org"), xddr.ICE("stun:example.org"))
	})
}
