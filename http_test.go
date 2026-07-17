package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestHTTP(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.HTTP
			normalized xddr.HTTP
		}{
			{"http:foo", "http://foo"},
			{"http://foo", "http://foo"},
			{"http://foo:80", "http://foo"},
			{"http://foo:443", "http://foo:443"},
			{"https:foo", "https://foo"},
			{"https://foo", "https://foo"},
			{"https://foo:80", "https://foo:80"},
			{"https://foo:443", "https://foo"},

			// Path, query, and fragment are preserved.
			{"https://foo/p?a=1#frag", "https://foo/p?a=1#frag"},
			{"http://foo:80/x?q=1#f", "http://foo/x?q=1#f"},
			{"HTTP://Foo.COM/x", "http://foo.com/x"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				value, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, value, tc.normalized)
			})
		}

		_, err := xddr.HTTP("ftp://foo").Sanitize()
		AssertErrorContains(t, err, "scheme is not http or https")
	})
	t.Run("Getters", func(t *testing.T) {
		v := xddr.HTTP("https://user:pass@foo:8443/p?q=1#f")
		AssertEq(t, v.Scheme(), "https")
		AssertEq(t, v.Authority(), xddr.Authority("user:pass@foo:8443"))
		AssertEq(t, v.Host(), xddr.Host("foo"))
		AssertEq(t, v.Port(), 8443)
	})
	t.Run("Port", func(t *testing.T) {
		AssertEq(t, xddr.HTTP("http://foo").Port(), 80)
		AssertEq(t, xddr.HTTP("https://foo").Port(), 443)
		AssertEq(t, xddr.HTTP("https://foo:8443").Port(), 8443)
	})
	t.Run("WithHost", func(t *testing.T) {
		v, err := xddr.HTTP("http://foo:8080/p").WithHost("bar")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTP("http://bar:8080/p"))
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.HTTP("http://foo:8080/p").WithPort(80)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTP("http://foo/p"))

		v, err = xddr.HTTP("https://foo/p").WithPort(8443)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTP("https://foo:8443/p"))
	})
}

func TestHTTPLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{":80", "tcp::80"},
			{"0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"[::]:80", "tcp6:[::]:80"},
			{"tcp::80", "tcp::80"},
			{"tcp4::80", "tcp4:0.0.0.0:80"},
			{"tcp4:0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"tcp6::80", "tcp6:[::]:80"},
			{"tcp6:[::]:80", "tcp6:[::]:80"},
		} {
			t.Run(fmt.Sprintf("HTTPLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.HTTPLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.HTTPLocal(tc[1]))
			})
		}
	})
	t.Run("AsURL", func(t *testing.T) {
		for _, tc := range [][]string{
			{"tcp::80", "http://127.0.0.1:80"},
			{"tcp4:0.0.0.0:80", "http://127.0.0.1:80"},
			{"tcp6::80", "http://[::1]:80"},
			{"tcp6:[::]:80", "http://[::1]:80"},
			{"unix:/var/run/.sock", "unix:///var/run/.sock"},
			{"unix:rel.sock", "unix:rel.sock"},
		} {
			t.Run(fmt.Sprintf("HTTPLocal(%q).AsURL()=%q", tc[0], tc[1]), func(t *testing.T) {
				v := xddr.HTTPLocal(tc[0]).AsURL()
				AssertEq(t, v, xddr.HTTP(tc[1]))
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		v, err := xddr.HTTPLocal("tcp::80").WithHost("192.0.2.1")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTPLocal("tcp4:192.0.2.1:80"))

		v, err = xddr.HTTPLocal("tcp::80").WithHost("/x.sock")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTPLocal("unix:/x.sock"))
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.HTTPLocal("tcp4:0.0.0.0:80").WithPort(8080)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HTTPLocal("tcp4:0.0.0.0:8080"))

		_, err = xddr.HTTPLocal("unix:/x.sock").WithPort(8080)
		AssertErrorContains(t, err, "not a TCP local address")
	})
}
