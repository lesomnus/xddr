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
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				value, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, value, tc.normalized)
			})
		}
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
			{"tcp6:[::]:80", "http://[::1]:80"},
			{"unix:/var/run/.sock", "unix:///var/run/.sock"},
		} {
			t.Run(fmt.Sprintf("HTTPLocal(%q).AsURL()=%q", tc[0], tc[1]), func(t *testing.T) {
				v := xddr.HTTPLocal(tc[0]).AsURL()
				AssertEq(t, v, xddr.HTTP(tc[1]))
			})
		}
	})
}
