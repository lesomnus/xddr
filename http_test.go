package xddr_test

import (
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
