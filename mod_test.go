package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestReliable(t *testing.T) {
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range [][]string{
			{"tcp::80", "localhost", "tcp:localhost:80"},
			{"tcp::80", "192.0.2.1", "tcp4:192.0.2.1:80"},
			{"tcp::80", "[2001:db8::1]", "tcp6:[2001:db8::1]:80"},
		} {
			t.Run(fmt.Sprintf("reliableWithHost(%q, %q)=%q", tc[0], tc[1], tc[2]), func(t *testing.T) {
				v, err := xddr.GRPCLocal(tc[0]).WithHost(tc[1])
				AssertNoError(t, err)
				AssertEq(t, v, xddr.GRPCLocal(tc[2]))
			})
		}
	})
	t.Run("WithPort", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.GRPCLocal
			port  int
			want  xddr.GRPCLocal
		}{
			{"tcp::80", 443, "tcp::443"},
			{"tcp4:192.0.2.1:80", 443, "tcp4:192.0.2.1:443"},
			{"tcp6:[2001:db8::1]:80", 443, "tcp6:[2001:db8::1]:443"},
		} {
			t.Run(fmt.Sprintf("reliableWithPort(%q, %d)=%q", tc.given, tc.port, tc.want), func(t *testing.T) {
				v, err := xddr.GRPCLocal(tc.given).WithPort(tc.port)
				AssertNoError(t, err)
				AssertEq(t, v, xddr.GRPCLocal(tc.want))
			})
		}
	})
}
