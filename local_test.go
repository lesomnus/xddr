package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestLocal(t *testing.T) {
	t.Run("Split", func(t *testing.T) {
		for _, given := range [][]string{
			{":80", "", "80"},
			{"tcp:80", "tcp", "80"},
			{"tcp4::80", "tcp4", ":80"},
		} {
			t.Run(fmt.Sprintf("Local(%q).Split()=(%q, %q)", given[0], given[1], given[2]), func(t *testing.T) {
				network, address := xddr.Local(given[0]).Split()
				AssertEq(t, network, given[1])
				AssertEq(t, address, given[2])
			})
		}
	})
}

func TestTCPLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, given := range [][]string{
			{":80", "tcp::80"},
			{"0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"[::]:80", "tcp6:[::]:80"},
			{"tcp::80", "tcp::80"},
			{"tcp4::80", "tcp4:0.0.0.0:80"},
			{"tcp6::80", "tcp6:[::]:80"},
		} {
			t.Run(fmt.Sprintf("Local(%q).Sanitize()=%q", given[0], given[1]), func(t *testing.T) {
				v, err := xddr.TCPLocal(given[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.TCPLocal(given[1]))
			})
		}
	})
}
