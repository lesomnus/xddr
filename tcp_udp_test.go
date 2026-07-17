package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestUDPLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{":53", "udp::53"},
			{"0.0.0.0:53", "udp4:0.0.0.0:53"},
			{"[::]:53", "udp6:[::]:53"},
			{"udp::53", "udp::53"},
			{"udp4::53", "udp4:0.0.0.0:53"},
			{"udp6::53", "udp6:[::]:53"},
		} {
			t.Run(fmt.Sprintf("UDPLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.UDPLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.UDPLocal(tc[1]))
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		v, err := xddr.UDPLocal("udp::53").WithHost("192.0.2.1")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.UDPLocal("udp4:192.0.2.1:53"))
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.UDPLocal("udp4:192.0.2.1:53").WithPort(5353)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.UDPLocal("udp4:192.0.2.1:5353"))
	})
}

func TestTCPUDPLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{"tcp::80", "tcp::80"},
			{"tcp4:0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"udp::53", "udp::53"},
			{"udp6:[::]:53", "udp6:[::]:53"},
		} {
			t.Run(fmt.Sprintf("TCPUDPLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.TCPUDPLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.TCPUDPLocal(tc[1]))
			})
		}
		for _, tc := range [][]string{
			{"empty local address",
				"",
			},
			{"not a TCP or UDP local address",
				"unix:/x.sock",
				":80",
				"0.0.0.0:80",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("TCPUDPLocal(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.TCPUDPLocal(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.TCPUDPLocal
			value string
			want  xddr.TCPUDPLocal
		}{
			{"tcp::80", "192.0.2.1", "tcp4:192.0.2.1:80"},
			{"udp::53", "[2001:db8::1]", "udp6:[2001:db8::1]:53"},
			{"udp4:0.0.0.0:53", "localhost", "udp:localhost:53"},
		} {
			t.Run(fmt.Sprintf("TCPUDPLocal(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}

		// Unlike [TCPUnixLocal], it does not accept a filesystem path.
		_, err := xddr.TCPUDPLocal("tcp::80").WithHost("/x.sock")
		Assert(t, err != nil, "want error, but nil")

		_, err = xddr.TCPUDPLocal("unix:/x.sock").WithHost("localhost")
		AssertErrorContains(t, err, "not a TCP or UDP local address")
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.TCPUDPLocal("udp4:0.0.0.0:53").WithPort(5353)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.TCPUDPLocal("udp4:0.0.0.0:5353"))

		_, err = xddr.TCPUDPLocal("unix:/x.sock").WithPort(80)
		AssertErrorContains(t, err, "not a TCP or UDP local address")
	})
}
