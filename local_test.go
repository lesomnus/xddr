package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{"tcp::80", "tcp::80"},
			{"tcp4:0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"udp::53", "udp::53"},
			{"unix:/x.sock", "unix:/x.sock"},
		} {
			t.Run(fmt.Sprintf("Local(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.Local(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.Local(tc[1]))
			})
		}

		// Unlike more specific types, the network must be explicit.
		_, err := xddr.Local(":80").Sanitize()
		AssertErrorContains(t, err, "unknown network")

		_, err = xddr.Local("foo:bar").Sanitize()
		AssertErrorContains(t, err, "unknown network")
	})
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
			{"localhost:80", "tcp:localhost:80"},
			{"tcp:localhost:80", "tcp:localhost:80"},

			// Port 0 is valid and the result is idempotent.
			{":0", "tcp::0"},
			{"tcp::0", "tcp::0"},
			{"127.0.0.1:0", "tcp4:127.0.0.1:0"},
			{"tcp4:127.0.0.1:0", "tcp4:127.0.0.1:0"},
		} {
			t.Run(fmt.Sprintf("Local(%q).Sanitize()=%q", given[0], given[1]), func(t *testing.T) {
				v, err := xddr.TCPLocal(given[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.TCPLocal(given[1]))
			})
		}
		for _, tc := range [][]string{
			{"empty local address",
				"",
			},
			{"IPv4 address with IPv6 network",
				"tcp6:0.0.0.0:80",
			},
			{"IPv6 address with IPv4 network",
				"tcp4:[::]:80",
			},
			{"missing port",
				"tcp:0.0.0.0",
			},
			{"userinfo not allowed",
				"tcp:user@0.0.0.0:80",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("TCPLocal(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.TCPLocal(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		v, err := xddr.TCPLocal("tcp::80").WithHost("192.0.2.1")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.TCPLocal("tcp4:192.0.2.1:80"))
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.TCPLocal("tcp4:192.0.2.1:80").WithPort(443)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.TCPLocal("tcp4:192.0.2.1:443"))
	})
}

func TestUnixLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{"/var/run/x.sock", "unix:/var/run/x.sock"},
			{"./rel.sock", "unix:./rel.sock"},
			{"rel.sock", "unix:rel.sock"},
			{"unix:/var/run/x.sock", "unix:/var/run/x.sock"},
			{"unixgram:/var/run/x.sock", "unixgram:/var/run/x.sock"},
			{"unixpacket:/var/run/x.sock", "unixpacket:/var/run/x.sock"},
			{"/tmp/a:b.sock", "unix:/tmp/a:b.sock"},
		} {
			t.Run(fmt.Sprintf("UnixLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.UnixLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.UnixLocal(tc[1]))
			})
		}

		_, err := xddr.UnixLocal("").Sanitize()
		AssertErrorContains(t, err, "empty local address")

		_, err = xddr.UnixLocal("unix:").Sanitize()
		AssertErrorContains(t, err, "empty socket path")
	})
}

func TestLocalLike(t *testing.T) {
	t.Run("NetworkOf AddressOf", func(t *testing.T) {
		AssertEq(t, xddr.NetworkOf(xddr.Local("tcp4:0.0.0.0:80")), "tcp4")
		AssertEq(t, xddr.AddressOf(xddr.Local("tcp4:0.0.0.0:80")), "0.0.0.0:80")
		AssertEq(t, xddr.NetworkOf(xddr.TCPLocal("tcp::80")), "tcp")
		AssertEq(t, xddr.NetworkOf(xddr.UDPLocal("udp6:[::]:53")), "udp6")
		AssertEq(t, xddr.NetworkOf(xddr.UnixLocal("unix:/x.sock")), "unix")
		AssertEq(t, xddr.AddressOf(xddr.UnixLocal("unix:/x.sock")), "/x.sock")
		AssertEq(t, xddr.NetworkOf(xddr.HTTPLocal("tcp4:0.0.0.0:80")), "tcp4")
		AssertEq(t, xddr.NetworkOf(xddr.GRPCLocal("tcp4:0.0.0.0:80")), "tcp4")
		AssertEq(t, xddr.NetworkOf(xddr.ICELocal("udp4:0.0.0.0:3478")), "udp4")
		AssertEq(t, xddr.NetworkOf(xddr.TCPUDPLocal("udp::53")), "udp")
		AssertEq(t, xddr.NetworkOf(xddr.TCPUnixLocal("unix:/x.sock")), "unix")
	})
	t.Run("Listen", func(t *testing.T) {
		l, err := xddr.Listen(xddr.TCPLocal("tcp4:127.0.0.1:0"))
		if err != nil {
			t.Skipf("cannot listen: %v", err)
		}
		defer l.Close()
		AssertEq(t, l.Addr().Network(), "tcp")
	})
	t.Run("ListenPacket", func(t *testing.T) {
		c, err := xddr.ListenPacket(xddr.UDPLocal("udp4:127.0.0.1:0"))
		if err != nil {
			t.Skipf("cannot listen: %v", err)
		}
		defer c.Close()
		AssertEq(t, c.LocalAddr().Network(), "udp")
	})
}
