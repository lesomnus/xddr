package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestICE(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.ICE
			normalized xddr.ICE
		}{
			{"stun:example.com", "stun:example.com"},
			{"STUN:example.com", "stun:example.com"},
			{"stun://example.com", "stun:example.com"},
			{"stun:example.com:3478", "stun:example.com"},
			{"stun:example.com:1234", "stun:example.com:1234"},
			{"stuns:example.com:5349", "stuns:example.com"},
			{"stuns:example.com:443", "stuns:example.com:443"},
			{"turn:example.com", "turn:example.com"},
			{"turn:example.com:3478?transport=udp", "turn:example.com?transport=udp"},
			{"turn:example.com?transport=tcp", "turn:example.com?transport=tcp"},
			{"turns:example.com:5349?transport=tcp", "turns:example.com?transport=tcp"},
			{"turns:example.com:443?transport=tcp", "turns:example.com:443?transport=tcp"},
			{"turn:192.0.2.1:1234", "turn:192.0.2.1:1234"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
		for _, tc := range [][]string{
			{"unexpected scheme",
				"http://example.com",
				"stunx:example.com",
			},
			{"must not have userinfo, path, or fragment",
				"stun:user@example.com",
				"stun:example.com/path",
				"stun:example.com#frag",
			},
			{"STUN URI must not have query",
				"stun:example.com?transport=udp",
				"stuns:example.com?transport=udp",
			},
			{"can only have 'transport' parameter",
				"turn:example.com?foo=bar",
			},
			{"'transport' parameter must be 'udp' or 'tcp'",
				"turn:example.com?transport=sctp",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("ICE(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.ICE(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Host", func(t *testing.T) {
		AssertEq(t, xddr.ICE("stun:example.com").Host(), xddr.Host("example.com"))
		AssertEq(t, xddr.ICE("turns:example.com:443?transport=tcp").Host(), xddr.Host("example.com"))
	})
	t.Run("Port", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.ICE
			want  int
		}{
			{"stun:example.com", 3478},
			{"turn:example.com", 3478},
			{"stuns:example.com", 5349},
			{"turns:example.com", 5349},
			{"stun:example.com:1234", 1234},
			{"turns:example.com:443?transport=tcp", 443},
		} {
			t.Run(fmt.Sprintf("ICE(%q).Port()=%d", tc.given, tc.want), func(t *testing.T) {
				AssertEq(t, tc.given.Port(), tc.want)
			})
		}
	})
	t.Run("Transport", func(t *testing.T) {
		AssertEq(t, xddr.ICE("turn:example.com?transport=udp").Transport(), "udp")
		AssertEq(t, xddr.ICE("turns:example.com:443?transport=tcp").Transport(), "tcp")
		AssertEq(t, xddr.ICE("stun:example.com").Transport(), "")
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.ICE
			value string
			want  xddr.ICE
		}{
			{"stun:example.com", "stun.example.org", "stun:stun.example.org"},
			{"turn:example.com:1234?transport=udp", "192.0.2.1", "turn:192.0.2.1:1234?transport=udp"},
		} {
			t.Run(fmt.Sprintf("ICE(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}
	})
	t.Run("WithPort", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.ICE
			port  int
			want  xddr.ICE
		}{
			{"stun:example.com", 1234, "stun:example.com:1234"},
			{"stun:example.com:1234", 3478, "stun:example.com"},
			{"turns:example.com:443?transport=tcp", 5349, "turns:example.com?transport=tcp"},
		} {
			t.Run(fmt.Sprintf("ICE(%q).WithPort(%d)=%q", tc.given, tc.port, tc.want), func(t *testing.T) {
				v, err := tc.given.WithPort(tc.port)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}
	})
}

func TestICELocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{"udp::3478", "udp::3478"},
			{"udp4::3478", "udp4:0.0.0.0:3478"},
			{"udp6::3478", "udp6:[::]:3478"},
			{"udp:0.0.0.0:3478", "udp4:0.0.0.0:3478"},
			{"tcp::3478", "tcp::3478"},
			{"tcp4:0.0.0.0:3478", "tcp4:0.0.0.0:3478"},
		} {
			t.Run(fmt.Sprintf("ICELocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.ICELocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.ICELocal(tc[1]))
			})
		}

		_, err := xddr.ICELocal("unix:/x.sock").Sanitize()
		AssertErrorContains(t, err, "not a TCP or UDP local address")
	})
	t.Run("WithHost", func(t *testing.T) {
		v, err := xddr.ICELocal("udp::3478").WithHost("192.0.2.1")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.ICELocal("udp4:192.0.2.1:3478"))

		_, err = xddr.ICELocal("udp::3478").WithHost("/x.sock")
		Assert(t, err != nil, "want error, but nil")
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.ICELocal("udp4:0.0.0.0:3478").WithPort(1234)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.ICELocal("udp4:0.0.0.0:1234"))
	})
	t.Run("Address", func(t *testing.T) {
		a := xddr.ICELocal("udp6:[::]:53").Address()
		AssertEq(t, a, xddr.Authority("[::]:53"))
		AssertEq(t, a.Host(), xddr.Host("[::]"))
		AssertEq(t, a.Port(), 53)
	})
	t.Run("IsStreamDgram", func(t *testing.T) {
		Assert(t, xddr.ICELocal("udp4:0.0.0.0:3478").IsDgram(), "udp4 is dgram")
		Assert(t, !xddr.ICELocal("udp4:0.0.0.0:3478").IsStream(), "udp4 is not stream")
		Assert(t, xddr.ICELocal("tcp4:0.0.0.0:3478").IsStream(), "tcp4 is stream")
		Assert(t, !xddr.ICELocal("tcp4:0.0.0.0:3478").IsDgram(), "tcp4 is not dgram")
	})
}
