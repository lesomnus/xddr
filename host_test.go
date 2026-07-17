package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestHost(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.Host
			normalized xddr.Host
		}{
			{"127.0.0.1", "127.0.0.1"},
			{"::1", "[::1]"},
			{"[::1]", "[::1]"},
			{"[0:0::1]", "[::1]"},
			{"localhost", "localhost"},
			{"Example.COM", "example.com"},
		} {
			t.Run(fmt.Sprintf("Host(%q).Sanitize()=%q", tc.given, tc.normalized), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
		for _, tc := range [][]string{
			{"host is empty",
				"",
			},
			{"invalid character",
				"exa mple.com",
			},
			{"must have at least 2 colons",
				"[:]",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("Host(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.Host(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Union", func(t *testing.T) {
		Assert(t, xddr.Host("127.0.0.1").IsIPv4(), "127.0.0.1 is IPv4")
		Assert(t, xddr.Host("[::1]").IsIPv6(), "[::1] is IPv6")
		Assert(t, xddr.Host("example.com").IsDomain(), "example.com is domain")
		Assert(t, !xddr.Host("example.com").IsIPv4(), "example.com is not IPv4")
		Assert(t, !xddr.Host("127.0.0.1").IsDomain(), "127.0.0.1 is not domain")

		if v, ok := xddr.Host("127.0.0.1").IPv4(); !ok || v != "127.0.0.1" {
			t.Fatalf("want (127.0.0.1, true), but (%q, %v)", v, ok)
		}
		if v, ok := xddr.Host("[::1]").IPv6(); !ok || v != "[::1]" {
			t.Fatalf("want ([::1], true), but (%q, %v)", v, ok)
		}
		if v, ok := xddr.Host("example.com").Domain(); !ok || v != "example.com" {
			t.Fatalf("want (example.com, true), but (%q, %v)", v, ok)
		}
	})
}

func TestHostPort(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.HostPort
			normalized xddr.HostPort
		}{
			{"example.com:443", "example.com:443"},
			{"Example.COM:443", "example.com:443"},
			{"127.0.0.1:443", "127.0.0.1:443"},
			{"[::1]:443", "[::1]:443"},
			{"[0:0::1]:443", "[::1]:443"},
			{"example.com:0443", "example.com:443"},
			{"example.com:0", "example.com:0"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
		for _, tc := range [][]string{
			{"hostport is empty",
				"",
			},
			{"missing ':' separator for port",
				"example.com",
				"[::1]",
			},
			{"port is empty",
				"example.com:",
			},
			{"port is not a valid number",
				"example.com:x",
			},
			{"port number out of range",
				"example.com:70000",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("HostPort(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.HostPort(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Split", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.HostPort
			host  xddr.Host
			port  int
		}{
			{"example.com:443", "example.com", 443},
			{"127.0.0.1:443", "127.0.0.1", 443},
			{"[::1]:443", "[::1]", 443},

			// Port is -1 if absent.
			{"example.com", "example.com", -1},
			{"[::1]", "[::1]", -1},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				h, p := tc.given.Split()
				AssertEq(t, h, tc.host)
				AssertEq(t, p, tc.port)
				AssertEq(t, tc.given.Host(), tc.host)
				AssertEq(t, tc.given.Port(), tc.port)
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.HostPort
			value string
			want  xddr.HostPort
		}{
			{"example.com:443", "example.org", "example.org:443"},
			{"example.com:443", "::1", "[::1]:443"},
			{"[::1]:443", "127.0.0.1", "127.0.0.1:443"},
		} {
			t.Run(fmt.Sprintf("HostPort(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.HostPort("example.com:443").WithPort(8080)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.HostPort("example.com:8080"))

		_, err = xddr.HostPort("example.com:443").WithPort(-1)
		AssertErrorContains(t, err, "port number out of range")

		_, err = xddr.HostPort("example.com:443").WithPort(70000)
		AssertErrorContains(t, err, "port number out of range")
	})
}
