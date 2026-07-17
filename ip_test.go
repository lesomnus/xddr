package xddr_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestIPv4(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, given := range []xddr.IPv4{
			"0.0.0.0",
			"0.0.0.1",
			"10.0.0.1",
			"127.0.0.1",
			"192.168.0.1",
			"255.255.255.255",
		} {
			t.Run(fmt.Sprintf("IPv4(%q).Sanitize()=%q", given, given), func(t *testing.T) {
				_, err := given.Sanitize()
				AssertNoError(t, err)
			})
		}
		for _, tc := range []struct {
			given xddr.IPv4
			err   string
		}{
			{"", "must have 4 fields"},
			{"1.2.3", "must have 4 fields"},
			{"1.2..3", "[2]: empty"},
			{"1.01.0.1", "[1]: leading zeros not allowed"},
			{"255.1.2.X", "[3]: not a valid number"},
			{"256.0.0.1", "[0]: must be between 0 and 255"},
		} {
			t.Run(fmt.Sprintf("IPv4(%q).Sanitize() -> %q", tc.given, tc.err), func(t *testing.T) {
				_, err := tc.given.Sanitize()
				Assert(t, err != nil, "want error, but nil")
				Assert(t, strings.Contains(err.Error(), tc.err), "want error like %q, but %q", tc.err, err)
			})
		}
	})
	t.Run("Bytes", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.IPv4
			want  [4]byte
		}{
			{"0.0.0.0", [4]byte{0, 0, 0, 0}},
			{"0.0.0.1", [4]byte{0, 0, 0, 1}},
			{"10.0.0.1", [4]byte{10, 0, 0, 1}},
			{"127.0.0.1", [4]byte{127, 0, 0, 1}},
			{"192.168.0.1", [4]byte{192, 168, 0, 1}},
			{"255.255.255.255", [4]byte{255, 255, 255, 255}},

			// Does not panic on un-sanitized values.
			{"1.2.3", [4]byte{1, 2, 3, 0}},
			{"1.2.3.4.5", [4]byte{1, 2, 3, 4}},
		} {
			t.Run(fmt.Sprintf("IPv4(%q).Bytes()=%v", tc.given, tc.want), func(t *testing.T) {
				got := tc.given.Bytes()
				AssertEq(t, got, tc.want)
			})
		}
	})
	t.Run("Is", func(t *testing.T) {
		Assert(t, xddr.IPv4("0.0.0.0").IsUnspecified(), "0.0.0.0 is unspecified")
		Assert(t, xddr.IPv4("127.0.0.1").IsLoopback(), "127.0.0.1 is loopback")
		Assert(t, xddr.IPv4("10.0.0.1").IsPrivate(), "10.0.0.1 is private")
		Assert(t, xddr.IPv4("172.16.0.1").IsPrivate(), "172.16.0.1 is private")
		Assert(t, !xddr.IPv4("172.32.0.1").IsPrivate(), "172.32.0.1 is not private")
		Assert(t, xddr.IPv4("192.168.0.1").IsPrivate(), "192.168.0.1 is private")
		Assert(t, !xddr.IPv4("8.8.8.8").IsPrivate(), "8.8.8.8 is not private")
	})
}

func TestIP(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.IP
			normalized xddr.IP
		}{
			{"", ""},
			{"127.0.0.1", "127.0.0.1"},
			{"::1", "::1"},
			{"[::1]", "::1"},
			{"0:0::1", "::1"},
			{"::ffff:192.0.2.128", "::ffff:192.0.2.128"},
		} {
			t.Run(fmt.Sprintf("IP(%q).Sanitize()=%q", tc.given, tc.normalized), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}

		_, err := xddr.IP("abc").Sanitize()
		AssertErrorContains(t, err, "invalid IP address")
	})
	t.Run("V4V6", func(t *testing.T) {
		if v, ok := xddr.IP("").V4(); !ok || v != "0.0.0.0" {
			t.Fatalf("want (0.0.0.0, true), but (%q, %v)", v, ok)
		}
		if v, ok := xddr.IP("").V6(); !ok || v != "::" {
			t.Fatalf("want (::, true), but (%q, %v)", v, ok)
		}
		if v, ok := xddr.IP("1.2.3.4").V4(); !ok || v != "1.2.3.4" {
			t.Fatalf("want (1.2.3.4, true), but (%q, %v)", v, ok)
		}
		if _, ok := xddr.IP("1.2.3.4").V6(); ok {
			t.Fatal("1.2.3.4 is not IPv6")
		}
		if _, ok := xddr.IP("::1").V4(); ok {
			t.Fatal("::1 is not IPv4")
		}
		if _, ok := xddr.IP("::ffff:1.2.3.4").V4(); ok {
			t.Fatal("::ffff:1.2.3.4 is IPv6, not IPv4")
		}
		if _, ok := xddr.IP("::ffff:1.2.3.4").V6(); !ok {
			t.Fatal("::ffff:1.2.3.4 is IPv6")
		}
	})
	t.Run("Is", func(t *testing.T) {
		Assert(t, xddr.IP("").IsUnspecified(), "empty IP is unspecified")
		Assert(t, xddr.IP("0.0.0.0").IsUnspecified(), "0.0.0.0 is unspecified")
		Assert(t, xddr.IP("::").IsUnspecified(), ":: is unspecified")
		Assert(t, xddr.IP("127.0.0.1").IsLoopback(), "127.0.0.1 is loopback")
		Assert(t, xddr.IP("::1").IsLoopback(), "::1 is loopback")
		Assert(t, !xddr.IP("192.0.2.1").IsLoopback(), "192.0.2.1 is not loopback")
		Assert(t, xddr.IP("10.0.0.1").IsPrivate(), "10.0.0.1 is private")
		Assert(t, xddr.IP("fc00::1").IsPrivate(), "fc00::1 is private")
		Assert(t, xddr.IP("fd12::1").IsPrivate(), "fd12::1 is private")
		Assert(t, !xddr.IP("2001:db8::1").IsPrivate(), "2001:db8::1 is not private")
	})
}

func TestIPPort(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.IPPort
			normalized xddr.IPPort
		}{
			{":80", ":80"},
			{"127.0.0.1:80", "127.0.0.1:80"},
			{"[::1]:80", "[::1]:80"},
			{"[0:0::1]:80", "[::1]:80"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
		for _, tc := range [][]string{
			{"missing ':' separator for port",
				"1.2.3.4",
				"[::1]",
			},
			{"invalid port number",
				"1.2.3.4:x",
			},
			{"port number must be between 0 and 65535",
				"1.2.3.4:70000",
			},
			{"invalid IP address",
				"abc:80",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("IPPort(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.IPPort(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Split", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.IPPort
			ip    xddr.IP
			port  int
		}{
			{":80", "", 80},
			{"127.0.0.1:80", "127.0.0.1", 80},
			{"[::1]:80", "::1", 80},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				ip, port := tc.given.Split()
				AssertEq(t, ip, tc.ip)
				AssertEq(t, port, tc.port)
				AssertEq(t, tc.given.IP(), tc.ip)
				AssertEq(t, tc.given.Port(), tc.port)
			})
		}
	})
	t.Run("WithIP", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.IPPort
			value string
			want  xddr.IPPort
		}{
			{":80", "127.0.0.1", "127.0.0.1:80"},
			{"127.0.0.1:80", "::1", "[::1]:80"},
			{"[::1]:80", "0.0.0.0", "0.0.0.0:80"},
		} {
			t.Run(fmt.Sprintf("IPPort(%q).WithIP(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithIP(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}

		_, err := xddr.IPPort("127.0.0.1:80").WithIP("abc")
		AssertErrorContains(t, err, "invalid IP address")
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.IPPort("127.0.0.1:80").WithPort(443)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.IPPort("127.0.0.1:443"))

		_, err = xddr.IPPort("127.0.0.1:80").WithPort(70000)
		AssertErrorContains(t, err, "port number must be between 0 and 65535")
	})
}

func TestIPwithCIDR(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.IPwithCIDR
			normalized xddr.IPwithCIDR
		}{
			{"10.0.0.0/8", "10.0.0.0/8"},
			{"192.168.0.0/16", "192.168.0.0/16"},
			{"::/0", "::/0"},
			{"0:0::1/128", "::1/128"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
		for _, tc := range [][]string{
			{"missing '/' separator for CIDR",
				"1.2.3.4",
			},
			{"missing IP address before '/'",
				"/8",
			},
			{"invalid network size",
				"1.2.3.4/x",
			},
			{"network size must be between 0 and 32 for IPv4",
				"1.2.3.4/33",
			},
			{"network size must be between 0 and 128 for IPv6",
				"::1/129",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("IPwithCIDR(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.IPwithCIDR(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Split", func(t *testing.T) {
		ip, n := xddr.IPwithCIDR("10.0.0.0/8").Split()
		AssertEq(t, ip, xddr.IP("10.0.0.0"))
		AssertEq(t, n, 8)
		AssertEq(t, xddr.IPwithCIDR("10.0.0.0/8").IP(), xddr.IP("10.0.0.0"))
		AssertEq(t, xddr.IPwithCIDR("10.0.0.0/8").Size(), 8)
	})
	t.Run("Is", func(t *testing.T) {
		Assert(t, xddr.IPwithCIDR("10.0.0.0/8").IsPrivate(), "10.0.0.0/8 is private")
		Assert(t, xddr.IPwithCIDR("127.0.0.1/32").IsLoopback(), "127.0.0.1/32 is loopback")
		Assert(t, xddr.IPwithCIDR("0.0.0.0/0").IsUnspecified(), "0.0.0.0/0 is unspecified")
	})
}

func TestIPv6(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.IPv6
			want  xddr.IPv6
		}{
			{"::", "::"},
			{"::1", "::1"},
			{"1::", "1::"},
			{"1::1", "1::1"},
			{"::1:0:0:1", "::1:0:0:1"},
			{"1:0:0:1::", "1:0:0:1::"},
			{"::AbCd", "::abcd"},
			{"1:0:1:0:1:2:3:4", "1:0:1:0:1:2:3:4"},
			{"::ffff:192.0.2.128", "::ffff:192.0.2.128"},
			{"::0:ffff:192.0.2.128", "::ffff:192.0.2.128"},
			{"0::ffff:192.0.2.128", "::ffff:192.0.2.128"},
			{"0::0:ffff:192.0.2.128", "::ffff:192.0.2.128"},
			{"0:0:0:0:0:ffff:192.0.2.128", "::ffff:192.0.2.128"},
			{"aaaa:0:0:bbbb:0:0:0:d", "aaaa:0:0:bbbb::d"},
			{"aaaa:0:0:bbbb:0:0:c:d", "aaaa::bbbb:0:0:c:d"},
			{"aaaa:0:0:bbbb::c:d", "aaaa::bbbb:0:0:c:d"},
			{"0aaa:00bb:000c:000:00:0:d:e", "aaa:bb:c::d:e"},
			{"1111:2222:3333:4444:5555:6666:7777:8888", "1111:2222:3333:4444:5555:6666:7777:8888"},

			// Zero runs interleaved with non-zero blocks.
			{"0:1:0:2:0:3:0:0", "0:1:0:2:0:3::"},
			{"0:0:1:0:2:0:3:0", "::1:0:2:0:3:0"},
			{"1::7:0", "1::7:0"},
			{"1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7:0"},

			// Dotted-quad tails.
			{"::ffff:102:304", "::ffff:102:304"},
			{"64:ff9b::1.2.3.4", "64:ff9b::102:304"},
			{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
			{"::1.2.3.4", "::102:304"},
		} {
			t.Run(fmt.Sprintf("IPv6(%q).Sanitize()=%q", tc.given, tc.want), func(t *testing.T) {
				value, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
			t.Run(fmt.Sprintf("IPv6(%q).Sanitize()=%q", "["+tc.given+"]", tc.want), func(t *testing.T) {
				value, err := xddr.IPv6("[" + tc.given + "]").Sanitize()
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
		for _, tc := range [][]string{
			{"empty",
				""},
			{"missing closing ']'",
				"[::1"},
			{"must have at most 8 blocks",
				"1:2:3:4:5:6:7:8:9",
			},
			{"must have at least 2 colons",
				"1",
				"1:",
				":1",
			},
			{"must have at least 2 colons",
				"1:2",
			},
			{"must have 8 blocks",
				"1:2:3",
				"1:2:3:4:5:6:7",
			},
			{"IPv4-mapped address must be at the end",
				"::1.2.3.4:ffff",
			},
			{"single ':' at the beginning is not allowed",
				":2::",
				":2:3::",
				":2:3:4:5:6:7",
			},
			{"single ':' at the end is not allowed",
				"::7:",
				"::6:7:",
				"1:2:3:4:5:6:7:",
			},
			{"only one '::' allowed",
				"::0::",
				"::1::",
				"1::0::",
				"1::1::",
				"1:0::4::6",
				"1:2::4::6",
				"1::0:4::6",
				"1::3:4::6",
			},
			{"invalid IPv4-mapped IPv6 address",
				"::ffff:1.2.3",
				"::ffff:1.2..3",
				"::ffff:1.01.0.1",
				"::ffff:255.1.2.X",
				"::ffff:256.0.0.1",
			},
			{"block too long",
				"12345::",
				"::23456",
				"::2:34567",
			},
			{"not a valid hex number",
				"::-1",
				"g::",
				"::h",
				"::1:z",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("IPv6(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.IPv6(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("Bytes", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.IPv6
			want  [16]byte
		}{
			{"::", [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			{"::1", [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			{"1::", [16]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			{"1::1", [16]byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			{"::ffff:192.0.2.128", [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 128}},
			{"64:ff9b::1.2.3.4", [16]byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
			{"64:ff9b::102:304", [16]byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}},
			{"aaaa:0:0:bbbb::cccc", [16]byte{0xaa, 0xaa, 0, 0, 0, 0, 0xbb, 0xbb, 0, 0, 0, 0, 0, 0, 0xcc, 0xcc}},
			{"1111:2222:3333:4444:5555:6666:7777:8888", [16]byte{0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88}},
		} {
			t.Run(fmt.Sprintf("IPv6(%q).Bytes()=%v", tc.given, tc.want), func(t *testing.T) {
				got := tc.given.Bytes()
				AssertEq(t, got, tc.want)
			})
		}
	})
}
