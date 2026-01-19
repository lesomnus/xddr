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
		} {
			t.Run(fmt.Sprintf("IPv4(%q).Bytes()=%v", tc.given, tc.want), func(t *testing.T) {
				got := tc.given.Bytes()
				AssertEq(t, got, tc.want)
			})
		}
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
