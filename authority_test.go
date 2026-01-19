package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestAuthority(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.Authority
			normalized xddr.Authority

			userinfo string
			host     xddr.Host
			port     int
		}{
			{
				"127.0.0.1",
				"127.0.0.1",
				"", "127.0.0.1", -1,
			},
			{
				"[::1]",
				"[::1]",
				"", "[::1]", -1,
			},
			{
				"host",
				"host",
				"", "host", -1,
			},
			{
				"@host",
				"host",
				"", "host", -1,
			},
			{
				":80",
				":80",
				"", "", 80,
			},
			{
				"user:pass@host",
				"user:pass@host",
				"user:pass", "host", -1,
			},
			{
				"0.0.0.0:80",
				"0.0.0.0:80",
				"", "0.0.0.0", 80,
			},
			{
				"[::]:80",
				"[::]:80",
				"", "[::]", 80,
			},
			{
				"host:80",
				"host:80",
				"", "host", 80,
			},
			{
				"@host:80",
				"host:80",
				"", "host", 80,
			},
			{
				"user@:80",
				"user@:80",
				"user", "", 80,
			},
			{
				"user:pass@host:80",
				"user:pass@host:80",
				"user:pass", "host", 80,
			},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v.Userinfo(), tc.userinfo)
				AssertEq(t, v.Host(), tc.host)
				AssertEq(t, v.Port(), tc.port)
			})
		}
		for _, tc := range [][]string{
			{"invalid character", // in userinfo
				"us er@localhost",
			},
			{"missing host",
				"",
				"@",
			},
			{"invalid IPv6 address format",
				"[:",
				"[:]",
				"@[:]",
				"[:]:42",
				"@[:]:42",
			},
			{"invalid IPv6 address",
				"[1:2]",
			},
			{"invalid host",
				"exa mple.com",
			},
			{"missing port number",
				"example.com:",
				"@example.com:",
			},
			{"invalid character", // in port
				"example.com:8a",
				"example.com:0x42",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("Authority(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.Authority(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
	t.Run("String", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.Authority
			want  string
		}{
			{"host", "host"},
			{"user@host", "user@host"},
			{"user:@host", "user:****@host"},
			{"user:secret@host", "user:****@host"},
			{"host:80", "host:80"},
			{"user@host:80", "user@host:80"},
			{"user:@host:80", "user:****@host:80"},
			{"user:secret@host:80", "user:****@host:80"},
		} {
			t.Run(fmt.Sprintf("Authority(%q).String()=%q", tc.given, tc.want), func(t *testing.T) {
				value := tc.given.String()
				AssertEq(t, value, tc.want)
			})
		}
	})
	t.Run("WithUserinfo", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.Authority
			value string
			want  xddr.Authority
		}{
			{"host", "user:pass", "user:pass@host"},
			{"user@host", "admin", "admin@host"},
			{"user:pass@host", "admin:1234", "admin:1234@host"},
		} {
			t.Run(fmt.Sprintf("Authority(%q).WithUserinfo(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithUserinfo(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.Authority
			value string
			want  xddr.Authority
		}{
			{"user:pass@host", "example.com", "user:pass@example.com"},
			{"user:pass@host:80", "example.com", "user:pass@example.com:80"},
		} {
			t.Run(fmt.Sprintf("Authority(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
	t.Run("WithPort", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.Authority
			value int
			want  xddr.Authority
		}{
			{"user:pass@host", 80, "user:pass@host:80"},
			{"user:pass@host:80", 443, "user:pass@host:443"},
		} {
			t.Run(fmt.Sprintf("Authority(%q).WithPort(%d)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				value, err := tc.given.WithPort(tc.value)
				AssertNoError(t, err)
				AssertEq(t, value, tc.want)
			})
		}
	})
}
