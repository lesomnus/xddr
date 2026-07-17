package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestTCPUnixLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{":80", "tcp::80"},
			{"[::]:80", "tcp6:[::]:80"},
			{"tcp::80", "tcp::80"},
			{"tcp4::80", "tcp4:0.0.0.0:80"},
			{"0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"localhost:80", "tcp:localhost:80"},
			{"/var/run/x.sock", "unix:/var/run/x.sock"},
			{"./rel.sock", "unix:./rel.sock"},
			{"unix:/var/run/x.sock", "unix:/var/run/x.sock"},
			{"unixgram:/var/run/x.sock", "unixgram:/var/run/x.sock"},
			{"unixpacket:/var/run/x.sock", "unixpacket:/var/run/x.sock"},
		} {
			t.Run(fmt.Sprintf("TCPUnixLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.TCPUnixLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.TCPUnixLocal(tc[1]))
			})
		}

		_, err := xddr.TCPUnixLocal("").Sanitize()
		AssertErrorContains(t, err, "empty local address")
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.TCPUnixLocal
			value string
			want  xddr.TCPUnixLocal
		}{
			{"tcp::80", "192.0.2.1", "tcp4:192.0.2.1:80"},
			{"tcp::80", "[2001:db8::1]", "tcp6:[2001:db8::1]:80"},
			{"tcp::80", "localhost", "tcp:localhost:80"},

			// A filesystem path switches it to a Unix domain socket.
			{"tcp::80", "/x.sock", "unix:/x.sock"},
			{"tcp::80", "./x.sock", "unix:./x.sock"},
		} {
			t.Run(fmt.Sprintf("TCPUnixLocal(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}

		_, err := xddr.TCPUnixLocal("unix:/x.sock").WithHost("localhost")
		AssertErrorContains(t, err, "not a TCP local address")
	})
	t.Run("WithPort", func(t *testing.T) {
		v, err := xddr.TCPUnixLocal("tcp::80").WithPort(443)
		AssertNoError(t, err)
		AssertEq(t, v, xddr.TCPUnixLocal("tcp::443"))

		_, err = xddr.TCPUnixLocal("unix:/x.sock").WithPort(80)
		AssertErrorContains(t, err, "not a TCP local address")

		_, err = xddr.TCPUnixLocal("tcp::80").WithPort(-1)
		AssertErrorContains(t, err, "port number out of range")

		_, err = xddr.TCPUnixLocal("tcp::80").WithPort(70000)
		AssertErrorContains(t, err, "port number out of range")
	})
}
