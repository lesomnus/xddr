package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestGRPC(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.GRPC
			normalized xddr.GRPC
		}{
			{"grpc.io", "dns:///grpc.io"},
			{"grpc.io:50051", "dns:///grpc.io:50051"},
			{"dns:grpc.io:50051", "dns:///grpc.io:50051"},
			{"dns://grpc.io:50051", "dns://grpc.io:50051"},
			{"dns:///grpc.io:50051", "dns:///grpc.io:50051"},
			{"dns://resolver.example/grpc.io:50051", "dns://resolver.example/grpc.io:50051"},
			{"xds:///wallet.grpcwallet.io", "xds:///wallet.grpcwallet.io"},
			{"unix:///var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"unix:/var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"unix:rel.sock", "unix:rel.sock"},
			{"ipv4:198.51.100.123:50051", "ipv4:198.51.100.123:50051"},

			// IPv6 endpoints.
			{"[::1]:50051", "dns:///[::1]:50051"},
			{"dns:///[::1]:50051", "dns:///[::1]:50051"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
	})
	t.Run("Endpoint", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.GRPC
			want  xddr.Authority
		}{
			{"dns:///grpc.io:50051", "grpc.io:50051"},
			{"dns://grpc.io:50051", "grpc.io:50051"},
			{"dns://resolver.example/grpc.io:50051", "grpc.io:50051"},
			{"xds:///wallet.grpcwallet.io", "wallet.grpcwallet.io"},
			{"ipv4:198.51.100.123:50051", "198.51.100.123:50051"},
			{"unix:///var/run/grpc.sock", ""},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				AssertEq(t, tc.given.Endpoint(), tc.want)
			})
		}
	})
	t.Run("HostPort", func(t *testing.T) {
		v := xddr.GRPC("dns:///grpc.io:50051")
		AssertEq(t, v.Scheme(), "dns")
		AssertEq(t, v.Host(), xddr.Host("grpc.io"))
		AssertEq(t, v.Port(), 50051)

		v = xddr.GRPC("ipv4:198.51.100.123:50051")
		AssertEq(t, v.Scheme(), "ipv4")
		AssertEq(t, v.Host(), xddr.Host("198.51.100.123"))
		AssertEq(t, v.Port(), 50051)
	})
	t.Run("Local", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.GRPC
			want  xddr.Local
		}{
			{"dns:///grpc.io:50051", "tcp:grpc.io:50051"},
			{"dns:///192.0.2.1:50051", "tcp4:192.0.2.1:50051"},
			{"dns:///[2001:db8::1]:50051", "tcp6:[2001:db8::1]:50051"},
			{"dns://grpc.io:50051", "tcp:grpc.io:50051"},
			{"xds:///wallet.grpcwallet.io", "tcp:wallet.grpcwallet.io"},
			{"ipv4:198.51.100.123:50051", "tcp4:198.51.100.123:50051"},
			{"ipv6:[2001:db8::1]:50051", "tcp6:[2001:db8::1]:50051"},
			{"unix:///var/run/grpc.sock", "unix:/var/run/grpc.sock"},
			{"unix:rel.sock", "unix:rel.sock"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				AssertEq(t, tc.given.Local(), tc.want)
			})
		}
	})
	t.Run("WithHost", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.GRPC
			value string
			want  xddr.GRPC
		}{
			{"dns:///grpc.io:50051", "example.com", "dns:///example.com:50051"},
			{"dns://grpc.io:50051", "example.com", "dns://example.com:50051"},
			{"dns://resolver.example/grpc.io:50051", "example.com", "dns://resolver.example/example.com:50051"},
			{"ipv4:198.51.100.123:50051", "203.0.113.7", "ipv4:203.0.113.7:50051"},
		} {
			t.Run(fmt.Sprintf("GRPC(%q).WithHost(%q)=%q", tc.given, tc.value, tc.want), func(t *testing.T) {
				v, err := tc.given.WithHost(tc.value)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}

		_, err := xddr.GRPC("unix:///var/run/grpc.sock").WithHost("example.com")
		AssertErrorContains(t, err, "unix target does not have a host")
	})
	t.Run("WithPort", func(t *testing.T) {
		for _, tc := range []struct {
			given xddr.GRPC
			port  int
			want  xddr.GRPC
		}{
			{"dns:///grpc.io:50051", 443, "dns:///grpc.io:443"},
			{"dns://grpc.io:50051", 443, "dns://grpc.io:443"},
		} {
			t.Run(fmt.Sprintf("GRPC(%q).WithPort(%d)=%q", tc.given, tc.port, tc.want), func(t *testing.T) {
				v, err := tc.given.WithPort(tc.port)
				AssertNoError(t, err)
				AssertEq(t, v, tc.want)
			})
		}

		_, err := xddr.GRPC("unix:///var/run/grpc.sock").WithPort(443)
		AssertErrorContains(t, err, "unix target does not have a port")
	})
}

func TestGRPCLocal(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range [][]string{
			{":80", "tcp::80"},
			{"0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"[::]:80", "tcp6:[::]:80"},
			{"tcp::80", "tcp::80"},
			{"tcp4::80", "tcp4:0.0.0.0:80"},
			{"tcp4:0.0.0.0:80", "tcp4:0.0.0.0:80"},
			{"tcp6::80", "tcp6:[::]:80"},
			{"tcp6:[::]:80", "tcp6:[::]:80"},
		} {
			t.Run(fmt.Sprintf("GRPCLocal(%q).Sanitize()=%q", tc[0], tc[1]), func(t *testing.T) {
				v, err := xddr.GRPCLocal(tc[0]).Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, xddr.GRPCLocal(tc[1]))
			})
		}
	})
	t.Run("AsURL", func(t *testing.T) {
		for _, tc := range [][]string{
			{"tcp::80", "dns:///127.0.0.1:80"},
			{"tcp4:0.0.0.0:80", "dns:///127.0.0.1:80"},
			{"tcp6::80", "dns:///[::1]:80"},
			{"tcp6:[::]:80", "dns:///[::1]:80"},
			{"unix:/var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"unix:rel.sock", "unix:rel.sock"},
		} {
			t.Run(fmt.Sprintf("GRPCLocal(%q).AsURL()=%q", tc[0], tc[1]), func(t *testing.T) {
				v := xddr.GRPCLocal(tc[0]).AsURL()
				AssertEq(t, v, xddr.GRPC(tc[1]))
			})
		}
	})
}
