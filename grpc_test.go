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
			{"grpc.io:50051", "dns:///grpc.io:50051"},
			{"dns://grpc.io:50051", "dns://grpc.io:50051"},
			{"dns:///grpc.io:50051", "dns:///grpc.io:50051"},
			{"unix:///var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"unix:/var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"ipv4:198.51.100.123:50051", "ipv4:198.51.100.123:50051"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v, tc.normalized)
			})
		}
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
			{"tcp6:[::]:80", "dns:///[::1]:80"},
			{"unix:/var/run/grpc.sock", "unix:///var/run/grpc.sock"},
		} {
			t.Run(fmt.Sprintf("GRPCLocal(%q).AsURL()=%q", tc[0], tc[1]), func(t *testing.T) {
				v := xddr.GRPCLocal(tc[0]).AsURL()
				AssertEq(t, v, xddr.GRPC(tc[1]))
			})
		}
	})
}
