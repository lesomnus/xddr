package xddr_test

import (
	"testing"

	"github.com/lesomnus/xddr"
)

func TestGRPC(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.GRPC
			normalized xddr.GRPC
		}{
			{"grpc.io:50051", "dns://grpc.io:50051"},
			{"dns://grpc.io:50051", "dns://grpc.io:50051"},
			{"unix:///var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"unix:/var/run/grpc.sock", "unix:///var/run/grpc.sock"},
			{"ipv4:198.51.100.123:50051", "ipv4:198.51.100.123:50051"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				value, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, value, tc.normalized)
			})
		}
	})

}
