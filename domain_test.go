package xddr_test

import (
	"fmt"
	"testing"

	"github.com/lesomnus/xddr"
)

func TestDomain(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, given := range []xddr.Domain{
			"localhost",
			"com",
			"com.",
			"42",
			"42.",
			"example.com",
			"example.com.",
			"sub.domain.example.com",
			"xn--o70b819a.example.com",
		} {
			t.Run(fmt.Sprintf("Domain(%q).Sanitize()=%q", given, given), func(t *testing.T) {
				_, err := given.Sanitize()
				AssertNoError(t, err)
			})
		}
		for _, tc := range [][]string{
			{"domain cannot be empty",
				"",
			},
			{"empty label",
				".example.com",
				"example..com",
			},
			{"label too long",
				"a-very-long-label-which-exceeds-the-maximum-length-of-sixty-three-characters.example.com",
			},
			{"label cannot start with a hyphen",
				"-",
				"-.",
				"-com.",
				"-example.com",
				"-example.com.",
				"foo.-example.com",
				"foo.-example.com.",
			},
			{"invalid character",
				"a_.com",
				"a!.com",
				"a#.com",
				"a?.com",
				"a/.com",
				"a+.com",
			},
		} {
			for _, given := range tc[1:] {
				t.Run(fmt.Sprintf("Domain(%q).Sanitize() -> %q", given, tc[0]), func(t *testing.T) {
					_, err := xddr.Domain(given).Sanitize()
					AssertErrorContains(t, err, tc[0])
				})
			}
		}
	})
}
