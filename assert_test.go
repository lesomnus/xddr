package xddr_test

import (
	"strings"
	"testing"
)

type A struct {
	t *testing.T
}

func Assert(t *testing.T, cond bool, format string, args ...any) A {
	if !cond {
		t.Helper()
		t.Fatalf(format, args...)
	}
	return A{t}
}

func AssertNoError(t *testing.T, err error) A {
	if err != nil {
		t.Helper()
		t.Fatalf("want no error, but %q", err)
	}
	return A{t}
}

func AssertErrorContains(t *testing.T, err error, substr string) A {
	if err == nil {
		t.Helper()
		t.Fatalf("want error containing %q, but nil", substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Helper()
		t.Fatalf("want error containing %q, but %q", substr, err)
	}
	return A{t}
}

func AssertEq[T comparable](t *testing.T, got, want T) A {
	if got != want {
		t.Helper()
		t.Fatalf("want \"%v\", but \"%v\"", want, got)
	}
	return A{t}
}
