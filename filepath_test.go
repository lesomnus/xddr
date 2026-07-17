package xddr_test

import (
	"testing"

	"github.com/lesomnus/xddr"
)

func TestFilepath(t *testing.T) {
	t.Run("Sanitize", func(t *testing.T) {
		for _, tc := range []struct {
			given      xddr.Filepath
			normalized xddr.Filepath

			scheme   string
			path     string
			query    string
			fragment string
		}{
			{
				"",
				"file://.",
				"file", ".", "", ""},
			{
				"/",
				"file:///",
				"file", "/", "", ""},
			{
				"file:",
				"file:/",
				"file", "/", "", ""},
			{
				"file:/",
				"file:/",
				"file", "/", "", ""},
			{
				"file:.",
				"file:.",
				"file", ".", "", ""},
			{
				"file:./",
				"file:./",
				"file", "./", "", ""},
			{
				"file:../",
				"file:../",
				"file", "../", "", ""},
			{
				"file:/absolute/path.txt",
				"file:/absolute/path.txt",
				"file", "/absolute/path.txt", "", ""},
			{
				"file:./relative/path.txt",
				"file:./relative/path.txt",
				"file", "./relative/path.txt", "", ""},
			{
				"file:../relative/path.txt",
				"file:../relative/path.txt",
				"file", "../relative/path.txt", "", ""},
			{
				"file:///absolute/path.txt",
				"file:///absolute/path.txt",
				"file", "/absolute/path.txt", "", ""},
			{
				"file://./relative/path.txt",
				"file://./relative/path.txt",
				"file", "./relative/path.txt", "", ""},
			{
				"file://../relative/path.txt",
				"file://../relative/path.txt",
				"file", "../relative/path.txt", "", ""},

			// Query.
			{
				"file:/a?query",
				"file:/a?query",
				"file", "/a", "query", ""},
			{
				"file:/a?query#",
				"file:/a?query",
				"file", "/a", "query", ""},
			{
				"file:./r?query",
				"file:./r?query",
				"file", "./r", "query", ""},
			{
				"file:./r?query#",
				"file:./r?query",
				"file", "./r", "query", ""},
			{
				"file:../r?query",
				"file:../r?query",
				"file", "../r", "query", ""},
			{
				"file:///a?query",
				"file:///a?query",
				"file", "/a", "query", ""},
			{
				"file:../r?query",
				"file:../r?query",
				"file", "../r", "query", ""},
			{
				"file:///a?query#",
				"file:///a?query",
				"file", "/a", "query", ""},
			{
				"file://./r?query",
				"file://./r?query",
				"file", "./r", "query", ""},
			{
				"file://./r?query#",
				"file://./r?query",
				"file", "./r", "query", ""},
			{
				"file://../r?query",
				"file://../r?query",
				"file", "../r", "query", ""},
			{
				"file://../r?query#",
				"file://../r?query",
				"file", "../r", "query", ""},

			// Fragment.
			{
				"file:/a#fragment",
				"file:/a#fragment",
				"file", "/a", "", "fragment"},
			{
				"file:/a?#fragment",
				"file:/a#fragment",
				"file", "/a", "", "fragment"},
			{
				"file:./r#fragment",
				"file:./r#fragment",
				"file", "./r", "", "fragment"},
			{
				"file:./r?#fragment",
				"file:./r#fragment",
				"file", "./r", "", "fragment"},
			{
				"file:../r#fragment",
				"file:../r#fragment",
				"file", "../r", "", "fragment"},
			{
				"file:../r?#fragment",
				"file:../r#fragment",
				"file", "../r", "", "fragment"},
			{
				"file:../r#fragment",
				"file:../r#fragment",
				"file", "../r", "", "fragment"},
			{
				"file:../r?#fragment",
				"file:../r#fragment",
				"file", "../r", "", "fragment"},
			{
				"file://./r#fragment",
				"file://./r#fragment",
				"file", "./r", "", "fragment"},
			{
				"file://./r?#fragment",
				"file://./r#fragment",
				"file", "./r", "", "fragment"},
			{
				"file://../r#fragment",
				"file://../r#fragment",
				"file", "../r", "", "fragment"},
			{
				"file://../r?#fragment",
				"file://../r#fragment",
				"file", "../r", "", "fragment"},
		} {
			t.Run(string(tc.given), func(t *testing.T) {
				v, err := tc.given.Sanitize()
				AssertNoError(t, err)
				AssertEq(t, v.Scheme(), tc.scheme)
				AssertEq(t, v.Path(), tc.path)
				AssertEq(t, v.Query(), tc.query)
				AssertEq(t, v.Fragment(), tc.fragment)
			})
		}
	})
	t.Run("WithPath", func(t *testing.T) {
		v, err := xddr.Filepath("file:/a?q#f").WithPath("/b")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.Filepath("file:/b?q#f"))
	})
	t.Run("WithQuery", func(t *testing.T) {
		v, err := xddr.Filepath("file:/a?q#f").WithQuery("x=1")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.Filepath("file:/a?x=1#f"))

		v, err = xddr.Filepath("file:/a?q#f").WithQuery("")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.Filepath("file:/a#f"))
	})
	t.Run("WithFragment", func(t *testing.T) {
		v, err := xddr.Filepath("file:/a?q#f").WithFragment("z")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.Filepath("file:/a?q#z"))

		v, err = xddr.Filepath("file:/a?q#f").WithFragment("")
		AssertNoError(t, err)
		AssertEq(t, v, xddr.Filepath("file:/a?q"))
	})
}
