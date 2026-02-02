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
}
