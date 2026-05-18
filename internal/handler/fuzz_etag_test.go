package handler

import "testing"

func FuzzMatchesETag(f *testing.F) {
	f.Add("*", "\"abc123\"")
	f.Add("\"abc123\"", "\"abc123\"")
	f.Add("\"abc\"", "\"def\"")
	f.Add("", "")
	f.Add("abc", "abc")
	f.Add("W/\"abc\"", "\"abc\"")

	f.Fuzz(func(t *testing.T, header, etag string) {
		_ = matchesETag(header, etag)
	})
}
