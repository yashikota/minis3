package handler

import (
	"strings"
	"testing"
)

func FuzzMatchesETag(f *testing.F) {
	f.Add("*", "\"abc123\"")
	f.Add("\"abc123\"", "\"abc123\"")
	f.Add("\"abc\"", "\"def\"")
	f.Add("", "")
	f.Add("abc", "abc")
	f.Add("W/\"abc\"", "\"abc\"")

	f.Fuzz(func(t *testing.T, header, etag string) {
		got := matchesETag(header, etag)
		// A bare "*" wildcard always matches.
		if header == "*" && !got {
			t.Fatalf("matchesETag(%q, %q) = false, want true", header, etag)
		}
		// A single already-trimmed (comma-free) header equal to the ETag
		// always matches. Surrounding whitespace is stripped from list
		// members before comparison, so all-whitespace inputs intentionally
		// do not round-trip.
		if header != "*" && !strings.Contains(header, ",") &&
			header == etag && strings.TrimSpace(header) == header && !got {
			t.Fatalf("matchesETag(%q, %q) = false, want true", header, etag)
		}
	})
}
