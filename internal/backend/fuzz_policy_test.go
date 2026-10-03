package backend

import (
	"strings"
	"testing"
)

func FuzzWildcardMatch(f *testing.F) {
	f.Add("*", "anything")
	f.Add("foo*", "foobar")
	f.Add("?oo", "foo")
	f.Add("", "")
	f.Add("*a*a*a*b", "aaaaaac")
	f.Add("arn:aws:s3:::*", "arn:aws:s3:::my-bucket")
	f.Add("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key.txt")
	f.Add("s3:*", "s3:GetObject")
	f.Add("*", "")
	f.Add("?", "x")
	f.Add("??", "ab")
	f.Add("a*b*c", "axbxc")
	f.Add("a*b*c", "abc")
	f.Add("***", "x")
	f.Add("*?*?*", "ab")
	f.Add(strings.Repeat("*", 50), strings.Repeat("a", 50))
	f.Add("prefix*suffix", "prefixmiddlesuffix")
	f.Add("*.*.*", "a.b.c")

	f.Fuzz(func(t *testing.T, pattern, s string) {
		got := wildcardMatch(pattern, s)
		// Patterns without wildcards behave like string equality.
		if !strings.ContainsAny(pattern, "*?") && got != (pattern == s) {
			t.Fatalf("wildcardMatch(%q, %q) = %v, want %v", pattern, s, got, pattern == s)
		}
		// A lone star matches everything, including the empty string.
		if pattern == "*" && !got {
			t.Fatalf("wildcardMatch(%q, %q) = false, want true", pattern, s)
		}
		// An empty pattern matches only the empty string.
		if pattern == "" && got != (s == "") {
			t.Fatalf("wildcardMatch(%q, %q) = %v, want %v", pattern, s, got, s == "")
		}
	})
}

func FuzzPolicyStringOrSliceUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`"s3:GetObject"`))
	f.Add([]byte(`["s3:GetObject","s3:PutObject"]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`""`))
	f.Add([]byte(`"*"`))
	f.Add([]byte(`["*"]`))
	f.Add([]byte(`["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"]`))
	f.Add([]byte(`123`))
	f.Add([]byte(`true`))
	f.Add([]byte(`[null]`))
	f.Add([]byte(`[""]`))
	f.Add([]byte(`[123, "abc"]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p PolicyStringOrSlice
		_ = p.UnmarshalJSON(data)
	})
}
