package backend

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
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

	f.Add("?", "あ")
	f.Add("a?c", "aéc")

	f.Fuzz(func(t *testing.T, pattern, s string) {
		got := wildcardMatch(pattern, s)
		// Oracle: the pattern translated to an anchored regular expression.
		if utf8.ValidString(pattern) && utf8.ValidString(s) {
			var re strings.Builder
			re.WriteString(`(?s)\A`)
			for _, r := range pattern {
				switch r {
				case '*':
					re.WriteString(".*")
				case '?':
					re.WriteString(".")
				default:
					re.WriteString(regexp.QuoteMeta(string(r)))
				}
			}
			re.WriteString(`\z`)
			if want := regexp.MustCompile(re.String()).MatchString(s); got != want {
				t.Fatalf("wildcardMatch(%q, %q) = %v, regexp oracle = %v", pattern, s, got, want)
			}
		}
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
		if err := p.UnmarshalJSON(data); err != nil {
			return
		}
		// Oracle: every decoded value is the literal spelling of a JSON
		// scalar of the input, in order.
		var raw any
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.UseNumber()
		if err := decoder.Decode(&raw); err != nil {
			t.Fatalf("UnmarshalJSON accepted %q that encoding/json rejects", data)
		}
		items, isArray := raw.([]any)
		if !isArray {
			items = []any{raw}
		}
		want := make([]string, 0, len(items))
		for _, item := range items {
			switch v := item.(type) {
			case string:
				want = append(want, v)
			case json.Number:
				want = append(want, v.String())
			case bool:
				if v {
					want = append(want, "true")
				} else {
					want = append(want, "false")
				}
			default:
				t.Fatalf("UnmarshalJSON accepted a non-scalar value in %q", data)
			}
		}
		if !slices.Equal([]string(p), want) {
			t.Fatalf("UnmarshalJSON(%q) = %q, want %q", data, p, want)
		}
	})
}
