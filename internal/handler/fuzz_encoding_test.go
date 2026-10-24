package handler

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzAwsQueryEscape(f *testing.F) {
	f.Add("/bucket/key with spaces")
	f.Add("")
	f.Add("hello+world")
	f.Add("special!@#$%^&*()")
	f.Add("日本語テスト")
	f.Add("a/b/c/d/e")
	f.Add("~unreserved-chars._")
	f.Add("reserved:/?#[]@!$&'()*+,;=")
	f.Add("\x00\x01\x7f\x80\xff")
	f.Add("AZaz09-_.~")
	f.Add("key=value&foo=bar")
	f.Add("path/to/object with spaces/file (1).txt")

	f.Fuzz(func(t *testing.T, s string) {
		escaped := awsQueryEscape(s)
		// SigV4 URI encoding: only unreserved characters stay as they are.
		if strings.Trim(escaped, sigV4Unreserved+"%") != "" {
			t.Fatalf("awsQueryEscape(%q) = %q leaves a reserved character", s, escaped)
		}
		if got, err := url.PathUnescape(escaped); err != nil || got != s {
			t.Fatalf("awsQueryEscape(%q) = %q does not decode back (%q, %v)", s, escaped, got, err)
		}
	})
}

func FuzzS3URLEncode(f *testing.F) {
	f.Add("/bucket/key")
	f.Add("")
	f.Add("hello world")
	f.Add("special!@#$%^&*()")
	f.Add("日本語")
	f.Add("/a/b/c?query=val")
	f.Add("/bucket/key with spaces/file.txt")
	f.Add("/bucket/特殊文字/キー")
	f.Add("/bucket/key+plus")
	f.Add("/bucket/dir1/dir2/dir3/deep/key")
	f.Add("/bucket/key%already-encoded")

	f.Fuzz(func(t *testing.T, s string) {
		encoded := s3URLEncode(s)
		if strings.Trim(encoded, sigV4Unreserved+"%/") != "" {
			t.Fatalf("s3URLEncode(%q) = %q leaves a reserved character", s, encoded)
		}
		if got, err := url.PathUnescape(encoded); err != nil || got != s {
			t.Fatalf("s3URLEncode(%q) = %q does not decode back (%q, %v)", s, encoded, got, err)
		}
	})
}

func FuzzEncodeHeaderMetadataValue(f *testing.F) {
	f.Add("simple-value")
	f.Add("")
	f.Add("value with spaces")
	f.Add("日本語メタデータ")
	f.Add("\x00\x01\x02\xff")
	f.Add("ASCII only 0123456789")
	f.Add("special=chars;here")
	f.Add("multi\nline\nvalue")
	f.Add("\ttab\tseparated")
	f.Add("emoji: 🎉🚀")

	f.Fuzz(func(t *testing.T, v string) {
		got := encodeHeaderMetadataValue(v)
		latin1 := utf8.ValidString(v)
		nonASCII := false
		for _, r := range v {
			latin1 = latin1 && r <= 0xff
			nonASCII = nonASCII || r > 0x7f
		}
		if !latin1 || !nonASCII {
			if got != v {
				t.Fatalf("encodeHeaderMetadataValue(%q) = %q, want it unchanged", v, got)
			}
			return
		}
		// Latin-1 text is sent as one byte per character.
		var decoded strings.Builder
		for i := 0; i < len(got); i++ {
			decoded.WriteRune(rune(got[i]))
		}
		if len(got) != utf8.RuneCountInString(v) || decoded.String() != v {
			t.Fatalf("encodeHeaderMetadataValue(%q) = %q is not its Latin-1 form", v, got)
		}
	})
}

// sigV4Unreserved are the characters SigV4 URI encoding leaves unescaped.
const sigV4Unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"

func FuzzStripAWSChunkedContentEncoding(f *testing.F) {
	f.Add("aws-chunked")
	f.Add("gzip, aws-chunked")
	f.Add("")
	f.Add("gzip")
	f.Add("aws-chunked, gzip, deflate")
	f.Add(",,,")
	f.Add("identity")
	f.Add("br, gzip, aws-chunked")
	f.Add("AWS-CHUNKED")
	f.Add(" aws-chunked ")

	f.Fuzz(func(t *testing.T, contentEncoding string) {
		_ = stripAWSChunkedContentEncoding(contentEncoding)
	})
}
