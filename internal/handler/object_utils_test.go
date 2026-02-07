package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestStripAWSChunkedContentEncoding(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "no aws-chunked", input: "gzip", expected: "gzip"},
		{name: "suffix aws-chunked", input: "gzip, aws-chunked", expected: "gzip"},
		{name: "prefix aws-chunked", input: "aws-chunked, gzip", expected: "gzip"},
		{
			name:     "middle aws-chunked",
			input:    "deflate, aws-chunked, gzip",
			expected: "deflate, gzip",
		},
		{name: "only aws-chunked", input: "aws-chunked", expected: ""},
		{name: "duplicate aws-chunked", input: "aws-chunked, aws-chunked", expected: ""},
		{name: "whitespace normalized", input: " gzip , aws-chunked ", expected: "gzip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripAWSChunkedContentEncoding(tt.input)
			if got != tt.expected {
				t.Fatalf(
					"stripAWSChunkedContentEncoding(%q) = %q, want %q",
					tt.input,
					got,
					tt.expected,
				)
			}
		})
	}
}

func TestMatchesETag(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		etag    string
		matched bool
	}{
		{name: "wildcard", header: "*", etag: "\"abc\"", matched: true},
		{name: "quoted exact", header: "\"abc\"", etag: "\"abc\"", matched: true},
		{name: "unquoted exact", header: "abc", etag: "\"abc\"", matched: true},
		{name: "csv contains match", header: "def, abc, ghi", etag: "\"abc\"", matched: true},
		{name: "no match", header: "\"xyz\"", etag: "\"abc\"", matched: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesETag(tt.header, tt.etag)
			if got != tt.matched {
				t.Fatalf("matchesETag(%q, %q) = %v, want %v", tt.header, tt.etag, got, tt.matched)
			}
		})
	}
}

func TestEvaluateConditionalHeaders(t *testing.T) {
	lastModified := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	obj := &backend.Object{
		ETag:         "\"etag-1\"",
		LastModified: lastModified,
	}

	t.Run("if-match mismatch returns 412", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.Header.Set("If-Match", "\"other\"")
		result := evaluateConditionalHeaders(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-none-match match returns 304", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.Header.Set("If-None-Match", "\"etag-1\"")
		result := evaluateConditionalHeaders(r, obj)
		if !result.ShouldReturn || result.StatusCode != 304 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-unmodified-since before last-modified returns 412", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.Header.Set("If-Unmodified-Since", lastModified.Add(-time.Minute).Format(http.TimeFormat))
		result := evaluateConditionalHeaders(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-modified-since after last-modified returns 304", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.Header.Set("If-Modified-Since", lastModified.Add(time.Minute).Format(http.TimeFormat))
		result := evaluateConditionalHeaders(r, obj)
		if !result.ShouldReturn || result.StatusCode != 304 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-match takes precedence over if-none-match", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		r.Header.Set("If-Match", "\"other\"")
		r.Header.Set("If-None-Match", "\"etag-1\"")
		result := evaluateConditionalHeaders(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("no conditional headers returns no early response", func(t *testing.T) {
		r := httptest.NewRequest("GET", "http://example.test", nil)
		result := evaluateConditionalHeaders(r, obj)
		if result.ShouldReturn || result.StatusCode != 0 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})
}

func TestEvaluateCopySourceConditionals(t *testing.T) {
	lastModified := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	obj := &backend.Object{
		ETag:         "\"etag-1\"",
		LastModified: lastModified,
	}

	t.Run("if-match mismatch returns 412", func(t *testing.T) {
		r := httptest.NewRequest("PUT", "http://example.test", nil)
		r.Header.Set("x-amz-copy-source-if-match", "\"other\"")
		result := evaluateCopySourceConditionals(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-none-match match returns 412", func(t *testing.T) {
		r := httptest.NewRequest("PUT", "http://example.test", nil)
		r.Header.Set("x-amz-copy-source-if-none-match", "\"etag-1\"")
		result := evaluateCopySourceConditionals(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("if-modified-since not modified returns 412", func(t *testing.T) {
		r := httptest.NewRequest("PUT", "http://example.test", nil)
		r.Header.Set(
			"x-amz-copy-source-if-modified-since",
			lastModified.Add(time.Minute).Format(http.TimeFormat),
		)
		result := evaluateCopySourceConditionals(r, obj)
		if !result.ShouldReturn || result.StatusCode != 412 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})

	t.Run("no conditions returns no early response", func(t *testing.T) {
		r := httptest.NewRequest("PUT", "http://example.test", nil)
		result := evaluateCopySourceConditionals(r, obj)
		if result.ShouldReturn || result.StatusCode != 0 {
			t.Fatalf("unexpected result: %#v", result)
		}
	})
}

func TestParseExpires(t *testing.T) {
	t.Run("empty value", func(t *testing.T) {
		if got := parseExpires(""); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("http time format", func(t *testing.T) {
		input := "Mon, 02 Jan 2006 15:04:05 GMT"
		got := parseExpires(input)
		if got == nil || got.Format(http.TimeFormat) != input {
			t.Fatalf("unexpected parsed time: %v", got)
		}
	})

	t.Run("rfc3339 format", func(t *testing.T) {
		input := "2026-02-07T12:34:56Z"
		got := parseExpires(input)
		if got == nil || got.UTC().Format(time.RFC3339) != input {
			t.Fatalf("unexpected parsed time: %v", got)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		if got := parseExpires("not-a-date"); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}
