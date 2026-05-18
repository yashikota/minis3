package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzEvaluateConditionalHeaders(f *testing.F) {
	f.Add("\"abc123\"", "", "", "")
	f.Add("", "\"abc123\"", "", "")
	f.Add("", "", "Mon, 15 Jan 2024 10:30:00 GMT", "")
	f.Add("", "", "", "Mon, 15 Jan 2024 10:30:00 GMT")
	f.Add("*", "", "", "")
	f.Add("\"etag1\", \"etag2\"", "", "", "")
	f.Add("", "", "invalid-date", "")
	f.Add("\"abc\"", "\"def\"", "Mon, 15 Jan 2024 10:30:00 GMT", "Mon, 01 Jan 2020 00:00:00 GMT")

	f.Fuzz(func(t *testing.T, ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		if ifModifiedSince != "" {
			req.Header.Set("If-Modified-Since", ifModifiedSince)
		}
		if ifUnmodifiedSince != "" {
			req.Header.Set("If-Unmodified-Since", ifUnmodifiedSince)
		}

		obj := &backend.Object{
			ETag:         "\"abc123\"",
			LastModified: time.Now(),
		}
		_ = evaluateConditionalHeaders(req, obj)
	})
}
