package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBucketPutReadErrorBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket-readerr")

	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "put bucket tagging read error",
			target: "http://example.test/bucket-readerr?tagging",
		},
		{name: "put bucket policy read error", target: "http://example.test/bucket-readerr?policy"},
		{name: "put bucket acl read error", target: "http://example.test/bucket-readerr?acl"},
		{name: "put lifecycle read error", target: "http://example.test/bucket-readerr?lifecycle"},
		{
			name:   "put encryption read error",
			target: "http://example.test/bucket-readerr?encryption",
		},
		{name: "put cors read error", target: "http://example.test/bucket-readerr?cors"},
		{name: "put website read error", target: "http://example.test/bucket-readerr?website"},
		{
			name:   "put public access block read error",
			target: "http://example.test/bucket-readerr?publicAccessBlock",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, tc.target, nil)
			req.Body = io.NopCloser(failingReader{})
			w := doRequest(h, req)
			requireStatus(t, w, http.StatusBadRequest)
			requireS3ErrorCode(t, w, "InvalidRequest")
		})
	}
}
