package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleObjectMainPaths(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-http")

	t.Run("put object success with metadata", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/obj-http/key",
			"hello-world",
			map[string]string{
				"Content-Type":                 "text/plain",
				"Cache-Control":                "max-age=60",
				"Expires":                      time.Now().UTC().Format(http.TimeFormat),
				"Content-Encoding":             "gzip",
				"Content-Language":             "en",
				"Content-Disposition":          "inline",
				"x-amz-meta-user":              "alice",
				"x-amz-storage-class":          "STANDARD_IA",
				"x-amz-server-side-encryption": "AES256",
				"x-amz-tagging":                "a=b",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("put object precondition failed", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/obj-http/key",
			"new",
			map[string]string{"If-None-Match": "*"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, w, "PreconditionFailed")
	})

	t.Run("get object success", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/obj-http/key?response-content-type=text%2Fplain",
			"",
			map[string]string{"x-amz-checksum-mode": "ENABLED"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("get object range success", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/obj-http/key", "", map[string]string{"Range": "bytes=0-4"})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusPartialContent)
	})

	t.Run("get object range invalid", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/obj-http/key", "", map[string]string{"Range": "bytes=999-1000"})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusRequestedRangeNotSatisfiable)
		requireS3ErrorCode(t, w, "InvalidRange")
	})

	t.Run("get object invalid part number", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/obj-http/key?partNumber=abc", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("get object unsupported sse header", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/obj-http/key",
			"",
			map[string]string{"x-amz-server-side-encryption": "AES256"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("head object success", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodHead, "http://example.test/obj-http/key", "", nil))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("head object unsupported sse header", func(t *testing.T) {
		req := newRequest(
			http.MethodHead,
			"http://example.test/obj-http/key",
			"",
			map[string]string{"x-amz-server-side-encryption": "AES256"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("delete object success", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodDelete, "http://example.test/obj-http/key", "", nil))
		requireStatus(t, w, http.StatusNoContent)
	})

	t.Run("delete object no such bucket", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodDelete, "http://example.test/missing/key", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("head object on delete marker", func(t *testing.T) {
		if err := b.SetBucketVersioning("obj-http", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "obj-http", "ver", "v1")
		if _, err := b.DeleteObject("obj-http", "ver", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		w := doRequest(h, newRequest(http.MethodHead, "http://example.test/obj-http/ver", "", nil))
		requireStatus(t, w, http.StatusNotFound)
	})

	t.Run("method not allowed", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodPatch, "http://example.test/obj-http/key", "", nil))
		requireStatus(t, w, http.StatusMethodNotAllowed)
		requireS3ErrorCode(t, w, "MethodNotAllowed")
	})
}
