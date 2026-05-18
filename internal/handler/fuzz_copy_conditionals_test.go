package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzEvaluateCopySourceConditionals(f *testing.F) {
	f.Add("\"etag123\"", "", "", "", "\"etag123\"", int64(1700000000))
	f.Add("", "Thu, 01 Jan 2024 00:00:00 GMT", "", "", "\"etag\"", int64(1700000000))
	f.Add("", "", "\"etag123\"", "", "\"etag123\"", int64(1700000000))
	f.Add("", "", "", "Thu, 01 Jan 2024 00:00:00 GMT", "\"etag\"", int64(1700000000))
	f.Add("", "", "", "", "\"etag\"", int64(1700000000))

	f.Fuzz(
		func(t *testing.T, ifMatch, ifUnmodifiedSince, ifNoneMatch, ifModifiedSince, etag string, lastModUnix int64) {
			if lastModUnix < 0 || lastModUnix > 1e12 {
				return
			}
			req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
			if ifMatch != "" {
				req.Header.Set("x-amz-copy-source-if-match", ifMatch)
			}
			if ifUnmodifiedSince != "" {
				req.Header.Set("x-amz-copy-source-if-unmodified-since", ifUnmodifiedSince)
			}
			if ifNoneMatch != "" {
				req.Header.Set("x-amz-copy-source-if-none-match", ifNoneMatch)
			}
			if ifModifiedSince != "" {
				req.Header.Set("x-amz-copy-source-if-modified-since", ifModifiedSince)
			}
			lastMod := time.Unix(lastModUnix, 0)
			srcObj := &backend.Object{
				ETag:         etag,
				LastModified: lastMod,
			}
			_ = evaluateCopySourceConditionals(req, srcObj)
		},
	)
}

func FuzzLifecycleObjectHasTagForHeader(f *testing.F) {
	f.Add("env", "prod", "env", "prod")
	f.Add("env", "prod", "env", "dev")
	f.Add("key", "value", "other", "val")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, objTagKey, objTagVal, searchKey, searchVal string) {
		obj := &backend.Object{
			Tags: map[string]string{},
		}
		if objTagKey != "" {
			obj.Tags[objTagKey] = objTagVal
		}
		tag := backend.Tag{Key: searchKey, Value: searchVal}
		_ = lifecycleObjectHasTagForHeader(obj, tag)
	})
}

func FuzzLifecycleObjectSizeMatchForHeader(f *testing.F) {
	f.Add(int64(1024), int64(512), int64(2048))
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(100), int64(100), int64(100))
	f.Add(int64(500), int64(0), int64(1000))

	f.Fuzz(func(t *testing.T, size, greaterThan, lessThan int64) {
		if size < 0 || greaterThan < 0 || lessThan < 0 {
			return
		}
		_ = lifecycleObjectSizeMatchForHeader(size, greaterThan, lessThan)
	})
}

func FuzzChecksumFromCompleteHeaders(f *testing.F) {
	f.Add("CRC32", "x-amz-checksum-crc32", "abc123")
	f.Add("CRC32C", "x-amz-checksum-crc32c", "def456")
	f.Add("SHA256", "x-amz-checksum-sha256", "sha256val")
	f.Add("unknown", "", "")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, algorithm, headerName, headerValue string) {
		req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploadId=abc", nil)
		if headerName != "" {
			req.Header.Set(headerName, headerValue)
		}
		_ = checksumFromCompleteHeaders(algorithm, req)
	})
}
