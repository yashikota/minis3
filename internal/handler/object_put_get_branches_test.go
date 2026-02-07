package handler

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleObjectPutConditionalAndChunkedBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-put-branch")

	t.Run("if-match on missing key returns no such key", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put-branch/missing",
				"data",
				map[string]string{"If-Match": "\"etag\""},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("if-match mismatch returns precondition failed", func(t *testing.T) {
		mustPutObject(t, b, "obj-put-branch", "existing", "data")
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put-branch/existing",
				"new-data",
				map[string]string{"If-Match": "\"other\""},
			),
		)
		requireStatus(t, w, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, w, "PreconditionFailed")
	})

	t.Run("invalid inline tags are rejected", func(t *testing.T) {
		var pairs []string
		for i := 0; i < 11; i++ {
			pairs = append(pairs, "k"+string(rune('a'+i))+"=v")
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put-branch/too-many-tags",
				"data",
				map[string]string{"x-amz-tagging": strings.Join(pairs, "&")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidTag")
	})

	t.Run("aws chunked encoding is decoded and stripped from stored encoding", func(t *testing.T) {
		chunked := "4;chunk-signature=abc\r\ntest\r\n5;chunk-signature=def\r\n-body\r\n0;chunk-signature=end\r\n\r\n"
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put-branch/chunked",
				chunked,
				map[string]string{"Content-Encoding": "aws-chunked,gzip"},
			),
		)
		requireStatus(t, w, http.StatusOK)

		obj, err := b.GetObject("obj-put-branch", "chunked")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if string(obj.Data) != "test-body" {
			t.Fatalf("unexpected stored data: %q", string(obj.Data))
		}
		if obj.ContentEncoding != "gzip" {
			t.Fatalf("expected stored content encoding gzip, got %q", obj.ContentEncoding)
		}
	})
}

func TestHandleObjectGetAdditionalErrorBranches(t *testing.T) {
	h, b := newTestHandler(t)

	t.Run("get missing bucket returns no such bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-get-bucket/key", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("get missing version returns no such version", func(t *testing.T) {
		mustCreateBucket(t, b, "obj-get-version")
		if err := b.SetBucketVersioning("obj-get-version", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "obj-get-version", "k", "v1")
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-get-version/k?versionId=missing",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("get latest delete marker returns delete marker headers", func(t *testing.T) {
		mustCreateBucket(t, b, "obj-get-delete-marker")
		if err := b.SetBucketVersioning("obj-get-delete-marker", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "obj-get-delete-marker", "k", "v1")
		if _, err := b.DeleteObject("obj-get-delete-marker", "k", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-get-delete-marker/k", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
		if got := w.Header().Get("x-amz-delete-marker"); got != "true" {
			t.Fatalf("unexpected x-amz-delete-marker: %q", got)
		}
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("expected x-amz-version-id for delete marker response")
		}
	})
}
