package handler

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func setupCopyHandler(t *testing.T) (*Handler, *backend.Backend) {
	t.Helper()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src")
	mustCreateBucket(t, b, "dst")
	mustPutObject(t, b, "src", "key", "data")
	return h, b
}

func TestCopyObjectAdditionalBranches(t *testing.T) {
	t.Run("source access denied", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "src-owner")
		b.SetBucketOwner("dst", "dst-owner")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{"x-amz-copy-source": "/src/key"},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("destination access denied", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "src-owner")
		b.SetBucketOwner("dst", "dst-owner")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{
					"Authorization":     authHeader("src-owner"),
					"x-amz-copy-source": "/src/key",
				},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("conditional mismatch returns precondition failed", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{
					"Authorization":              authHeader("copy-owner"),
					"x-amz-copy-source":          "/src/key",
					"x-amz-copy-source-if-match": "\"other\"",
				},
			),
		)
		requireStatus(t, w, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, w, "PreconditionFailed")
	})

	t.Run("copy source bucket missing", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "dst")
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{"x-amz-copy-source": "/missing/key"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("destination bucket missing", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "src")
		mustPutObject(t, b, "src", "key", "data")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing/copied",
				"",
				map[string]string{"x-amz-copy-source": "/src/key"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("conditional missing version", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")
		if err := b.SetBucketVersioning("src", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "src", "key", "new-data")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{
					"Authorization":              authHeader("copy-owner"),
					"x-amz-copy-source":          "/src/key?versionId=missing",
					"x-amz-copy-source-if-match": "\"etag\"",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("conditional delete marker version", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")
		if err := b.SetBucketVersioning("src", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "src", "key", "new-data")
		delRes, err := b.DeleteObject("src", "key", false)
		if err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		if !delRes.IsDeleteMarker || delRes.VersionId == "" {
			t.Fatalf("expected delete marker result, got %+v", delRes)
		}
		headers := map[string]string{
			"Authorization": authHeader("copy-owner"),
			"x-amz-copy-source": fmt.Sprintf(
				"/src/key?versionId=%s",
				delRes.VersionId,
			),
			"x-amz-copy-source-if-match": "\"etag\"",
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				headers,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("no-conditional missing version at copy stage", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")
		if err := b.SetBucketVersioning("src", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "src", "key", "new-data")

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{
					"Authorization":     authHeader("copy-owner"),
					"x-amz-copy-source": "/src/key?versionId=missing",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("object lock headers without destination lock config", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")
		retainUntil := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		headers := map[string]string{
			"Authorization":                       authHeader("copy-owner"),
			"x-amz-copy-source":                   "/src/key",
			"x-amz-object-lock-mode":              backend.RetentionModeGovernance,
			"x-amz-object-lock-retain-until-date": retainUntil,
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				headers,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("copy with replace directives and version headers", func(t *testing.T) {
		h, b := setupCopyHandler(t)
		b.SetBucketOwner("src", "copy-owner")
		b.SetBucketOwner("dst", "copy-owner")
		if err := b.SetBucketVersioning("src", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if err := b.SetBucketVersioning("dst", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "src", "key", "latest-data")
		srcObj, err := b.GetObject("src", "key")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		headers := map[string]string{
			"Authorization": authHeader("copy-owner"),
			"x-amz-copy-source": fmt.Sprintf(
				"/src/key?versionId=%s",
				srcObj.VersionId,
			),
			"x-amz-metadata-directive":        "REPLACE",
			"Content-Type":                    "text/plain",
			"x-amz-meta-foo":                  "bar",
			"x-amz-tagging-directive":         "REPLACE",
			"x-amz-tagging":                   "k=v",
			"x-amz-storage-class":             "STANDARD_IA",
			"x-amz-website-redirect-location": "/landing.html",
			"x-amz-server-side-encryption":    "AES256",
			"x-amz-checksum-algorithm":        "SHA256",
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				headers,
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-copy-source-version-id"); got != srcObj.VersionId {
			t.Fatalf("unexpected source version header: %q", got)
		}
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("expected destination version id header")
		}
		if got := w.Header().Get("x-amz-storage-class"); got != "STANDARD_IA" {
			t.Fatalf("unexpected storage class header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption"); got != "AES256" {
			t.Fatalf("unexpected sse header: %q", got)
		}

		copied, err := b.GetObject("dst", "copied")
		if err != nil {
			t.Fatalf("GetObject(dst/copied) failed: %v", err)
		}
		if copied.Metadata["foo"] != "bar" {
			t.Fatalf("metadata replace did not apply: %+v", copied.Metadata)
		}
		if copied.Tags["k"] != "v" {
			t.Fatalf("tagging replace did not apply: %+v", copied.Tags)
		}
		if copied.StorageClass != "STANDARD_IA" {
			t.Fatalf("unexpected storage class on copied object: %q", copied.StorageClass)
		}
		if copied.WebsiteRedirectLocation != "/landing.html" {
			t.Fatalf("unexpected website redirect: %q", copied.WebsiteRedirectLocation)
		}
		if copied.ServerSideEncryption != "AES256" {
			t.Fatalf("unexpected destination SSE: %q", copied.ServerSideEncryption)
		}
		if copied.ChecksumAlgorithm != "SHA256" {
			t.Fatalf("unexpected checksum algorithm: %q", copied.ChecksumAlgorithm)
		}
	})
}
