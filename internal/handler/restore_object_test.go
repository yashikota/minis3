package handler

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleRestoreObject(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "restore-bucket")
	b.SetBucketOwner("restore-bucket", "minis3-access-key")
	ownerHeaders := map[string]string{"Authorization": authHeader("minis3-access-key")}

	// Put a GLACIER object
	if _, err := b.PutObject("restore-bucket", "glacier-key", []byte("archived data"), backend.PutObjectOptions{
		StorageClass: "GLACIER",
	}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Put a STANDARD object
	mustPutObject(t, b, "restore-bucket", "standard-key", "normal data")

	t.Run("POST restore happy path temporary", func(t *testing.T) {
		restoreXML := `<RestoreRequest><Days>7</Days></RestoreRequest>`
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/restore-bucket/glacier-key?restore",
			restoreXML,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("x-amz-restore header on GET after temporary restore", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodGet,
			"http://example.test/restore-bucket/glacier-key",
			"",
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)
		restoreHeader := w.Header().Get("x-amz-restore")
		if restoreHeader == "" {
			t.Fatal("expected x-amz-restore header to be set")
		}
		if !strings.Contains(restoreHeader, `ongoing-request="false"`) {
			t.Fatalf("unexpected restore header: %s", restoreHeader)
		}
		if !strings.Contains(restoreHeader, "expiry-date=") {
			t.Fatalf("expected expiry-date in restore header: %s", restoreHeader)
		}
	})

	t.Run("x-amz-restore header on HEAD after restore", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodHead,
			"http://example.test/restore-bucket/glacier-key",
			"",
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)
		restoreHeader := w.Header().Get("x-amz-restore")
		if restoreHeader == "" {
			t.Fatal("expected x-amz-restore header to be set on HEAD")
		}
	})

	t.Run("POST restore permanent", func(t *testing.T) {
		// Put a new DEEP_ARCHIVE object
		if _, err := b.PutObject("restore-bucket", "deep-key", []byte("deep"), backend.PutObjectOptions{
			StorageClass: "DEEP_ARCHIVE",
		}); err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		restoreXML := `<RestoreRequest></RestoreRequest>`
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/restore-bucket/deep-key?restore",
			restoreXML,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)

		// GET should have restore header without expiry-date
		wGet := doRequest(h, newRequest(
			http.MethodGet,
			"http://example.test/restore-bucket/deep-key",
			"",
			ownerHeaders,
		))
		requireStatus(t, wGet, http.StatusOK)
		restoreHeader := wGet.Header().Get("x-amz-restore")
		if !strings.Contains(restoreHeader, `ongoing-request="false"`) {
			t.Fatalf("unexpected restore header: %s", restoreHeader)
		}
	})

	t.Run("POST restore on non-archived object", func(t *testing.T) {
		restoreXML := `<RestoreRequest><Days>1</Days></RestoreRequest>`
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/restore-bucket/standard-key?restore",
			restoreXML,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidObjectState")
	})

	t.Run("POST restore on nonexistent key", func(t *testing.T) {
		restoreXML := `<RestoreRequest><Days>1</Days></RestoreRequest>`
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/restore-bucket/no-such-key?restore",
			restoreXML,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("POST restore on nonexistent bucket", func(t *testing.T) {
		restoreXML := `<RestoreRequest><Days>1</Days></RestoreRequest>`
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/no-such-bucket/key?restore",
			restoreXML,
			nil,
		))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("GET auto-restores non-restored archived object (read-through)", func(t *testing.T) {
		// Put a new GLACIER object without restoring it
		if _, err := b.PutObject("restore-bucket", "unrestored-key", []byte("need restore"), backend.PutObjectOptions{
			StorageClass: "GLACIER",
		}); err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		w := doRequest(h, newRequest(
			http.MethodGet,
			"http://example.test/restore-bucket/unrestored-key",
			"",
			ownerHeaders,
		))
		// Should succeed (auto-restore / read-through)
		requireStatus(t, w, http.StatusOK)
		if w.Body.String() != "need restore" {
			t.Fatalf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("POST restore malformed XML", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/restore-bucket/glacier-key?restore",
			`<bad xml`,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})
}
