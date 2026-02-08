package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleRestoreObject(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")
	_, err := b.PutObject("bucket", "glacier-key", []byte("data"), backend.PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	_, err = b.PutObject("bucket", "standard-key", []byte("data"), backend.PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	t.Run("restore GLACIER object returns 202", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"/bucket/glacier-key?restore",
			`<RestoreRequest><Days>1</Days></RestoreRequest>`,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusAccepted)
	})

	t.Run("restore already restored returns 200", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"/bucket/glacier-key?restore",
			`<RestoreRequest><Days>5</Days></RestoreRequest>`,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("restore non-GLACIER object returns 403 InvalidObjectState", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"/bucket/standard-key?restore",
			`<RestoreRequest><Days>1</Days></RestoreRequest>`,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidObjectState")
	})

	t.Run("restore non-existent key returns 404", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"/bucket/no-such-key?restore",
			`<RestoreRequest><Days>1</Days></RestoreRequest>`,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("restore in non-existent bucket returns 404", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"/no-bucket/key?restore",
			`<RestoreRequest><Days>1</Days></RestoreRequest>`,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("malformed XML returns 400", func(t *testing.T) {
		req := newRequest(http.MethodPost, "/bucket/glacier-key?restore", `<notxml>`, nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("empty body is accepted", func(t *testing.T) {
		// Re-create a fresh GLACIER object for clean state
		_, err := b.PutObject("bucket", "glacier-key2", []byte("data"), backend.PutObjectOptions{
			StorageClass: "GLACIER",
		})
		if err != nil {
			t.Fatalf("PutObject: %v", err)
		}
		req := newRequest(http.MethodPost, "/bucket/glacier-key2?restore", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusAccepted)
	})
}

func TestGetObjectGlacierBlocked(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")

	_, err := b.PutObject("bucket", "glacier-key", []byte("data"), backend.PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	t.Run("GET un-restored GLACIER object returns 403 InvalidObjectState", func(t *testing.T) {
		req := newRequest(http.MethodGet, "/bucket/glacier-key", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidObjectState")
	})

	t.Run("HEAD un-restored GLACIER object returns 403 InvalidObjectState", func(t *testing.T) {
		req := newRequest(http.MethodHead, "/bucket/glacier-key", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
	})

	t.Run("GET restored GLACIER object succeeds", func(t *testing.T) {
		_, err := b.RestoreObject("bucket", "glacier-key", "", 1)
		if err != nil {
			t.Fatalf("RestoreObject: %v", err)
		}

		req := newRequest(http.MethodGet, "/bucket/glacier-key", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)

		restore := w.Header().Get("x-amz-restore")
		if restore == "" {
			t.Fatal("expected x-amz-restore header")
		}
	})

	t.Run("HEAD restored GLACIER object has x-amz-restore header", func(t *testing.T) {
		req := newRequest(http.MethodHead, "/bucket/glacier-key", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)

		restore := w.Header().Get("x-amz-restore")
		if restore == "" {
			t.Fatal("expected x-amz-restore header")
		}
	})
}

func TestRestoreObjectVersionNotFound(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "bucket")

	_, err := b.PutObject("bucket", "key", []byte("data"), backend.PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	req := newRequest(
		http.MethodPost,
		"/bucket/key?restore&versionId=bad-version",
		`<RestoreRequest><Days>1</Days></RestoreRequest>`,
		nil,
	)
	w := doRequest(h, req)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchVersion")
}
