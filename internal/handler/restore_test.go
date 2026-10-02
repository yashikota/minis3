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

func TestGetObjectGlacierAutoRestore(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")

	_, err := b.PutObject("bucket", "glacier-key", []byte("data"), backend.PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	t.Run("GET un-restored GLACIER object triggers read-through restore", func(t *testing.T) {
		req := newRequest(http.MethodGet, "/bucket/glacier-key", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidObjectState")
	})

	t.Run("GET restored GLACIER object has x-amz-restore header", func(t *testing.T) {
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

func TestGetObjectArchivedReturnsForbidden(t *testing.T) {
	// AWS returns 403 InvalidObjectState for GetObject on archived
	// objects without a valid restore, regardless of read-through.
	tests := []struct {
		name         string
		storageClass string
		readThrough  string
	}{
		{"GLACIER with read-through ON", "GLACIER", "true"},
		{"GLACIER with read-through OFF", "GLACIER", "false"},
		{"DEEP_ARCHIVE with read-through ON", "DEEP_ARCHIVE", "true"},
		{"DEEP_ARCHIVE with read-through OFF", "DEEP_ARCHIVE", "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MINIS3_CLOUD_ALLOW_READ_THROUGH", tt.readThrough)
			h, b := newTestHandler(t)
			mustCreateBucket(t, b, "bucket")
			if _, err := b.PutObject(
				"bucket",
				"cold-key",
				[]byte("data"),
				backend.PutObjectOptions{StorageClass: tt.storageClass},
			); err != nil {
				t.Fatalf("PutObject: %v", err)
			}
			req := newRequest(http.MethodGet, "/bucket/cold-key", "", nil)
			w := doRequest(h, req)
			requireStatus(t, w, http.StatusForbidden)
			requireS3ErrorCode(t, w, "InvalidObjectState")
		})
	}
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
