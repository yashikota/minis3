package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleAdmin_ForceDeleteBucket(t *testing.T) {
	t.Run("deletes empty bucket", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "test-bucket")

		req := newRequest(http.MethodDelete, "/_minis3/buckets/test-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)

		if _, ok := b.GetBucket("test-bucket"); ok {
			t.Fatal("bucket still exists after admin force delete")
		}
	})

	t.Run("deletes non-empty bucket", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "test-bucket")
		mustPutObject(t, b, "test-bucket", "key1", "data")

		req := newRequest(http.MethodDelete, "/_minis3/buckets/test-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)

		if _, ok := b.GetBucket("test-bucket"); ok {
			t.Fatal("bucket still exists after admin force delete")
		}
	})

	t.Run("deletes bucket with locked objects", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateObjectLockBucket(t, b, "lock-bucket")

		retain := time.Now().Add(24 * 365 * time.Hour)
		if _, err := b.PutObject("lock-bucket", "locked-key", []byte("data"), backend.PutObjectOptions{
			RetentionMode:   backend.RetentionModeCompliance,
			RetainUntilDate: &retain,
			LegalHoldStatus: backend.LegalHoldStatusOn,
		}); err != nil {
			t.Fatal(err)
		}

		req := newRequest(http.MethodDelete, "/_minis3/buckets/lock-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)

		if _, ok := b.GetBucket("lock-bucket"); ok {
			t.Fatal("bucket still exists after admin force delete")
		}
	})

	t.Run("returns 404 for nonexistent bucket", func(t *testing.T) {
		h, _ := newTestHandler(t)

		req := newRequest(http.MethodDelete, "/_minis3/buckets/no-such-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("returns 404 for empty bucket name", func(t *testing.T) {
		h, _ := newTestHandler(t)

		req := newRequest(http.MethodDelete, "/_minis3/buckets/", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
	})

	t.Run("returns 404 for non-DELETE method", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "test-bucket")

		req := newRequest(http.MethodGet, "/_minis3/buckets/test-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)

		// Bucket should still exist
		if _, ok := b.GetBucket("test-bucket"); !ok {
			t.Fatal("bucket was deleted by non-DELETE request")
		}
	})

	t.Run("returns 404 for unknown admin path", func(t *testing.T) {
		h, _ := newTestHandler(t)

		req := newRequest(http.MethodGet, "/_minis3/unknown", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
	})

	t.Run("does not require S3 auth", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "test-bucket")

		// Request without any Authorization header
		req := newRequest(http.MethodDelete, "/_minis3/buckets/test-bucket", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)
	})
}
