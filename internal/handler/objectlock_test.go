package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestObjectLockConfigurationHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "plain-bucket")
	mustCreateObjectLockBucket(t, b, "lock-bucket")

	t.Run("get object lock config bucket not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/nope?object-lock", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("get object lock config not enabled", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/plain-bucket?object-lock", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "ObjectLockConfigurationNotFoundError")
	})

	t.Run("get object lock config success", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/lock-bucket?object-lock", "", nil))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("put object lock config malformed xml", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-bucket?object-lock",
				"<broken",
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put object lock config bucket not found", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/nope?object-lock", payload, nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("put object lock config invalid bucket state", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/plain-bucket?object-lock", payload, nil),
		)
		requireStatus(t, w, http.StatusConflict)
		requireS3ErrorCode(t, w, "InvalidBucketState")
	})

	t.Run("put object lock config invalid retention period", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>0</Days></DefaultRetention></Rule></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket?object-lock", payload, nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRetentionPeriod")
	})

	t.Run("put object lock config invalid mode", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>INVALID</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket?object-lock", payload, nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put object lock config success", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket?object-lock", payload, nil),
		)
		requireStatus(t, w, http.StatusOK)
	})
}

func TestObjectRetentionHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "plain-bucket")
	mustCreateObjectLockBucket(t, b, "lock-bucket")
	mustPutObject(t, b, "plain-bucket", "obj", "data")
	mustPutObject(t, b, "lock-bucket", "no-retention", "data")

	retainedUntil := time.Now().Add(24 * time.Hour).UTC()
	if _, err := b.PutObject(
		"lock-bucket",
		"locked",
		[]byte("data"),
		backend.PutObjectOptions{RetentionMode: "GOVERNANCE", RetainUntilDate: &retainedUntil},
	); err != nil {
		t.Fatalf("PutObject locked failed: %v", err)
	}

	t.Run("get retention bucket not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/nope/key?retention", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("get retention object lock not enabled", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/plain-bucket/obj?retention", "", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("get retention object not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/lock-bucket/missing?retention", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("get retention no such object lock config", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/lock-bucket/no-retention?retention", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchObjectLockConfiguration")
	})

	t.Run("put retention malformed xml", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/no-retention?retention", "<bad", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put retention invalid mode", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><Retention><Mode>INVALID</Mode><RetainUntilDate>2026-12-31T00:00:00Z</RetainUntilDate></Retention>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/no-retention?retention", payload, nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put retention object locked", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2026-12-31T00:00:00Z</RetainUntilDate></Retention>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/locked?retention", payload, nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("put retention success with bypass", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2026-12-31T00:00:00Z</RetainUntilDate></Retention>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-bucket/locked?retention",
				payload,
				map[string]string{"x-amz-bypass-governance-retention": "true"},
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("get retention success", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/lock-bucket/locked?retention", "", nil))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("version not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/lock-bucket/locked?retention&versionId=nope", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})
}

func TestObjectLegalHoldHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "plain-bucket")
	mustCreateObjectLockBucket(t, b, "lock-bucket")
	mustPutObject(t, b, "plain-bucket", "obj", "data")
	mustPutObject(t, b, "lock-bucket", "obj", "data")

	t.Run("get legal hold bucket not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/nope/obj?legal-hold", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("get legal hold object lock not enabled", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/plain-bucket/obj?legal-hold", "", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("put legal hold malformed xml", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/obj?legal-hold", "<bad", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put legal hold invalid status", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>MAYBE</Status></LegalHold>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/obj?legal-hold", payload, nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put legal hold success", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>ON</Status></LegalHold>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/obj?legal-hold", payload, nil),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("get legal hold success", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/lock-bucket/obj?legal-hold", "", nil))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("get legal hold version not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/lock-bucket/obj?legal-hold&versionId=nope", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("put legal hold object not found", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>ON</Status></LegalHold>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/lock-bucket/nope?legal-hold", payload, nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("put legal hold bucket not found", func(t *testing.T) {
		payload := `<?xml version="1.0" encoding="UTF-8"?><LegalHold><Status>ON</Status></LegalHold>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/nope/obj?legal-hold", payload, nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})
}
