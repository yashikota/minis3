package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestObjectLockReadErrorAndMissingBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "plain-lock-extra")
	mustCreateObjectLockBucket(t, b, "lock-extra")
	mustPutObject(t, b, "plain-lock-extra", "obj", "data")
	mustPutObject(t, b, "lock-extra", "obj", "data")

	retentionPayload := `<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2027-01-01T00:00:00Z</RetainUntilDate></Retention>`
	legalHoldPayload := `<LegalHold><Status>ON</Status></LegalHold>`
	objectLockConfigPayload := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`

	t.Run("put object lock config read error", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/lock-extra?object-lock",
			nil,
		)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("put retention read error", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/lock-extra/obj?retention",
			nil,
		)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("put retention missing bucket, key, version and lock config", func(t *testing.T) {
		wBucket := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-such-lock/obj?retention",
				retentionPayload,
				nil,
			),
		)
		requireStatus(t, wBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wBucket, "NoSuchBucket")

		wKey := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra/missing?retention",
				retentionPayload,
				nil,
			),
		)
		requireStatus(t, wKey, http.StatusNotFound)
		requireS3ErrorCode(t, wKey, "NoSuchKey")

		wVersion := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra/obj?retention&versionId=missing",
				retentionPayload,
				nil,
			),
		)
		requireStatus(t, wVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wVersion, "NoSuchVersion")

		wNoLock := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/plain-lock-extra/obj?retention",
				retentionPayload,
				nil,
			),
		)
		requireStatus(t, wNoLock, http.StatusBadRequest)
		requireS3ErrorCode(t, wNoLock, "InvalidRequest")
	})

	t.Run("get legal hold missing key", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/lock-extra/missing?legal-hold",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("put legal hold read error", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/lock-extra/obj?legal-hold",
			nil,
		)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("put legal hold missing version and lock config", func(t *testing.T) {
		wVersion := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra/obj?legal-hold&versionId=missing",
				legalHoldPayload,
				nil,
			),
		)
		requireStatus(t, wVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wVersion, "NoSuchVersion")

		wNoLock := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/plain-lock-extra/obj?legal-hold",
				legalHoldPayload,
				nil,
			),
		)
		requireStatus(t, wNoLock, http.StatusBadRequest)
		requireS3ErrorCode(t, wNoLock, "InvalidRequest")
	})

	t.Run("put object lock config generic malformed schema branch", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra?object-lock",
				objectLockConfigPayload,
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("put retention and legal hold remain functional", func(t *testing.T) {
		wRetention := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra/obj?retention",
				retentionPayload,
				nil,
			),
		)
		requireStatus(t, wRetention, http.StatusOK)

		wLegalHold := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/lock-extra/obj?legal-hold",
				legalHoldPayload,
				nil,
			),
		)
		requireStatus(t, wLegalHold, http.StatusOK)
	})

	t.Run("sanity check object lock bucket exists", func(t *testing.T) {
		if _, ok := b.GetBucket("lock-extra"); !ok {
			t.Fatal("lock-extra bucket should exist")
		}
	})
}

func TestPutObjectLockConfigurationMissingBucketBranch(t *testing.T) {
	h, _ := newTestHandler(t)
	payload := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/no-such-lock-extra?object-lock",
			payload,
			nil,
		),
	)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchBucket")
}

func TestPutObjectLockConfigurationMalformedXMLBranch(t *testing.T) {
	h, _ := newTestHandler(t)
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/no-such-lock-extra?object-lock",
			"<bad",
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "MalformedXML")
}

func TestPutObjectLockConfigurationInvalidStateBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "plain-lock-invalid-state")
	payload := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/plain-lock-invalid-state?object-lock",
			payload,
			nil,
		),
	)
	requireStatus(t, w, http.StatusConflict)
	requireS3ErrorCode(t, w, "InvalidBucketState")
}

func TestPutObjectLockConfigurationInvalidRetentionPeriodBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-invalid-retention")
	payload := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>0</Days></DefaultRetention></Rule></ObjectLockConfiguration>`
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/lock-invalid-retention?object-lock",
			payload,
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidRetentionPeriod")
}

func TestPutObjectLockConfigurationInvalidConfigBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-invalid-config")
	payload := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>INVALID</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>`
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/lock-invalid-config?object-lock",
			payload,
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "MalformedXML")
}

func TestPutObjectRetentionInvalidConfigBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "retention-invalid-config")
	mustPutObject(t, b, "retention-invalid-config", "obj", "data")
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/retention-invalid-config/obj?retention",
			`<Retention><Mode>INVALID</Mode><RetainUntilDate>2027-01-01T00:00:00Z</RetainUntilDate></Retention>`,
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "MalformedXML")
}

func TestPutObjectLegalHoldInvalidConfigBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "legalhold-invalid-config")
	mustPutObject(t, b, "legalhold-invalid-config", "obj", "data")
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/legalhold-invalid-config/obj?legal-hold",
			`<LegalHold><Status>MAYBE</Status></LegalHold>`,
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "MalformedXML")
}

func TestObjectLockHelpersSanity(t *testing.T) {
	if backend.S3Xmlns == "" {
		t.Fatal("expected backend.S3Xmlns to be non-empty")
	}
}
