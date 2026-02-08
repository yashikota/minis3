package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func patchGetObjectLockConfigurationForTest(
	t *testing.T,
	fn func(*Handler, string) (*backend.ObjectLockConfiguration, error),
) {
	t.Helper()
	orig := getObjectLockConfigurationFn
	getObjectLockConfigurationFn = fn
	t.Cleanup(func() {
		getObjectLockConfigurationFn = orig
	})
}

func patchPutObjectLockConfigurationForTest(
	t *testing.T,
	fn func(*Handler, string, *backend.ObjectLockConfiguration) error,
) {
	t.Helper()
	orig := putObjectLockConfigurationFn
	putObjectLockConfigurationFn = fn
	t.Cleanup(func() {
		putObjectLockConfigurationFn = orig
	})
}

func patchGetObjectRetentionForTest(
	t *testing.T,
	fn func(*Handler, string, string, string) (*backend.ObjectLockRetention, error),
) {
	t.Helper()
	orig := getObjectRetentionFn
	getObjectRetentionFn = fn
	t.Cleanup(func() {
		getObjectRetentionFn = orig
	})
}

func patchPutObjectRetentionForTest(
	t *testing.T,
	fn func(*Handler, string, string, string, *backend.ObjectLockRetention, bool) error,
) {
	t.Helper()
	orig := putObjectRetentionFn
	putObjectRetentionFn = fn
	t.Cleanup(func() {
		putObjectRetentionFn = orig
	})
}

func patchGetObjectLegalHoldForTest(
	t *testing.T,
	fn func(*Handler, string, string, string) (*backend.ObjectLockLegalHold, error),
) {
	t.Helper()
	orig := getObjectLegalHoldFn
	getObjectLegalHoldFn = fn
	t.Cleanup(func() {
		getObjectLegalHoldFn = orig
	})
}

func patchPutObjectLegalHoldForTest(
	t *testing.T,
	fn func(*Handler, string, string, string, *backend.ObjectLockLegalHold) error,
) {
	t.Helper()
	orig := putObjectLegalHoldFn
	putObjectLegalHoldFn = fn
	t.Cleanup(func() {
		putObjectLegalHoldFn = orig
	})
}

func TestObjectLockInternalErrorBranchesWithHooks(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "hook-lock-errors")
	mustPutObject(t, b, "hook-lock-errors", "obj", "value")

	t.Run("get object lock configuration internal error", func(t *testing.T) {
		patchGetObjectLockConfigurationForTest(
			t,
			func(*Handler, string) (*backend.ObjectLockConfiguration, error) {
				return nil, errors.New("lock get boom")
			},
		)
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/hook-lock-errors?object-lock", "", nil),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("put object lock configuration internal error", func(t *testing.T) {
		patchPutObjectLockConfigurationForTest(
			t,
			func(*Handler, string, *backend.ObjectLockConfiguration) error {
				return errors.New("lock put boom")
			},
		)
		body := `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-lock-errors?object-lock",
				body,
				nil,
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("get retention internal error", func(t *testing.T) {
		patchGetObjectRetentionForTest(
			t,
			func(*Handler, string, string, string) (*backend.ObjectLockRetention, error) {
				return nil, errors.New("retention get boom")
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/hook-lock-errors/obj?retention",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("put retention internal error", func(t *testing.T) {
		patchPutObjectRetentionForTest(
			t,
			func(
				*Handler,
				string,
				string,
				string,
				*backend.ObjectLockRetention,
				bool,
			) error {
				return errors.New("retention put boom")
			},
		)
		body := `<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2099-01-01T00:00:00Z</RetainUntilDate></Retention>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-lock-errors/obj?retention",
				body,
				nil,
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("get legal hold internal error", func(t *testing.T) {
		patchGetObjectLegalHoldForTest(
			t,
			func(*Handler, string, string, string) (*backend.ObjectLockLegalHold, error) {
				return nil, errors.New("legalhold get boom")
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/hook-lock-errors/obj?legal-hold",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("put legal hold internal error", func(t *testing.T) {
		patchPutObjectLegalHoldForTest(
			t,
			func(*Handler, string, string, string, *backend.ObjectLockLegalHold) error {
				return errors.New("legalhold put boom")
			},
		)
		body := `<LegalHold><Status>ON</Status></LegalHold>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-lock-errors/obj?legal-hold",
				body,
				nil,
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})
}
