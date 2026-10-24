package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func patchGetObjectLockConfigurationForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string) (*backend.ObjectLockConfiguration, error),
) {
	t.Helper()
	orig := h.hooks.getObjectLockConfiguration
	h.hooks.getObjectLockConfiguration = fn
	t.Cleanup(func() {
		h.hooks.getObjectLockConfiguration = orig
	})
}

func patchPutObjectLockConfigurationForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string, *backend.ObjectLockConfiguration) error,
) {
	t.Helper()
	orig := h.hooks.putObjectLockConfiguration
	h.hooks.putObjectLockConfiguration = fn
	t.Cleanup(func() {
		h.hooks.putObjectLockConfiguration = orig
	})
}

func patchGetObjectRetentionForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string, string, string) (*backend.ObjectLockRetention, error),
) {
	t.Helper()
	orig := h.hooks.getObjectRetention
	h.hooks.getObjectRetention = fn
	t.Cleanup(func() {
		h.hooks.getObjectRetention = orig
	})
}

func patchPutObjectRetentionForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string, string, string, *backend.ObjectLockRetention, bool) error,
) {
	t.Helper()
	orig := h.hooks.putObjectRetention
	h.hooks.putObjectRetention = fn
	t.Cleanup(func() {
		h.hooks.putObjectRetention = orig
	})
}

func patchGetObjectLegalHoldForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string, string, string) (*backend.ObjectLockLegalHold, error),
) {
	t.Helper()
	orig := h.hooks.getObjectLegalHold
	h.hooks.getObjectLegalHold = fn
	t.Cleanup(func() {
		h.hooks.getObjectLegalHold = orig
	})
}

func patchPutObjectLegalHoldForTest(
	t *testing.T,
	h *Handler,
	fn func(*Handler, string, string, string, *backend.ObjectLockLegalHold) error,
) {
	t.Helper()
	orig := h.hooks.putObjectLegalHold
	h.hooks.putObjectLegalHold = fn
	t.Cleanup(func() {
		h.hooks.putObjectLegalHold = orig
	})
}

func TestObjectLockInternalErrorBranchesWithHooks(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "hook-lock-errors")
	mustPutObject(t, b, "hook-lock-errors", "obj", "value")

	t.Run("get object lock configuration internal error", func(t *testing.T) {
		patchGetObjectLockConfigurationForTest(t, h,
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
		patchPutObjectLockConfigurationForTest(t, h,
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
		patchGetObjectRetentionForTest(t, h,
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
		patchPutObjectRetentionForTest(t, h,
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
		patchGetObjectLegalHoldForTest(t, h,
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
		patchPutObjectLegalHoldForTest(t, h,
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
