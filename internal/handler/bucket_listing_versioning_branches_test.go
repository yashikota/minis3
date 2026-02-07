package handler

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestBucketCreateAndListingAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)

	t.Run("create bucket body read error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test/read-error-bucket", nil)
		req.Body = io.NopCloser(failingReader{})
		req.ContentLength = 1
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("list v1 and v2 access denied for non-owner", func(t *testing.T) {
		mustCreateBucket(t, b, "list-denied-branch")
		b.SetBucketOwner("list-denied-branch", "owner-ak")

		wV2 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-denied-branch?list-type=2",
				"",
				nil,
			),
		)
		requireStatus(t, wV2, http.StatusForbidden)
		requireS3ErrorCode(t, wV2, "AccessDenied")

		wV1 := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/list-denied-branch", "", nil),
		)
		requireStatus(t, wV1, http.StatusForbidden)
		requireS3ErrorCode(t, wV1, "AccessDenied")
	})

	t.Run("list v1 common prefixes with url encoding", func(t *testing.T) {
		mustCreateBucket(t, b, "list-cp-branch")
		b.SetBucketOwner("list-cp-branch", "owner-ak")
		mustPutObject(t, b, "list-cp-branch", "dir one/a.txt", "a")
		mustPutObject(t, b, "list-cp-branch", "dir one/b.txt", "b")

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-cp-branch?delimiter=/&encoding-type=url",
				"",
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, w, http.StatusOK)

		var resp backend.ListBucketV1Result
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse ListBucketV1Result: %v body=%s", err, w.Body.String())
		}
		if len(resp.CommonPrefixes) != 1 || resp.CommonPrefixes[0].Prefix != "dir%20one/" {
			t.Fatalf("unexpected common prefixes: %+v", resp.CommonPrefixes)
		}
	})
}

func TestBucketVersioningAndListVersionsAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "versioning-branch")
	b.SetBucketOwner("versioning-branch", "owner-ak")

	t.Run("put bucket versioning read error", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/versioning-branch?versioning",
			nil,
		)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("get bucket versioning includes MFA delete when enabled", func(t *testing.T) {
		if err := b.SetBucketVersioning("versioning-branch", backend.VersioningEnabled, backend.MFADeleteEnabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/versioning-branch?versioning", "", nil),
		)
		requireStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<MfaDelete>Enabled</MfaDelete>") {
			t.Fatalf("expected MfaDelete in response, got body=%s", w.Body.String())
		}
	})

	t.Run("list object versions common prefixes with url encoding", func(t *testing.T) {
		if err := b.SetBucketVersioning("versioning-branch", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "versioning-branch", "vdir one/a.txt", "a")
		mustPutObject(t, b, "versioning-branch", "vdir one/b.txt", "b")

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/versioning-branch?versions&delimiter=/&encoding-type=url",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)

		var resp backend.ListVersionsResult
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse ListVersionsResult: %v body=%s", err, w.Body.String())
		}
		if len(resp.CommonPrefixes) != 1 || resp.CommonPrefixes[0].Prefix != "vdir%20one/" {
			t.Fatalf("unexpected common prefixes: %+v", resp.CommonPrefixes)
		}
	})
}
