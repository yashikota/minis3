package handler

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("forced read error")
}

func TestHandleObjectQueryMethodNotAllowedBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-query-branches")
	mustPutObject(t, b, "obj-query-branches", "k", "v")

	tests := []struct {
		name   string
		method string
		target string
	}{
		{
			name:   "tagging method not allowed",
			method: http.MethodPatch,
			target: "http://example.test/obj-query-branches/k?tagging",
		},
		{
			name:   "acl method not allowed",
			method: http.MethodDelete,
			target: "http://example.test/obj-query-branches/k?acl",
		},
		{
			name:   "retention method not allowed",
			method: http.MethodPost,
			target: "http://example.test/obj-query-branches/k?retention",
		},
		{
			name:   "legal hold method not allowed",
			method: http.MethodDelete,
			target: "http://example.test/obj-query-branches/k?legal-hold",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doRequest(h, newRequest(tc.method, tc.target, "", nil))
			requireStatus(t, w, http.StatusMethodNotAllowed)
			requireS3ErrorCode(t, w, "MethodNotAllowed")
		})
	}
}

func TestHandleObjectPutAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "put-branches")

	t.Run("body read error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test/put-branches/k", nil)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("invalid sse header", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/put-branches/invalid-sse",
				"data",
				map[string]string{"x-amz-server-side-encryption": "not-valid"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("missing bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/missing-put-bucket/k", "data", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("object lock invalid request without lock bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/put-branches/lock",
				"data",
				map[string]string{
					"x-amz-object-lock-mode": backend.RetentionModeGovernance,
					"x-amz-object-lock-retain-until-date": time.Now().
						UTC().
						Add(24 * time.Hour).
						Format(time.RFC3339),
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("block public acl canned", func(t *testing.T) {
		if err := b.PutPublicAccessBlock(
			"put-branches",
			&backend.PublicAccessBlockConfiguration{BlockPublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/put-branches/public-acl",
				"data",
				map[string]string{"x-amz-acl": "public-read"},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("versioned kms and trailer checksum", func(t *testing.T) {
		if err := b.SetBucketVersioning("put-branches", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/put-branches/kms",
				"data",
				map[string]string{
					"x-amz-server-side-encryption":                "aws:kms",
					"x-amz-server-side-encryption-aws-kms-key-id": "kms-key-1",
					"x-amz-trailer":                               "x-amz-checksum-crc32c",
					"x-amz-website-redirect-location":             "/landing.html",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("expected x-amz-version-id to be set for versioned bucket")
		}
		if got := w.Header().Get("x-amz-server-side-encryption"); got != "aws:kms" {
			t.Fatalf("unexpected sse header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"); got != "kms-key-1" {
			t.Fatalf("unexpected kms key id header: %q", got)
		}
	})
}

func TestHandleObjectSSECAndPartBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-ssec")

	keyRaw := []byte("0123456789abcdef0123456789abcdef")
	keyB64 := base64.StdEncoding.EncodeToString(keyRaw)
	md := md5.Sum(keyRaw)
	md5B64 := base64.StdEncoding.EncodeToString(md[:])

	putHeaders := map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       keyB64,
		"x-amz-server-side-encryption-customer-key-md5":   md5B64,
	}
	wPut := doRequest(
		h,
		newRequest(http.MethodPut, "http://example.test/obj-ssec/key", "abcd", putHeaders),
	)
	requireStatus(t, wPut, http.StatusOK)

	obj, err := b.GetObject("obj-ssec", "key")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	obj.Parts = []backend.ObjectPart{
		{PartNumber: 1, Size: 2, ETag: "\"p1\""},
		{PartNumber: 2, Size: 2, ETag: "\"p2\""},
	}

	t.Run("get missing sse-c headers", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj-ssec/key", "", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	ssecReqHeaders := map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key-md5":   md5B64,
	}

	t.Run("get wrong sse-c md5", func(t *testing.T) {
		headers := map[string]string{
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key-md5":   "wrong",
		}
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-ssec/key", "", headers),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("get conditional precondition failed", func(t *testing.T) {
		headers := map[string]string{
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key-md5":   md5B64,
			"If-Match": "\"other\"",
		}
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-ssec/key", "", headers),
		)
		requireStatus(t, w, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, w, "PreconditionFailed")
	})

	t.Run("get part number valid and invalid", func(t *testing.T) {
		w1 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-ssec/key?partNumber=1",
				"",
				ssecReqHeaders,
			),
		)
		requireStatus(t, w1, http.StatusPartialContent)
		if got := w1.Body.String(); got != "ab" {
			t.Fatalf("unexpected part body: %q", got)
		}

		w2 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-ssec/key?partNumber=9",
				"",
				ssecReqHeaders,
			),
		)
		requireStatus(t, w2, http.StatusBadRequest)
		requireS3ErrorCode(t, w2, "InvalidPart")
	})

	t.Run("head branch variants", func(t *testing.T) {
		wMissingHeaders := doRequest(
			h,
			newRequest(http.MethodHead, "http://example.test/obj-ssec/key", "", nil),
		)
		requireStatus(t, wMissingHeaders, http.StatusBadRequest)
		requireS3ErrorCode(t, wMissingHeaders, "InvalidRequest")

		wCond := doRequest(
			h,
			newRequest(
				http.MethodHead,
				"http://example.test/obj-ssec/key",
				"",
				map[string]string{
					"x-amz-server-side-encryption-customer-algorithm": "AES256",
					"x-amz-server-side-encryption-customer-key-md5":   md5B64,
					"If-Match": "\"other\"",
				},
			),
		)
		requireStatus(t, wCond, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, wCond, "PreconditionFailed")

		wPart := doRequest(
			h,
			newRequest(
				http.MethodHead,
				"http://example.test/obj-ssec/key?partNumber=2",
				"",
				ssecReqHeaders,
			),
		)
		requireStatus(t, wPart, http.StatusPartialContent)
		if got := wPart.Header().Get("Content-Length"); got != "2" {
			t.Fatalf("unexpected part content length: %q", got)
		}

		wMissingVersion := doRequest(
			h,
			newRequest(
				http.MethodHead,
				"http://example.test/obj-ssec/key?versionId=missing",
				"",
				nil,
			),
		)
		requireStatus(t, wMissingVersion, http.StatusNotFound)
	})
}

func TestHandleObjectDeleteAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "delete-branches")
	if err := b.SetBucketVersioning("delete-branches", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	mustPutObject(t, b, "delete-branches", "k", "data")

	obj, err := b.GetObject("delete-branches", "k")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}

	t.Run("delete specific version success and not found", func(t *testing.T) {
		wSuccess := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/delete-branches/k?versionId="+obj.VersionId,
				"",
				nil,
			),
		)
		requireStatus(t, wSuccess, http.StatusNoContent)
		if got := wSuccess.Header().Get("x-amz-version-id"); got != obj.VersionId {
			t.Fatalf("unexpected deleted version header: %q", got)
		}

		wMissing := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/delete-branches/k?versionId=missing",
				"",
				nil,
			),
		)
		requireStatus(t, wMissing, http.StatusNoContent)
	})

	t.Run("delete creates delete marker headers", func(t *testing.T) {
		mustPutObject(t, b, "delete-branches", "dm", "data")
		w := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/delete-branches/dm", "", nil),
		)
		requireStatus(t, w, http.StatusNoContent)
		if got := w.Header().Get("x-amz-delete-marker"); got != "true" {
			t.Fatalf("unexpected delete marker header: %q", got)
		}
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("expected x-amz-version-id for delete marker")
		}
	})

	t.Run("delete locked object version", func(t *testing.T) {
		mustCreateObjectLockBucket(t, b, "lock-delete-branches")
		if err := b.SetBucketVersioning("lock-delete-branches", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		retain := time.Now().UTC().Add(24 * time.Hour)
		lockedObj, err := b.PutObject(
			"lock-delete-branches",
			"locked",
			[]byte("data"),
			backend.PutObjectOptions{
				RetentionMode:   backend.RetentionModeCompliance,
				RetainUntilDate: &retain,
			},
		)
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/lock-delete-branches/locked?versionId="+lockedObj.VersionId,
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})
}

func TestPutObjectRetainUntilDateTruncatesFractionalSeconds(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-retain-truncate")

	retainUntil := time.Now().UTC().Add(30 * time.Second).Add(789 * time.Millisecond)
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/lock-retain-truncate/key",
			"data",
			map[string]string{
				"x-amz-object-lock-mode":              backend.RetentionModeGovernance,
				"x-amz-object-lock-retain-until-date": retainUntil.Format(time.RFC3339Nano),
			},
		),
	)
	requireStatus(t, w, http.StatusOK)

	obj, err := b.GetObject("lock-retain-truncate", "key")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if obj.RetainUntilDate == nil {
		t.Fatal("expected RetainUntilDate to be set")
	}
	if obj.RetainUntilDate.Nanosecond() != 0 {
		t.Fatalf(
			"expected retain-until date to be second-precision, got %v",
			obj.RetainUntilDate,
		)
	}
}
