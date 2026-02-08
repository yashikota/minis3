package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestUploadPartSSEResponseHeaderBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustPublicWriteBucket(t, b, "mp-sse", "minis3-access-key")

	t.Run("upload part echoes sse-kms headers", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-sse",
			"kms",
			map[string]string{
				"Authorization":                               authHeader("minis3-access-key"),
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "kms-key-1",
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-sse/kms?uploadId=%s&partNumber=1", uploadID),
				"part-data",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-server-side-encryption"); got != "aws:kms" {
			t.Fatalf("unexpected sse header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"); got != "kms-key-1" {
			t.Fatalf("unexpected kms key header: %q", got)
		}
	})

	t.Run("upload part echoes sse-c headers", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": authHeader("minis3-access-key"),
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
			"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
		}
		uploadID := createMultipartUpload(t, h, "mp-sse", "ssec", headers)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-sse/ssec?uploadId=%s&partNumber=1", uploadID),
				"part-data",
				headers,
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-server-side-encryption-customer-algorithm"); got != "AES256" {
			t.Fatalf("unexpected sse-c algorithm header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption-customer-key-md5"); got != "Xr4ilOzQ4PCOq3aQ0qbuaQ==" {
			t.Fatalf("unexpected sse-c md5 header: %q", got)
		}
	})
}

func TestCompleteMultipartUploadAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustPublicWriteBucket(t, b, "mp-complete", "minis3-access-key")
	if err := b.SetBucketVersioning("mp-complete", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	t.Run("read body error", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"http://example.test/mp-complete/k?uploadId=u",
			nil,
		)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("no such upload", func(t *testing.T) {
		body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"e"</ETag></Part></CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-complete/k?uploadId=missing",
				body,
				nil,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("bucket not found while upload exists", func(t *testing.T) {
		mustPublicWriteBucket(t, b, "mp-gone", "minis3-access-key")
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-gone",
			"gone",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		if err := b.DeleteBucket("mp-gone"); err != nil {
			t.Fatalf("DeleteBucket failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-gone/gone?uploadId=%s", uploadID),
				`<CompleteMultipartUpload></CompleteMultipartUpload>`,
				nil,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("invalid request when object lock fields on non-lock bucket", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-complete",
			"lock-missing",
			map[string]string{
				"Authorization":          authHeader("minis3-access-key"),
				"x-amz-object-lock-mode": backend.RetentionModeGovernance,
				"x-amz-object-lock-retain-until-date": time.Now().
					UTC().
					Add(24 * time.Hour).
					Format(time.RFC3339),
			},
		)
		wPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-complete/lock-missing?uploadId=%s&partNumber=1",
					uploadID,
				),
				"single",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart, http.StatusOK)
		etag := wPart.Header().Get("ETag")

		complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + etag + `</ETag></Part></CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf(
					"http://example.test/mp-complete/lock-missing?uploadId=%s",
					uploadID,
				),
				complete,
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("success sets version id header", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-complete",
			"ok-versioned",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		wPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-complete/ok-versioned?uploadId=%s&partNumber=1",
					uploadID,
				),
				"single",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart, http.StatusOK)
		etag := wPart.Header().Get("ETag")

		complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + etag + `</ETag></Part></CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf(
					"http://example.test/mp-complete/ok-versioned?uploadId=%s",
					uploadID,
				),
				complete,
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("expected x-amz-version-id on successful complete multipart upload")
		}
	})
}

func TestUploadPartCopyAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-copy-branch")
	mustPutObject(t, b, "src-copy-branch", "src", "source-data")
	mustPublicWriteBucket(t, b, "dst-copy-branch", "dst-owner")

	t.Run("source access denied", func(t *testing.T) {
		b.SetBucketOwner("src-copy-branch", "src-owner")
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-copy-branch",
			"deny",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/dst-copy-branch/deny?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{"x-amz-copy-source": "/src-copy-branch/src"},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("no such upload", func(t *testing.T) {
		if err := b.PutObjectACL(
			"src-copy-branch",
			"src",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-copy-branch/no-upload?uploadId=missing&partNumber=1",
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-copy-branch/src",
					"x-amz-server-side-encryption-customer-algorithm": "AES256",
					"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
					"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("source bucket not found", func(t *testing.T) {
		if err := b.PutObjectACL(
			"src-copy-branch",
			"src",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-copy-branch",
			"missing-src-bucket",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/dst-copy-branch/missing-src-bucket?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/no-such-src/key",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("success echoes sse-kms headers", func(t *testing.T) {
		if err := b.PutObjectACL(
			"src-copy-branch",
			"src",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-copy-branch",
			"kms-copy",
			map[string]string{
				"Authorization":                               authHeader("dst-owner"),
				"x-amz-server-side-encryption":                "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id": "kms-key-1",
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/dst-copy-branch/kms-copy?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-copy-branch/src",
					"x-amz-server-side-encryption-customer-algorithm": "AES256",
					"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
					"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-server-side-encryption"); got != "aws:kms" {
			t.Fatalf("unexpected sse header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"); got != "kms-key-1" {
			t.Fatalf("unexpected kms key id header: %q", got)
		}
	})

	t.Run("success echoes sse-c headers", func(t *testing.T) {
		if err := b.PutObjectACL(
			"src-copy-branch",
			"src",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-copy-branch",
			"ssec-copy",
			map[string]string{
				"Authorization": authHeader("dst-owner"),
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
				"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
			},
		)
		if upload, ok := b.GetUpload(uploadID); !ok ||
			upload.SSECustomerKeyMD5 != "Xr4ilOzQ4PCOq3aQ0qbuaQ==" {
			t.Fatalf(
				"unexpected upload sse-c state: ok=%v algo=%q md5=%q",
				ok,
				upload.SSECustomerAlgorithm,
				upload.SSECustomerKeyMD5,
			)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/dst-copy-branch/ssec-copy?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-copy-branch/src",
					"x-amz-server-side-encryption-customer-algorithm": "AES256",
					"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
					"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-server-side-encryption-customer-algorithm"); got != "AES256" {
			t.Fatalf("unexpected sse-c algorithm header: %q", got)
		}
		if got := w.Header().Get("x-amz-server-side-encryption-customer-key-md5"); got != "Xr4ilOzQ4PCOq3aQ0qbuaQ==" {
			t.Fatalf("unexpected sse-c md5 header: %q", got)
		}
	})
}
