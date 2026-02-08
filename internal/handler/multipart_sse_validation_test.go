package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestValidateMultipartSSECustomerHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)

	if code, msg := validateMultipartSSECustomerHeaders(nil, req); code != "" || msg != "" {
		t.Fatalf("expected no error for nil upload, got code=%q msg=%q", code, msg)
	}

	upload := &backend.MultipartUpload{
		SSECustomerAlgorithm: "AES256",
		SSECustomerKeyMD5:    "abc",
	}

	t.Run("missing request headers", func(t *testing.T) {
		code, msg := validateMultipartSSECustomerHeaders(upload, req)
		if code != "InvalidArgument" || msg == "" {
			t.Fatalf("expected InvalidArgument for missing headers, got code=%q msg=%q", code, msg)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "aws:kms")
		req.Header.Set("x-amz-server-side-encryption-customer-key-md5", "abc")
		code, _ := validateMultipartSSECustomerHeaders(upload, req)
		if code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("key md5 mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		req.Header.Set("x-amz-server-side-encryption-customer-key-md5", "different")
		code, _ := validateMultipartSSECustomerHeaders(upload, req)
		if code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("success case-insensitive algorithm", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "aes256")
		req.Header.Set("x-amz-server-side-encryption-customer-key-md5", "abc")
		code, msg := validateMultipartSSECustomerHeaders(upload, req)
		if code != "" || msg != "" {
			t.Fatalf("expected success, got code=%q msg=%q", code, msg)
		}
	})
}

func TestValidateCopySourceSSECustomerHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)

	if code, msg := validateCopySourceSSECustomerHeaders(nil, req); code != "" || msg != "" {
		t.Fatalf("expected no error for nil source, got code=%q msg=%q", code, msg)
	}

	source := &backend.Object{
		SSECustomerAlgorithm: "AES256",
		SSECustomerKeyMD5:    "abc",
	}

	t.Run("missing request headers", func(t *testing.T) {
		code, msg := validateCopySourceSSECustomerHeaders(source, req)
		if code != "InvalidArgument" || msg == "" {
			t.Fatalf("expected InvalidArgument for missing headers, got code=%q msg=%q", code, msg)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "aws:kms")
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", "abc")
		code, _ := validateCopySourceSSECustomerHeaders(source, req)
		if code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("key md5 mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", "different")
		code, _ := validateCopySourceSSECustomerHeaders(source, req)
		if code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("success case-insensitive algorithm", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test", nil)
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "aes256")
		req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", "abc")
		code, msg := validateCopySourceSSECustomerHeaders(source, req)
		if code != "" || msg != "" {
			t.Fatalf("expected success, got code=%q msg=%q", code, msg)
		}
	})
}

func TestLoadCopySourceObjectForUploadPart(t *testing.T) {
	h, b := newTestHandler(t)

	obj, code, _, status := h.loadCopySourceObjectForUploadPart(nil)
	if obj != nil || code != "NoSuchKey" || status != http.StatusNotFound {
		t.Fatalf("unexpected nil source result: obj=%v code=%q status=%d", obj, code, status)
	}

	mustCreateBucket(t, b, "src-load")
	mustPutObject(t, b, "src-load", "k", "latest")

	obj, code, _, status = h.loadCopySourceObjectForUploadPart(&copySourceInfo{
		bucket: "missing-bucket",
		key:    "k",
	})
	if obj != nil || code != "NoSuchBucket" || status != http.StatusNotFound {
		t.Fatalf("unexpected missing bucket result: obj=%v code=%q status=%d", obj, code, status)
	}

	obj, code, _, status = h.loadCopySourceObjectForUploadPart(&copySourceInfo{
		bucket: "src-load",
		key:    "missing",
	})
	if obj != nil || code != "NoSuchKey" || status != http.StatusNotFound {
		t.Fatalf("unexpected missing key result: obj=%v code=%q status=%d", obj, code, status)
	}

	if err := b.SetBucketVersioning(
		"src-load",
		backend.VersioningEnabled,
		backend.MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	v1, err := b.PutObject("src-load", "ver", []byte("one"), backend.PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject v1 failed: %v", err)
	}
	if _, err := b.PutObject("src-load", "ver", []byte("two"), backend.PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject v2 failed: %v", err)
	}

	obj, code, _, status = h.loadCopySourceObjectForUploadPart(&copySourceInfo{
		bucket:    "src-load",
		key:       "ver",
		versionId: v1.VersionId,
	})
	if code != "" || status != 0 || obj == nil || obj.VersionId != v1.VersionId {
		t.Fatalf(
			"unexpected versioned lookup result: obj=%+v code=%q status=%d",
			obj,
			code,
			status,
		)
	}

	obj, code, _, status = h.loadCopySourceObjectForUploadPart(&copySourceInfo{
		bucket:    "src-load",
		key:       "ver",
		versionId: "missing-version",
	})
	if obj != nil || code != "NoSuchVersion" || status != http.StatusNotFound {
		t.Fatalf("unexpected missing version result: obj=%v code=%q status=%d", obj, code, status)
	}

	obj, code, _, status = h.loadCopySourceObjectForUploadPart(&copySourceInfo{
		bucket:    "src-load",
		key:       "missing-version-key",
		versionId: "v1",
	})
	if obj != nil || code != "NoSuchKey" || status != http.StatusNotFound {
		t.Fatalf(
			"unexpected missing version key result: obj=%v code=%q status=%d",
			obj,
			code,
			status,
		)
	}
}

func TestHandleCompleteMultipartUploadRejectsMissingSSECHeaders(t *testing.T) {
	h, b := newTestHandler(t)
	mustPublicWriteBucket(t, b, "complete-ssec", "minis3-access-key")

	uploadID := createMultipartUpload(
		t,
		h,
		"complete-ssec",
		"obj",
		map[string]string{
			"Authorization": authHeader("minis3-access-key"),
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
			"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
		},
	)

	w := doRequest(
		h,
		newRequest(
			http.MethodPost,
			"http://example.test/complete-ssec/obj?uploadId="+uploadID,
			`<CompleteMultipartUpload></CompleteMultipartUpload>`,
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidArgument")
}
