package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleObjectAnonymousPutWithoutPolicyIsDenied(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-private"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-private", "owner-access")
	h := New(b)

	req := httptest.NewRequest(
		http.MethodPut,
		"/bucket-private/obj",
		bytes.NewReader([]byte("data")),
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandleObjectAnonymousPutAllowedOnPublicWriteBucket(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-public-write"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.PutBucketACL("bucket-public-write", backend.CannedACLToPolicy("public-read-write")); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}
	h := New(b)

	req := httptest.NewRequest(
		http.MethodPut,
		"/bucket-public-write/obj",
		bytes.NewReader([]byte("data")),
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusOK)
	}
	if _, err := b.GetObject("bucket-public-write", "obj"); err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
}

func TestHandleObjectAnonymousGetRespectsObjectACL(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-acl"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-acl", "owner-access")
	if _, err := b.PutObject("bucket-acl", "obj", []byte("data"), backend.PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	h := New(b)

	t.Run("public-read object is readable anonymously", func(t *testing.T) {
		if err := b.PutObjectACL("bucket-acl", "obj", "", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/bucket-acl/obj", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("private object is not readable anonymously", func(t *testing.T) {
		if err := b.PutObjectACL("bucket-acl", "obj", "", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/bucket-acl/obj", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusForbidden)
		}
	})
}

func TestExtractAccessKey(t *testing.T) {
	t.Run("sigv4 header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/obj", nil)
		req.Header.Set(
			"Authorization",
			"AWS4-HMAC-SHA256 Credential=my-access/20260207/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
		)
		got := extractAccessKey(req)
		if got != "my-access" {
			t.Fatalf("unexpected access key: got %q, want %q", got, "my-access")
		}
	})

	t.Run("sigv2 header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/obj", nil)
		req.Header.Set("Authorization", "AWS my-access:signature")
		got := extractAccessKey(req)
		if got != "my-access" {
			t.Fatalf("unexpected access key: got %q, want %q", got, "my-access")
		}
	})

	t.Run("query x-amz-credential", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodGet,
			"/bucket/obj?X-Amz-Credential=query-access%2F20260207%2Fus-east-1%2Fs3%2Faws4_request",
			nil,
		)
		got := extractAccessKey(req)
		if got != "query-access" {
			t.Fatalf("unexpected access key: got %q, want %q", got, "query-access")
		}
	})

	t.Run("query awsaccesskeyid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/obj?AWSAccessKeyId=legacy-access", nil)
		got := extractAccessKey(req)
		if got != "legacy-access" {
			t.Fatalf("unexpected access key: got %q, want %q", got, "legacy-access")
		}
	})
}

func TestCheckAccessPolicyEvaluation(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("policy-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("policy-bucket", "owner-access")
	h := New(b)

	t.Run("no policy denies non-owner request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		if h.checkAccess(req, "policy-bucket", "s3:GetObject", "obj") {
			t.Fatal("expected non-owner access to be denied when no policy/ACL allows it")
		}
	})

	t.Run("no policy allows owner request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		req.Header.Set("Authorization", "AWS owner-access:sig")
		if !h.checkAccess(req, "policy-bucket", "s3:GetObject", "obj") {
			t.Fatal("expected owner access to be allowed when no explicit deny exists")
		}
	})

	t.Run("explicit deny blocks even owner", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`
		if err := b.PutBucketPolicy("policy-bucket", policy); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		req.Header.Set("Authorization", "AWS owner-access:sig")
		if h.checkAccess(req, "policy-bucket", "s3:GetObject", "obj") {
			t.Fatal("expected explicit deny to block owner")
		}
	})

	t.Run("allow permits non-owner", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-bucket/*"}]}`
		if err := b.PutBucketPolicy("policy-bucket", policy); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		req.Header.Set("Authorization", "AWS other-access:sig")
		if !h.checkAccess(req, "policy-bucket", "s3:GetObject", "obj") {
			t.Fatal("expected explicit allow to permit non-owner")
		}
	})
}

func TestCheckAccessWithContextUsesObjectTags(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("policy-context-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("policy-context-bucket", "owner-access")
	h := New(b)

	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-context-bucket/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/Project":"alpha"}}}]}`
	if err := b.PutBucketPolicy("policy-context-bucket", policy); err != nil {
		t.Fatalf("PutBucketPolicy failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/policy-context-bucket/obj", nil)
	req.Header.Set("Authorization", "AWS other-access:sig")

	allowed := h.checkAccessWithContext(
		req,
		"policy-context-bucket",
		"s3:GetObject",
		"obj",
		backend.PolicyEvalContext{
			ExistingObjectTags: map[string]string{"Project": "alpha"},
		},
	)
	if !allowed {
		t.Fatal("expected access to be allowed with matching existing object tag")
	}

	denied := h.checkAccessWithContext(
		req,
		"policy-context-bucket",
		"s3:GetObject",
		"obj",
		backend.PolicyEvalContext{
			ExistingObjectTags: map[string]string{"Project": "beta"},
		},
	)
	if denied {
		t.Fatal("expected access to be denied with non-matching existing object tag")
	}
}

func TestExtractPolicyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/bucket/obj", nil)
	req.Header.Set("x-amz-acl", "private")
	req.Header.Set("x-amz-copy-source", "/bucket/src")
	req.Header.Set("x-amz-metadata-directive", "REPLACE")
	req.Header.Set("Referer", "https://example.test/app")
	req.Header.Set("X-Ignored-Header", "ignored")

	headers := extractPolicyHeaders(req)
	if headers["x-amz-acl"] != "private" {
		t.Fatalf("unexpected x-amz-acl: %q", headers["x-amz-acl"])
	}
	if headers["x-amz-copy-source"] != "/bucket/src" {
		t.Fatalf("unexpected x-amz-copy-source: %q", headers["x-amz-copy-source"])
	}
	if headers["x-amz-metadata-directive"] != "REPLACE" {
		t.Fatalf("unexpected x-amz-metadata-directive: %q", headers["x-amz-metadata-directive"])
	}
	if headers["referer"] != "https://example.test/app" {
		t.Fatalf("unexpected referer: %q", headers["referer"])
	}
	if _, exists := headers["x-ignored-header"]; exists {
		t.Fatalf("unexpected ignored header presence: %#v", headers)
	}
}

func TestHandleRequestOptionsPreflightValidation(t *testing.T) {
	b := backend.New()
	h := New(b)

	tests := []struct {
		name   string
		header map[string]string
	}{
		{
			name:   "missing both origin and requested method",
			header: map[string]string{},
		},
		{
			name: "missing requested method",
			header: map[string]string{
				"Origin": "https://example.test",
			},
		},
		{
			name: "missing origin",
			header: map[string]string{
				"Access-Control-Request-Method": "GET",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/bucket/obj", nil)
			for k, v := range tt.header {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusBadRequest)
			}
		})
	}
}
