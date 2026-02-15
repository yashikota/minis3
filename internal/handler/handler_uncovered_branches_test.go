package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func patchVerifyPresignedURLForTest(t *testing.T, fn func(*http.Request) error) {
	t.Helper()
	orig := verifyPresignedURLFn
	verifyPresignedURLFn = fn
	t.Cleanup(func() {
		verifyPresignedURLFn = orig
	})
}

func patchVerifyAuthorizationHeaderForTest(t *testing.T, fn func(*http.Request) error) {
	t.Helper()
	orig := verifyAuthorizationHeaderFn
	verifyAuthorizationHeaderFn = fn
	t.Cleanup(func() {
		verifyAuthorizationHeaderFn = orig
	})
}

func patchBucketACLForAccessCheckForTest(
	t *testing.T,
	fn func(*Handler, string) (*backend.AccessControlPolicy, error),
) {
	t.Helper()
	orig := getBucketACLForAccessCheckFn
	getBucketACLForAccessCheckFn = fn
	t.Cleanup(func() {
		getBucketACLForAccessCheckFn = orig
	})
}

func patchObjectACLForAccessCheckForTest(
	t *testing.T,
	fn func(*Handler, string, string, string) (*backend.AccessControlPolicy, error),
) {
	t.Helper()
	orig := getObjectACLForAccessCheckFn
	getObjectACLForAccessCheckFn = fn
	t.Cleanup(func() {
		getObjectACLForAccessCheckFn = orig
	})
}

func TestHandleRequestAuthAndCORSBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "req-branch")

	if err := b.PutBucketCORS("req-branch", &backend.CORSConfiguration{
		CORSRules: []backend.CORSRule{{
			AllowedMethods: []string{"GET"},
			AllowedOrigins: []string{"*"},
		}},
	}); err != nil {
		t.Fatalf("PutBucketCORS failed: %v", err)
	}

	t.Run("preflight to root path is forbidden", func(t *testing.T) {
		req := newRequest(
			http.MethodOptions,
			"http://example.test/",
			"",
			map[string]string{
				"Origin":                        "https://example.test",
				"Access-Control-Request-Method": "GET",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
	})

	t.Run("presigned verification returns presigned error", func(t *testing.T) {
		patchVerifyPresignedURLForTest(t, func(*http.Request) error {
			return &presignedError{
				code:    "SignatureDoesNotMatch",
				message: "signature mismatch",
			}
		})
		req := newRequest(
			http.MethodGet,
			"http://example.test/req-branch?X-Amz-Signature=x",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "SignatureDoesNotMatch")
	})

	t.Run("presigned verification returns generic error", func(t *testing.T) {
		patchVerifyPresignedURLForTest(t, func(*http.Request) error {
			return errors.New("presigned boom")
		})
		req := newRequest(
			http.MethodGet,
			"http://example.test/req-branch?X-Amz-Signature=x",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("authorization verification returns presigned error", func(t *testing.T) {
		patchVerifyAuthorizationHeaderForTest(t, func(*http.Request) error {
			return &presignedError{
				code:    "InvalidAccessKeyId",
				message: "missing key",
			}
		})
		req := newRequest(http.MethodGet, "http://example.test/req-branch", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidAccessKeyId")
	})

	t.Run("authorization verification returns generic error", func(t *testing.T) {
		patchVerifyAuthorizationHeaderForTest(t, func(*http.Request) error {
			return errors.New("auth boom")
		})
		req := newRequest(http.MethodGet, "http://example.test/req-branch", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run(
		"origin without access-control-request-method falls back to request method",
		func(t *testing.T) {
			req := newRequest(
				http.MethodGet,
				"http://example.test/req-branch",
				"",
				map[string]string{"Origin": "https://example.test"},
			)
			w := doRequest(h, req)
			requireStatus(t, w, http.StatusOK)
			if got := w.Header().Get("access-control-allow-origin"); got != "*" {
				t.Fatalf("access-control-allow-origin = %q, want *", got)
			}
		},
	)
}

func TestExtractAccessKeyAdditionalBranches(t *testing.T) {
	reqV4NoCredential := httptest.NewRequest(http.MethodGet, "/", nil)
	reqV4NoCredential.Header.Set("Authorization", "AWS4-HMAC-SHA256 SignedHeaders=host")
	if got := extractAccessKey(reqV4NoCredential); got != "" {
		t.Fatalf("extractAccessKey(V4 without Credential) = %q, want empty", got)
	}

	reqUnknownScheme := httptest.NewRequest(http.MethodGet, "/", nil)
	reqUnknownScheme.Header.Set("Authorization", "Bearer token")
	if got := extractAccessKey(reqUnknownScheme); got != "" {
		t.Fatalf("extractAccessKey(unknown scheme) = %q, want empty", got)
	}
}

func TestCheckAccessErrorBranchesWithHooks(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "acl-branch")
	b.SetBucketOwner("acl-branch", "owner-ak")
	mustPutObject(t, b, "acl-branch", "k", "v")

	req := httptest.NewRequest(http.MethodGet, "/acl-branch/k", nil)
	req.Header.Set("Authorization", authHeader("other-ak"))

	t.Run("bucket acl lookups return errors", func(t *testing.T) {
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl boom")
			},
		)

		actions := []string{
			"s3:ListBucket",
			"s3:PutObject",
			"s3:GetBucketAcl",
			"s3:PutBucketAcl",
		}
		for _, action := range actions {
			if h.checkAccess(req, "acl-branch", action, "k") {
				t.Fatalf("checkAccess should deny on bucket ACL error for action %s", action)
			}
		}
	})

	t.Run("object acl lookups return errors", func(t *testing.T) {
		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("object acl boom")
			},
		)

		actions := []string{"s3:GetObjectAcl", "s3:PutObjectAcl", "s3:GetObject"}
		for _, action := range actions {
			if h.checkAccess(req, "acl-branch", action, "k") {
				t.Fatalf("checkAccess should deny on object ACL error for action %s", action)
			}
		}
	})

	t.Run("object acl action with empty key is denied", func(t *testing.T) {
		if h.checkAccess(req, "acl-branch", "s3:GetObjectAcl", "") {
			t.Fatal("s3:GetObjectAcl with empty key must be denied")
		}
		if h.checkAccess(req, "acl-branch", "s3:PutObjectAcl", "") {
			t.Fatal("s3:PutObjectAcl with empty key must be denied")
		}
	})

	t.Run("missing object fallback fails when bucket acl lookup fails", func(t *testing.T) {
		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl fallback boom")
			},
		)

		if h.checkAccess(req, "acl-branch", "s3:GetObject", "missing") {
			t.Fatal("fallback bucket ACL error should deny access")
		}
	})
}

func TestACLAndGrantHelperEdgeBranches(t *testing.T) {
	aclWithNilGrantee := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{
			Grants: []backend.Grant{{
				Grantee:    nil,
				Permission: backend.PermissionRead,
			}},
		},
	}
	if isPublicACL(aclWithNilGrantee) {
		t.Fatal("ACL with nil grantee should not be public")
	}

	if aclAllowsRead(nil, "", true) {
		t.Fatal("nil ACL must not allow read")
	}
	if aclAllowsWrite(nil, "", true) {
		t.Fatal("nil ACL must not allow write")
	}
	if aclAllowsACP(nil, "", true, backend.PermissionReadACP) {
		t.Fatal("nil ACL must not allow ACP")
	}

	if err := normalizeAndValidateACL(nil); err != nil {
		t.Fatalf("normalizeAndValidateACL(nil) error = %+v, want nil", err)
	}

	aclNilGrant := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{
			Grants: []backend.Grant{{
				Grantee:    nil,
				Permission: backend.PermissionRead,
			}},
		},
	}
	if err := normalizeAndValidateACL(aclNilGrant); err != nil {
		t.Fatalf("normalizeAndValidateACL with nil grant error = %+v, want nil", err)
	}

	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
		return
	}

	reqWithEmptyPart := newRequest(
		http.MethodPut,
		"http://example.test/acl-branch",
		"",
		map[string]string{
			"x-amz-grant-read": " , id=" + owner.ID,
		},
	)
	aclFromEmptyPart, err := aclFromGrantHeaders(reqWithEmptyPart, owner)
	if err != nil {
		t.Fatalf("aclFromGrantHeaders with empty part failed: %+v", err)
	}
	if aclFromEmptyPart == nil || len(aclFromEmptyPart.AccessControlList.Grants) != 1 {
		t.Fatalf("unexpected ACL from empty part case: %+v", aclFromEmptyPart)
	}

	reqEmptyValue := newRequest(
		http.MethodPut,
		"http://example.test/acl-branch",
		"",
		map[string]string{"x-amz-grant-read": `id=""`},
	)
	if _, err := aclFromGrantHeaders(reqEmptyValue, owner); err == nil ||
		err.code != "InvalidArgument" {
		t.Fatalf("empty grant value should fail with InvalidArgument, got %+v", err)
	}

	reqUnknownGrantKey := newRequest(
		http.MethodPut,
		"http://example.test/acl-branch",
		"",
		map[string]string{"x-amz-grant-read": "foo=bar"},
	)
	if _, err := aclFromGrantHeaders(reqUnknownGrantKey, owner); err == nil ||
		err.code != "InvalidArgument" {
		t.Fatalf("unknown grant key should fail with InvalidArgument, got %+v", err)
	}

	reqNormalizeError := newRequest(
		http.MethodPut,
		"http://example.test/acl-branch",
		"",
		map[string]string{"x-amz-grant-read": "id=unknown-canonical-id"},
	)
	if _, err := aclFromGrantHeaders(reqNormalizeError, owner); err == nil ||
		err.code != "InvalidArgument" {
		t.Fatalf("normalize error should propagate InvalidArgument, got %+v", err)
	}
}

func TestCORSHelperEdgeBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "cors-branch")

	if ok := h.setCORSHeadersForRequest(httptest.NewRecorder(), "", "", "", ""); ok {
		t.Fatal("setCORSHeadersForRequest should fail for empty parameters")
	}

	if err := b.PutBucketCORS("cors-branch", &backend.CORSConfiguration{
		CORSRules: []backend.CORSRule{{
			AllowedMethods: []string{"GET"},
			AllowedOrigins: []string{"https://allowed.example.test"},
			AllowedHeaders: []string{"x-amz-meta-*"},
		}},
	}); err != nil {
		t.Fatalf("PutBucketCORS failed: %v", err)
	}

	if ok := h.setCORSHeadersForRequest(
		httptest.NewRecorder(),
		"cors-branch",
		"https://allowed.example.test",
		"POST",
		"",
	); ok {
		t.Fatal("setCORSHeadersForRequest should reject method mismatch")
	}

	if ok := h.setCORSHeadersForRequest(
		httptest.NewRecorder(),
		"cors-branch",
		"https://denied.example.test",
		"GET",
		"",
	); ok {
		t.Fatal("setCORSHeadersForRequest should reject origin mismatch")
	}

	if corsHeaderMatch("", "x-amz-meta-k") {
		t.Fatal("corsHeaderMatch must reject empty pattern")
	}
	if corsHeaderMatch("*", "") {
		t.Fatal("corsHeaderMatch must reject empty header")
	}
}
