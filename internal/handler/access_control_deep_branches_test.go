package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestACLHelpersAdditionalBranches(t *testing.T) {
	acl := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{
			Grants: []backend.Grant{
				{
					Grantee:    nil,
					Permission: backend.PermissionRead,
				},
				{
					Grantee:    &backend.Grantee{URI: backend.AuthenticatedUsersURI},
					Permission: backend.PermissionWrite,
				},
				{
					Grantee:    &backend.Grantee{URI: backend.AuthenticatedUsersURI},
					Permission: backend.PermissionRead,
				},
			},
		},
	}

	if aclAllowsRead(acl, "", true) {
		t.Fatal("authenticated-users read grant should not allow anonymous requests")
	}
	if !aclAllowsRead(acl, "", false) {
		t.Fatal("authenticated-users read grant should allow authenticated requests")
	}

	writeACL := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{
			Grants: []backend.Grant{
				{
					Grantee:    nil,
					Permission: backend.PermissionWrite,
				},
				{
					Grantee:    &backend.Grantee{URI: backend.AllUsersURI},
					Permission: backend.PermissionWrite,
				},
			},
		},
	}
	if !aclAllowsWrite(writeACL, "", true) {
		t.Fatal("all-users write grant should allow anonymous write")
	}
}

func TestCheckAccessAdditionalBranches(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("access-branch"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("access-branch", "owner-ak")
	if _, err := b.PutObject("access-branch", "obj", []byte("data"), backend.PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	h := New(b)

	t.Run("missing bucket is allowed by checkAccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/no-such/key", nil)
		if !h.checkAccess(req, "no-such", "s3:GetObject", "key") {
			t.Fatal("checkAccess should allow when bucket does not exist")
		}
	})

	t.Run("restrict public buckets blocks non-owner even with public policy", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":"*","Resource":"arn:aws:s3:::access-branch/*"}]}`
		if err := b.PutBucketPolicy("access-branch", policy); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
		if err := b.PutPublicAccessBlock(
			"access-branch",
			&backend.PublicAccessBlockConfiguration{RestrictPublicBuckets: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/access-branch/obj", nil)
		req.Header.Set("Authorization", authHeader("other-ak"))
		if h.checkAccess(req, "access-branch", "s3:GetObject", "obj") {
			t.Fatal("non-owner should be blocked by RestrictPublicBuckets")
		}
	})

	t.Run("ignore public acls disables ACL fallback", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-branch"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		if err := b.PutBucketACL("access-branch", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		if err := b.PutPublicAccessBlock(
			"access-branch",
			&backend.PublicAccessBlockConfiguration{IgnorePublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/access-branch", nil)
		if h.checkAccess(req, "access-branch", "s3:ListBucket", "") {
			t.Fatal("ACL fallback should be disabled when IgnorePublicAcls=true")
		}

		if err := b.PutPublicAccessBlock(
			"access-branch",
			&backend.PublicAccessBlockConfiguration{IgnorePublicAcls: false},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		if !h.checkAccess(req, "access-branch", "s3:ListBucket", "") {
			t.Fatal(
				"public-read bucket ACL should allow anonymous list when ACL fallback is enabled",
			)
		}
	})

	t.Run("get object action with empty key is denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/access-branch", nil)
		if h.checkAccess(req, "access-branch", "s3:GetObject", "") {
			t.Fatal("s3:GetObject with empty key must be denied")
		}
	})
}

func TestCheckAccessWithContextAdditionalBranches(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("ctx-branch"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("ctx-branch", "owner-ak")
	h := New(b)

	t.Run("missing bucket is allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/missing", nil)
		if !h.checkAccessWithContext(
			req,
			"missing",
			"s3:ListBucket",
			"",
			backend.PolicyEvalContext{},
		) {
			t.Fatal("checkAccessWithContext should allow when bucket does not exist")
		}
	})

	t.Run("explicit deny is rejected", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListBucket","Principal":"*","Resource":"arn:aws:s3:::ctx-branch"}]}`
		if err := b.PutBucketPolicy("ctx-branch", policy); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/ctx-branch", nil)
		req.Header.Set("Authorization", authHeader("owner-ak"))
		if h.checkAccessWithContext(
			req,
			"ctx-branch",
			"s3:ListBucket",
			"",
			backend.PolicyEvalContext{},
		) {
			t.Fatal("explicit deny should be rejected even for owner")
		}
	})

	t.Run("owner is allowed when not denied", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("ctx-branch"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/ctx-branch", nil)
		req.Header.Set("Authorization", authHeader("owner-ak"))
		if !h.checkAccessWithContext(
			req,
			"ctx-branch",
			"s3:ListBucket",
			"",
			backend.PolicyEvalContext{},
		) {
			t.Fatal("owner should be allowed when no explicit deny exists")
		}
	})
}
