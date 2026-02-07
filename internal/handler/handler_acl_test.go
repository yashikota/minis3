package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestPresignedErrorError(t *testing.T) {
	e := &presignedError{message: "msg"}
	if got := e.Error(); got != "msg" {
		t.Fatalf("Error() = %q, want %q", got, "msg")
	}
}

func TestACLHelpers(t *testing.T) {
	if isPublicACL(nil) {
		t.Fatal("nil ACL should not be public")
	}

	allUsersRead := &backend.AccessControlPolicy{AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
		Grantee:    &backend.Grantee{URI: backend.AllUsersURI},
		Permission: backend.PermissionRead,
	}}}}
	if !isPublicACL(allUsersRead) {
		t.Fatal("expected public ACL")
	}

	authUsersWrite := &backend.AccessControlPolicy{AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
		Grantee:    &backend.Grantee{URI: backend.AuthenticatedUsersURI},
		Permission: backend.PermissionWrite,
	}}}}
	if !aclAllowsWrite(authUsersWrite, "", false) {
		t.Fatal("expected authenticated user write to be allowed")
	}

	canonical := backend.OwnerForAccessKey("minis3-access-key")
	canonicalReadACP := &backend.AccessControlPolicy{AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
		Grantee:    &backend.Grantee{ID: canonical.ID},
		Permission: backend.PermissionReadACP,
	}}}}
	if !aclAllowsACP(canonicalReadACP, canonical.ID, false, backend.PermissionReadACP) {
		t.Fatal("expected canonical read-acp to be allowed")
	}
	if aclAllowsRead(canonicalReadACP, canonical.ID, false) {
		t.Fatal("read should not be allowed when only read-acp exists")
	}
}

func TestNormalizeAndValidateACL(t *testing.T) {
	owner := backend.OwnerForAccessKey("minis3-access-key")

	t.Run("normalizes owner and email grantee", func(t *testing.T) {
		acl := &backend.AccessControlPolicy{
			Owner: &backend.Owner{ID: owner.ID},
			AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
				Grantee:    &backend.Grantee{Type: "AmazonCustomerByEmail", EmailAddress: "alt@example.com"},
				Permission: backend.PermissionRead,
			}}},
		}
		err := normalizeAndValidateACL(acl)
		if err != nil {
			t.Fatalf("unexpected error: %+v", err)
		}
		if acl.Owner.DisplayName == "" {
			t.Fatal("owner display name should be filled")
		}
		if acl.AccessControlList.Grants[0].Grantee.Type != "CanonicalUser" {
			t.Fatal("email grantee should be normalized to canonical user")
		}
	})

	t.Run("unknown owner", func(t *testing.T) {
		acl := &backend.AccessControlPolicy{Owner: &backend.Owner{ID: "unknown"}}
		err := normalizeAndValidateACL(acl)
		if err == nil || err.code != "InvalidArgument" {
			t.Fatalf("unexpected error: %+v", err)
		}
	})

	t.Run("unresolvable email", func(t *testing.T) {
		acl := &backend.AccessControlPolicy{AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
			Grantee:    &backend.Grantee{Type: "AmazonCustomerByEmail", EmailAddress: "missing@example.com"},
			Permission: backend.PermissionRead,
		}}}}
		err := normalizeAndValidateACL(acl)
		if err == nil || err.code != "UnresolvableGrantByEmailAddress" {
			t.Fatalf("unexpected error: %+v", err)
		}
	})

	t.Run("canonical grantee without id", func(t *testing.T) {
		acl := &backend.AccessControlPolicy{AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
			Grantee:    &backend.Grantee{Type: "CanonicalUser"},
			Permission: backend.PermissionRead,
		}}}}
		err := normalizeAndValidateACL(acl)
		if err == nil || err.code != "InvalidArgument" {
			t.Fatalf("unexpected error: %+v", err)
		}
	})
}

func TestACLFromGrantHeaders(t *testing.T) {
	owner := backend.OwnerForAccessKey("minis3-access-key")

	t.Run("no headers", func(t *testing.T) {
		req := newRequest(http.MethodPut, "http://example.test/bucket/key", "", nil)
		acl, err := aclFromGrantHeaders(req, owner)
		if err != nil || acl != nil {
			t.Fatalf("expected nil acl,nil err. got acl=%+v err=%+v", acl, err)
		}
	})

	t.Run("invalid header format", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/bucket/key",
			"",
			map[string]string{"x-amz-grant-read": "badformat"},
		)
		_, err := aclFromGrantHeaders(req, owner)
		if err == nil || err.code != "InvalidArgument" {
			t.Fatalf("unexpected error: %+v", err)
		}
	})

	t.Run("valid id uri email grants", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/bucket/key",
			"",
			map[string]string{
				"x-amz-grant-read":         "id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"x-amz-grant-write":        "uri=http://acs.amazonaws.com/groups/global/AllUsers",
				"x-amz-grant-full-control": "emailAddress=alt@example.com",
			},
		)
		acl, err := aclFromGrantHeaders(req, owner)
		if err != nil {
			t.Fatalf("unexpected error: %+v", err)
		}
		if acl == nil || len(acl.AccessControlList.Grants) != 3 {
			t.Fatalf("unexpected acl: %+v", acl)
		}
	})
}

func TestHandlerMiscBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")

	t.Run("bucket owner fallback", func(t *testing.T) {
		owner := h.bucketOwner("missing")
		if owner == nil || owner.ID == "" {
			t.Fatalf("unexpected owner: %+v", owner)
		}
	})

	t.Run("public access block helper", func(t *testing.T) {
		if cfg := h.getBucketPublicAccessBlock("bucket"); cfg != nil {
			t.Fatalf("expected nil config initially, got %+v", cfg)
		}
	})

	t.Run("options preflight valid continues", func(t *testing.T) {
		req := newRequest(http.MethodOptions, "http://example.test/bucket/key", "", map[string]string{
			"Origin":                        "https://example.test",
			"Access-Control-Request-Method": "GET",
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusMethodNotAllowed)
	})

	t.Run("expected bucket owner mismatch", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/bucket", "", map[string]string{
			"x-amz-expected-bucket-owner": "mismatch",
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})
}
