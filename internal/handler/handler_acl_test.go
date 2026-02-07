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
	if aclAllowsRead(nil, false) {
		t.Fatal("nil ACL should not allow read")
	}
	if aclAllowsWrite(nil, false) {
		t.Fatal("nil ACL should not allow write")
	}

	allUsersRead := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
			Grantee:    &backend.Grantee{URI: backend.AllUsersURI},
			Permission: backend.PermissionRead,
		}}},
	}
	if !isPublicACL(allUsersRead) {
		t.Fatal("expected public ACL")
	}
	if !aclAllowsRead(allUsersRead, true) {
		t.Fatal("all users read should be allowed for anonymous requests")
	}
	if aclAllowsWrite(allUsersRead, false) {
		t.Fatal("write should not be allowed for read-only ACL")
	}

	authUsersWrite := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
			Grantee:    &backend.Grantee{URI: backend.AuthenticatedUsersURI},
			Permission: backend.PermissionWrite,
		}}},
	}
	if !aclAllowsWrite(authUsersWrite, false) {
		t.Fatal("expected authenticated user write to be allowed")
	}
	if aclAllowsWrite(authUsersWrite, true) {
		t.Fatal("anonymous user should not be allowed by authenticated-users write grant")
	}
	canonicalRead := &backend.AccessControlPolicy{
		AccessControlList: backend.AccessControlList{Grants: []backend.Grant{{
			Grantee:    &backend.Grantee{ID: "0123456789abcdef"},
			Permission: backend.PermissionRead,
		}}},
	}
	if isPublicACL(canonicalRead) {
		t.Fatal("canonical-only ACL should not be considered public")
	}
	if aclAllowsRead(canonicalRead, false) {
		t.Fatal("canonical grants are not used by aclAllowsRead fallback")
	}
}

func TestHandlerMiscBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")

	t.Run("public access block helper", func(t *testing.T) {
		if cfg := h.getBucketPublicAccessBlock("bucket"); cfg != nil {
			t.Fatalf("expected nil config initially, got %+v", cfg)
		}
	})

	t.Run("options preflight valid continues", func(t *testing.T) {
		req := newRequest(
			http.MethodOptions,
			"http://example.test/bucket/key",
			"",
			map[string]string{
				"Origin":                        "https://example.test",
				"Access-Control-Request-Method": "GET",
			},
		)
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
