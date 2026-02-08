package handler

import (
	"encoding/xml"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func decodeACLFromResponse(
	t *testing.T,
	wBody []byte,
) *backend.AccessControlPolicy {
	t.Helper()

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(wBody, &acl); err != nil {
		t.Fatalf("failed to decode ACL XML: %v body=%s", err, string(wBody))
	}
	return &acl
}

func aclHasPublicGrant(acl *backend.AccessControlPolicy) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Grantee.URI == backend.AllUsersURI ||
			grant.Grantee.URI == backend.AuthenticatedUsersURI {
			return true
		}
	}
	return false
}

func aclHasOwnerFullControl(acl *backend.AccessControlPolicy, ownerID string) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Grantee.ID == ownerID && grant.Permission == backend.PermissionFullControl {
			return true
		}
	}
	return false
}

func TestCreateBucketWithCannedACLPreservesRequesterOwner(t *testing.T) {
	h, b := newTestHandler(t)

	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/owner-preserve-bucket",
			"",
			map[string]string{
				"Authorization": authHeader("owner-ak"),
				"x-amz-acl":     "public-read",
			},
		),
	)
	requireStatus(t, w, http.StatusOK)

	bucket, ok := b.GetBucket("owner-preserve-bucket")
	if !ok {
		t.Fatal("bucket should exist")
	}
	if bucket.OwnerAccessKey != "owner-ak" {
		t.Fatalf("unexpected owner access key: %q", bucket.OwnerAccessKey)
	}

	acl, err := b.GetBucketACL("owner-preserve-bucket")
	if err != nil {
		t.Fatalf("GetBucketACL failed: %v", err)
	}
	owner := backend.OwnerForAccessKey("owner-ak")
	if acl.Owner == nil || acl.Owner.ID != owner.ID {
		t.Fatalf("unexpected ACL owner: %+v want owner ID %q", acl.Owner, owner.ID)
	}
	if !aclHasOwnerFullControl(acl, owner.ID) {
		t.Fatalf("expected owner full control grant in ACL: %+v", acl.AccessControlList.Grants)
	}
	if !aclHasPublicGrant(acl) {
		t.Fatalf(
			"expected public grant for canned ACL public-read: %+v",
			acl.AccessControlList.Grants,
		)
	}
}

func TestGetBucketLocationAccessControl(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "location-auth-bucket")
	b.SetBucketOwner("location-auth-bucket", "owner-ak")

	t.Run("non-owner denied without policy", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/location-auth-bucket?location",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("owner allowed", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/location-auth-bucket?location",
				"",
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("public policy allows get bucket location", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Principal":"*","Action":"s3:GetBucketLocation",` +
			`"Resource":"arn:aws:s3:::location-auth-bucket"}]}`
		if err := b.PutBucketPolicy("location-auth-bucket", policy); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/location-auth-bucket?location",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})
}

func TestIgnorePublicACLsReturnsEffectiveBucketACL(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "ignore-public-bucket")
	b.SetBucketOwner("ignore-public-bucket", "owner-ak")

	owner := backend.OwnerForAccessKey("owner-ak")
	if err := b.PutBucketACL(
		"ignore-public-bucket",
		backend.CannedACLToPolicyForOwner("public-read", owner, owner),
	); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}

	before := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/ignore-public-bucket?acl",
			"",
			map[string]string{"Authorization": authHeader("owner-ak")},
		),
	)
	requireStatus(t, before, http.StatusOK)
	beforeACL := decodeACLFromResponse(t, before.Body.Bytes())
	if !aclHasPublicGrant(beforeACL) {
		t.Fatalf(
			"expected public grant before IgnorePublicAcls: %+v",
			beforeACL.AccessControlList.Grants,
		)
	}

	if err := b.PutPublicAccessBlock("ignore-public-bucket", &backend.PublicAccessBlockConfiguration{
		IgnorePublicAcls: true,
	}); err != nil {
		t.Fatalf("PutPublicAccessBlock failed: %v", err)
	}

	after := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/ignore-public-bucket?acl",
			"",
			map[string]string{"Authorization": authHeader("owner-ak")},
		),
	)
	requireStatus(t, after, http.StatusOK)
	afterACL := decodeACLFromResponse(t, after.Body.Bytes())
	if aclHasPublicGrant(afterACL) {
		t.Fatalf(
			"public grant should be hidden when IgnorePublicAcls=true: %+v",
			afterACL.AccessControlList.Grants,
		)
	}
	if !aclHasOwnerFullControl(afterACL, owner.ID) {
		t.Fatalf(
			"owner grant should remain in effective ACL: %+v",
			afterACL.AccessControlList.Grants,
		)
	}
}

func TestIgnorePublicACLsReturnsEffectiveObjectACL(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "ignore-public-object")
	b.SetBucketOwner("ignore-public-object", "owner-ak")
	mustPutObject(t, b, "ignore-public-object", "obj", "data")

	owner := backend.OwnerForAccessKey("owner-ak")
	if err := b.PutObjectACL(
		"ignore-public-object",
		"obj",
		"",
		backend.CannedACLToPolicyForOwner("public-read", owner, owner),
	); err != nil {
		t.Fatalf("PutObjectACL failed: %v", err)
	}

	before := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/ignore-public-object/obj?acl",
			"",
			map[string]string{"Authorization": authHeader("owner-ak")},
		),
	)
	requireStatus(t, before, http.StatusOK)
	beforeACL := decodeACLFromResponse(t, before.Body.Bytes())
	if !aclHasPublicGrant(beforeACL) {
		t.Fatalf(
			"expected public grant before IgnorePublicAcls: %+v",
			beforeACL.AccessControlList.Grants,
		)
	}

	if err := b.PutPublicAccessBlock("ignore-public-object", &backend.PublicAccessBlockConfiguration{
		IgnorePublicAcls: true,
	}); err != nil {
		t.Fatalf("PutPublicAccessBlock failed: %v", err)
	}

	after := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/ignore-public-object/obj?acl",
			"",
			map[string]string{"Authorization": authHeader("owner-ak")},
		),
	)
	requireStatus(t, after, http.StatusOK)
	afterACL := decodeACLFromResponse(t, after.Body.Bytes())
	if aclHasPublicGrant(afterACL) {
		t.Fatalf(
			"public grant should be hidden when IgnorePublicAcls=true: %+v",
			afterACL.AccessControlList.Grants,
		)
	}
	if !aclHasOwnerFullControl(afterACL, owner.ID) {
		t.Fatalf(
			"owner grant should remain in effective ACL: %+v",
			afterACL.AccessControlList.Grants,
		)
	}
}

func TestGetBucketACLAccessAndErrorBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket-acl-access")
	b.SetBucketOwner("bucket-acl-access", "owner-ak")

	t.Run("non-owner denied", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-acl-access?acl", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("authorized missing bucket returns no such bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-such-bucket-acl?acl",
				"",
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})
}
