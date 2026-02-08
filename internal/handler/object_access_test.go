package handler

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleObjectAnonymousPutWithoutPolicyIsDenied(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-private"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-private", "minis3-access-key")
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
	b.SetBucketOwner("bucket-acl", "minis3-access-key")
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

func TestHandleBucketACLRoundTripWithXSITypeGrants(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-acl-roundtrip"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-acl-roundtrip", "minis3-access-key")
	h := New(b)

	owner := backend.DefaultOwner()
	body := strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/" `,
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`,
		`<Owner><ID>`,
		owner.ID,
		`</ID><DisplayName>`,
		owner.DisplayName,
		`</DisplayName></Owner>`,
		`<AccessControlList>`,
		`<Grant><Grantee xsi:type="Group"><URI>`,
		backend.AllUsersURI,
		`</URI></Grantee><Permission>READ</Permission></Grant>`,
		`<Grant><Grantee xsi:type="CanonicalUser"><ID>`,
		owner.ID,
		`</ID><DisplayName>`,
		owner.DisplayName,
		`</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>`,
		`</AccessControlList></AccessControlPolicy>`,
	}, "")

	putReq := httptest.NewRequest(
		http.MethodPut,
		"/bucket-acl-roundtrip?acl",
		strings.NewReader(body),
	)
	putReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	putRes := httptest.NewRecorder()
	h.ServeHTTP(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("unexpected PUT status: got %d, want %d", putRes.Code, http.StatusOK)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/bucket-acl-roundtrip?acl", nil)
	getReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	getRes := httptest.NewRecorder()
	h.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf(
			"unexpected GET status: got %d, want %d, body=%s",
			getRes.Code,
			http.StatusOK,
			getRes.Body.String(),
		)
	}
	if !strings.Contains(getRes.Body.String(), backend.AllUsersURI) {
		t.Fatalf(
			"expected GET ACL response to include AllUsers grant, body=%s",
			getRes.Body.String(),
		)
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(getRes.Body.Bytes(), &acl); err != nil {
		t.Fatalf(
			"response ACL XML should be parseable: %v, body=%s",
			err,
			getRes.Body.String(),
		)
	}
}

func TestHandleObjectACLWithBucketOwnerReadForObjectWriter(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-owner-read-test"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-owner-read-test", "minis3-access-key")
	if err := b.PutBucketACL("bucket-owner-read-test", backend.CannedACLToPolicy("public-read-write")); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}
	h := New(b)

	putReq := httptest.NewRequest(
		http.MethodPut,
		"/bucket-owner-read-test/foo",
		strings.NewReader("bar"),
	)
	putReq.Header.Set("Authorization", "AWS minis3-alt-access-key:sig")
	putReq.Header.Set("x-amz-acl", "bucket-owner-read")
	putRes := httptest.NewRecorder()
	h.ServeHTTP(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("unexpected PUT status: got %d, want %d", putRes.Code, http.StatusOK)
	}

	getACLReq := httptest.NewRequest(http.MethodGet, "/bucket-owner-read-test/foo?acl", nil)
	getACLReq.Header.Set("Authorization", "AWS minis3-alt-access-key:sig")
	getACLRes := httptest.NewRecorder()
	h.ServeHTTP(getACLRes, getACLReq)
	if getACLRes.Code != http.StatusOK {
		t.Fatalf("unexpected GetObjectAcl status: got %d, want %d", getACLRes.Code, http.StatusOK)
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(getACLRes.Body.Bytes(), &acl); err != nil {
		t.Fatalf("failed to parse GetObjectAcl response: %v", err)
	}
	if acl.Owner == nil || acl.Owner.ID != backend.OwnerForAccessKey("minis3-alt-access-key").ID {
		t.Fatalf("unexpected ACL owner: %+v", acl.Owner)
	}
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
	b.SetBucketOwner("policy-bucket", "minis3-access-key")
	h := New(b)

	t.Run("no policy denies non-owner request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		if h.checkAccess(req, "policy-bucket", "s3:GetObject", "obj") {
			t.Fatal("expected non-owner access to be denied when no policy/ACL allows it")
		}
	})

	t.Run("no policy allows owner request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/policy-bucket/obj", nil)
		req.Header.Set("Authorization", "AWS minis3-access-key:sig")
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
		req.Header.Set("Authorization", "AWS minis3-access-key:sig")
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
	b.SetBucketOwner("policy-context-bucket", "minis3-access-key")
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

	ownerReq := httptest.NewRequest(http.MethodGet, "/policy-context-bucket/obj", nil)
	ownerReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	ownerAllowed := h.checkAccessWithContext(
		ownerReq,
		"policy-context-bucket",
		"s3:GetObject",
		"obj",
		backend.PolicyEvalContext{
			ExistingObjectTags: map[string]string{"Project": "beta"},
		},
	)
	if !ownerAllowed {
		t.Fatal("expected bucket owner to remain allowed without explicit deny")
	}
}

func TestCheckAccessBucketACLCanonicalUserPermissions(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-acl-canonical"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-acl-canonical", "minis3-access-key")
	owner := backend.OwnerForAccessKey("minis3-access-key")
	alt := backend.OwnerForAccessKey("minis3-alt-access-key")
	acl := &backend.AccessControlPolicy{
		Owner: owner,
		AccessControlList: backend.AccessControlList{
			Grants: []backend.Grant{
				{
					Grantee: &backend.Grantee{
						Type:        "CanonicalUser",
						ID:          alt.ID,
						DisplayName: alt.DisplayName,
					},
					Permission: backend.PermissionWrite,
				},
				{
					Grantee: &backend.Grantee{
						Type:        "CanonicalUser",
						ID:          alt.ID,
						DisplayName: alt.DisplayName,
					},
					Permission: backend.PermissionReadACP,
				},
				{
					Grantee: &backend.Grantee{
						Type:        "CanonicalUser",
						ID:          alt.ID,
						DisplayName: alt.DisplayName,
					},
					Permission: backend.PermissionWriteACP,
				},
				{
					Grantee: &backend.Grantee{
						Type:        "CanonicalUser",
						ID:          owner.ID,
						DisplayName: owner.DisplayName,
					},
					Permission: backend.PermissionFullControl,
				},
			},
		},
	}
	if err := b.PutBucketACL("bucket-acl-canonical", acl); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}

	h := New(b)
	req := httptest.NewRequest(http.MethodGet, "/bucket-acl-canonical", nil)
	req.Header.Set("Authorization", "AWS minis3-alt-access-key:sig")

	if !h.checkAccess(req, "bucket-acl-canonical", "s3:PutObject", "obj") {
		t.Fatal("expected alt user to have write access by canonical grant")
	}
	if !h.checkAccess(req, "bucket-acl-canonical", "s3:GetBucketAcl", "") {
		t.Fatal("expected alt user to have read ACP access by canonical grant")
	}
	if !h.checkAccess(req, "bucket-acl-canonical", "s3:PutBucketAcl", "") {
		t.Fatal("expected alt user to have write ACP access by canonical grant")
	}
}

func TestHandlePutBucketACLRejectsUnknownCanonicalUser(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-acl-invalid-user"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-acl-invalid-user", "minis3-access-key")
	h := New(b)

	owner := backend.OwnerForAccessKey("minis3-access-key")
	body := strings.Join([]string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/" `,
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`,
		`<Owner><ID>`,
		owner.ID,
		`</ID><DisplayName>`,
		owner.DisplayName,
		`</DisplayName></Owner>`,
		`<AccessControlList>`,
		`<Grant><Grantee xsi:type="CanonicalUser"><ID>_foo</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>`,
		`</AccessControlList></AccessControlPolicy>`,
	}, "")

	req := httptest.NewRequest(
		http.MethodPut,
		"/bucket-acl-invalid-user?acl",
		strings.NewReader(body),
	)
	req.Header.Set("Authorization", "AWS minis3-access-key:sig")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "<Code>InvalidArgument</Code>") {
		t.Fatalf("unexpected response body: %s", w.Body.String())
	}
}

func TestHandlePutObjectAppliesGrantHeaders(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-object-grants"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-object-grants", "minis3-access-key")
	h := New(b)

	alt := backend.OwnerForAccessKey("minis3-alt-access-key")
	putReq := httptest.NewRequest(
		http.MethodPut,
		"/bucket-object-grants/foo",
		strings.NewReader("bar"),
	)
	putReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	for _, header := range []string{
		"x-amz-grant-read",
		"x-amz-grant-write",
		"x-amz-grant-read-acp",
		"x-amz-grant-write-acp",
		"x-amz-grant-full-control",
	} {
		putReq.Header.Set(header, "id="+alt.ID)
	}
	putRes := httptest.NewRecorder()
	h.ServeHTTP(putRes, putReq)
	if putRes.Code != http.StatusOK {
		t.Fatalf("unexpected PUT status: got %d, want %d", putRes.Code, http.StatusOK)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/bucket-object-grants/foo?acl", nil)
	getReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	getRes := httptest.NewRecorder()
	h.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("unexpected GetObjectAcl status: got %d, want %d", getRes.Code, http.StatusOK)
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(getRes.Body.Bytes(), &acl); err != nil {
		t.Fatalf("failed to parse GetObjectAcl response: %v", err)
	}
	if len(acl.AccessControlList.Grants) != 6 {
		t.Fatalf("unexpected grant count: %d", len(acl.AccessControlList.Grants))
	}
	seen := make(map[string]bool, 5)
	ownerSeen := false
	owner := backend.OwnerForAccessKey("minis3-access-key")
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			t.Fatalf("unexpected nil grantee in grant")
		}
		if grant.Grantee.ID == alt.ID && grant.Grantee.DisplayName == alt.DisplayName {
			seen[grant.Permission] = true
			continue
		}
		if owner != nil &&
			grant.Grantee.ID == owner.ID &&
			grant.Permission == backend.PermissionFullControl {
			ownerSeen = true
			continue
		}
		t.Fatalf("unexpected grantee in grant: %+v", grant.Grantee)
	}
	for _, permission := range []string{
		backend.PermissionRead,
		backend.PermissionWrite,
		backend.PermissionReadACP,
		backend.PermissionWriteACP,
		backend.PermissionFullControl,
	} {
		if !seen[permission] {
			t.Fatalf(
				"missing permission %q in ACL grants: %+v",
				permission,
				acl.AccessControlList.Grants,
			)
		}
	}
	if !ownerSeen {
		t.Fatalf("missing owner full control grant: %+v", acl.AccessControlList.Grants)
	}
}

func TestHandleCreateBucketAppliesGrantHeaders(t *testing.T) {
	b := backend.New()
	h := New(b)
	alt := backend.OwnerForAccessKey("minis3-alt-access-key")

	createReq := httptest.NewRequest(http.MethodPut, "/bucket-create-grants", nil)
	createReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	for _, header := range []string{
		"x-amz-grant-read",
		"x-amz-grant-write",
		"x-amz-grant-read-acp",
		"x-amz-grant-write-acp",
		"x-amz-grant-full-control",
	} {
		createReq.Header.Set(header, "id="+alt.ID)
	}
	createRes := httptest.NewRecorder()
	h.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusOK {
		t.Fatalf("unexpected CreateBucket status: got %d, want %d", createRes.Code, http.StatusOK)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/bucket-create-grants?acl", nil)
	getReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	getRes := httptest.NewRecorder()
	h.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("unexpected GetBucketAcl status: got %d, want %d", getRes.Code, http.StatusOK)
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(getRes.Body.Bytes(), &acl); err != nil {
		t.Fatalf("failed to parse GetBucketAcl response: %v", err)
	}
	if len(acl.AccessControlList.Grants) != 6 {
		t.Fatalf("unexpected grant count: %d", len(acl.AccessControlList.Grants))
	}
	seen := make(map[string]bool, 5)
	ownerSeen := false
	owner := backend.OwnerForAccessKey("minis3-access-key")
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			t.Fatalf("unexpected nil grantee in grant")
		}
		if grant.Grantee.ID == alt.ID && grant.Grantee.DisplayName == alt.DisplayName {
			seen[grant.Permission] = true
			continue
		}
		if owner != nil &&
			grant.Grantee.ID == owner.ID &&
			grant.Permission == backend.PermissionFullControl {
			ownerSeen = true
			continue
		}
		t.Fatalf("unexpected grantee in grant: %+v", grant.Grantee)
	}
	for _, permission := range []string{
		backend.PermissionRead,
		backend.PermissionWrite,
		backend.PermissionReadACP,
		backend.PermissionWriteACP,
		backend.PermissionFullControl,
	} {
		if !seen[permission] {
			t.Fatalf(
				"missing permission %q in ACL grants: %+v",
				permission,
				acl.AccessControlList.Grants,
			)
		}
	}
	if !ownerSeen {
		t.Fatalf("missing owner full control grant: %+v", acl.AccessControlList.Grants)
	}
}

func TestHandleCopyObjectAppliesCannedACL(t *testing.T) {
	b := backend.New()
	if err := b.CreateBucket("bucket-copy-acl"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	b.SetBucketOwner("bucket-copy-acl", "minis3-access-key")
	if _, err := b.PutObject("bucket-copy-acl", "src", []byte("data"), backend.PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	h := New(b)

	copyReq := httptest.NewRequest(http.MethodPut, "/bucket-copy-acl/dst", nil)
	copyReq.Header.Set("Authorization", "AWS minis3-access-key:sig")
	copyReq.Header.Set("x-amz-copy-source", "/bucket-copy-acl/src")
	copyReq.Header.Set("x-amz-acl", "public-read")
	copyRes := httptest.NewRecorder()
	h.ServeHTTP(copyRes, copyReq)
	if copyRes.Code != http.StatusOK {
		t.Fatalf("unexpected CopyObject status: got %d, want %d", copyRes.Code, http.StatusOK)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/bucket-copy-acl/dst", nil)
	getReq.Header.Set("Authorization", "AWS minis3-alt-access-key:sig")
	getRes := httptest.NewRecorder()
	h.ServeHTTP(getRes, getReq)
	if getRes.Code != http.StatusOK {
		t.Fatalf("unexpected GET status: got %d, want %d", getRes.Code, http.StatusOK)
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
