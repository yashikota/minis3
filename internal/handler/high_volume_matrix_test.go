package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func encodePolicyWithConditions(t *testing.T, expiration string, conditions []any) string {
	t.Helper()
	policy := map[string]any{
		"expiration": expiration,
		"conditions": conditions,
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestValidatePostPolicyFieldRequirementMatrix(t *testing.T) {
	expiration := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")

	type fieldCase struct {
		field  string
		value  string
		exempt bool
	}

	cases := []fieldCase{
		{field: "key", value: "obj.txt", exempt: false},
		{field: "content-type", value: "text/plain", exempt: false},
		{field: "acl", value: "private", exempt: false},
		{field: "cache-control", value: "max-age=60", exempt: false},
		{field: "content-disposition", value: "inline", exempt: false},
		{field: "content-encoding", value: "gzip", exempt: false},
		{field: "expires", value: "Wed, 21 Oct 2015 07:28:00 GMT", exempt: false},
		{field: "success_action_redirect", value: "https://example.test/ok", exempt: false},
		{field: "success_action_status", value: "201", exempt: false},
		{field: "x-amz-meta-project", value: "alpha", exempt: false},
		{field: "x-amz-meta-user", value: "bob", exempt: false},
		{field: "x-amz-security-token", value: "token", exempt: false},
		{field: "x-amz-algorithm", value: "AWS4-HMAC-SHA256", exempt: false},
		{
			field:  "x-amz-credential",
			value:  "AKIA/20260208/us-east-1/s3/aws4_request",
			exempt: false,
		},
		{field: "x-amz-date", value: "20260208T000000Z", exempt: false},
		{field: "x-amz-storage-class", value: "STANDARD_IA", exempt: false},
		{field: "x-amz-checksum-sha256", value: "abcd", exempt: true},
		{field: "file", value: "ignored", exempt: true},
		{field: "policy", value: "ignored", exempt: true},
		{field: "signature", value: "ignored", exempt: true},
		{field: "x-amz-signature", value: "ignored", exempt: true},
		{field: "awsaccesskeyid", value: "ignored", exempt: true},
		{field: "x-ignore-client-debug", value: "ignored", exempt: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("missing_condition/"+tc.field, func(t *testing.T) {
			policy := encodePolicyWithConditions(
				t,
				expiration,
				[]any{
					map[string]any{"bucket": "bucket-a"},
				},
			)

			formFields := map[string]string{tc.field: tc.value}
			key := "obj.txt"
			contentType := "text/plain"
			if tc.field == "key" {
				key = tc.value
			}
			if tc.field == "content-type" {
				contentType = tc.value
			}

			status, ok := validatePostPolicy(
				policy,
				"bucket-a",
				key,
				contentType,
				formFields,
				1,
			)

			if tc.exempt {
				if !ok || status != 0 {
					t.Fatalf("exempt field should pass: ok=%v status=%d", ok, status)
				}
				return
			}

			if ok || status != 403 {
				t.Fatalf("required field should fail with 403: ok=%v status=%d", ok, status)
			}
		})

		t.Run("with_condition/"+tc.field, func(t *testing.T) {
			policy := encodePolicyWithConditions(
				t,
				expiration,
				[]any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"eq", "$" + tc.field, tc.value},
				},
			)

			formFields := map[string]string{tc.field: tc.value}
			key := "obj.txt"
			contentType := "text/plain"
			if tc.field == "key" {
				key = tc.value
			}
			if tc.field == "content-type" {
				contentType = tc.value
			}

			status, ok := validatePostPolicy(
				policy,
				"bucket-a",
				key,
				contentType,
				formFields,
				1,
			)

			if !ok || status != 0 {
				t.Fatalf("field with matching condition should pass: ok=%v status=%d", ok, status)
			}
		})
	}
}

func TestValidatePostPolicyContentLengthRangeGrid(t *testing.T) {
	expiration := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")

	for min := 0; min <= 4; min++ {
		for max := 0; max <= 4; max++ {
			for size := 0; size <= 4; size++ {
				min, max, size := min, max, size
				t.Run(
					fmt.Sprintf("min_%d_max_%d_size_%d", min, max, size),
					func(t *testing.T) {
						policy := encodePolicyWithConditions(
							t,
							expiration,
							[]any{
								map[string]any{"bucket": "bucket-a"},
								[]any{"content-length-range", min, max},
							},
						)

						status, ok := validatePostPolicy(
							policy,
							"bucket-a",
							"obj.txt",
							"text/plain",
							map[string]string{},
							int64(size),
						)

						shouldPass := max >= min && size >= min && size <= max
						if shouldPass {
							if !ok || status != 0 {
								t.Fatalf("expected pass: ok=%v status=%d", ok, status)
							}
							return
						}
						if ok || status != 400 {
							t.Fatalf("expected 400 failure: ok=%v status=%d", ok, status)
						}
					},
				)
			}
		}
	}
}

func TestEffectiveACLForResponseMatrix(t *testing.T) {
	owner := backend.OwnerForAccessKey("owner-ak")
	other := backend.OwnerForAccessKey("other-ak")

	mixedACL := backend.NewDefaultACLForOwner(owner)
	mixedACL.AccessControlList.Grants = append(
		mixedACL.AccessControlList.Grants,
		backend.Grant{
			Grantee: &backend.Grantee{
				Type: "CanonicalUser",
				ID:   other.ID,
			},
			Permission: backend.PermissionRead,
		},
		backend.Grant{
			Grantee: &backend.Grantee{
				Type: "Group",
				URI:  backend.AllUsersURI,
			},
			Permission: backend.PermissionRead,
		},
		backend.Grant{
			Grantee: &backend.Grantee{
				Type: "Group",
				URI:  backend.AuthenticatedUsersURI,
			},
			Permission: backend.PermissionRead,
		},
	)

	testACLs := map[string]*backend.AccessControlPolicy{
		"nil":                nil,
		"owner_only":         backend.NewDefaultACLForOwner(owner),
		"public_read":        backend.CannedACLToPolicyForOwner("public-read", owner, owner),
		"public_read_write":  backend.CannedACLToPolicyForOwner("public-read-write", owner, owner),
		"authenticated_read": backend.CannedACLToPolicyForOwner("authenticated-read", owner, owner),
		"mixed":              mixedACL,
	}

	for name, acl := range testACLs {
		name, acl := name, acl
		for _, ignorePublicACLs := range []bool{false, true} {
			ignorePublicACLs := ignorePublicACLs
			t.Run(
				fmt.Sprintf("%s/ignore_%t", name, ignorePublicACLs),
				func(t *testing.T) {
					res := effectiveACLForResponse(acl, ignorePublicACLs)

					if acl == nil {
						if res != nil {
							t.Fatalf("nil ACL should stay nil, got %+v", res)
						}
						return
					}

					if !ignorePublicACLs {
						if res != acl {
							t.Fatal("expected same ACL pointer when ignorePublicACLs=false")
						}
						if aclHasPublicGrant(res) != aclHasPublicGrant(acl) {
							t.Fatalf(
								"public grant presence changed unexpectedly: before=%v after=%v",
								aclHasPublicGrant(acl),
								aclHasPublicGrant(res),
							)
						}
						return
					}

					if res == acl {
						t.Fatal("expected a copied ACL when ignorePublicACLs=true")
					}
					if aclHasPublicGrant(res) {
						t.Fatalf(
							"public grants should be filtered: %+v",
							res.AccessControlList.Grants,
						)
					}
					if aclHasOwnerFullControl(acl, owner.ID) &&
						!aclHasOwnerFullControl(res, owner.ID) {
						t.Fatalf(
							"owner full control grant must be preserved: %+v",
							res.AccessControlList.Grants,
						)
					}
				},
			)
		}
	}
}
