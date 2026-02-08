package handler

import (
	"encoding/xml"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestBucketPolicyBranchCoverage(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "policy-branch")
	b.SetBucketOwner("policy-branch", "minis3-access-key")

	publicPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-branch/*"}]}`

	t.Run("put policy access denied for non-owner", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/policy-branch?policy",
				publicPolicy,
				nil,
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("put policy blocked by public access block", func(t *testing.T) {
		if err := b.PutPublicAccessBlock(
			"policy-branch",
			&backend.PublicAccessBlockConfiguration{BlockPublicPolicy: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/policy-branch?policy",
				publicPolicy,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")

		if err := b.DeletePublicAccessBlock("policy-branch"); err != nil {
			t.Fatalf("DeletePublicAccessBlock failed: %v", err)
		}
	})

	t.Run("put policy malformed and missing bucket", func(t *testing.T) {
		wMalformed := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/policy-branch?policy",
				`{"bad":`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wMalformed, "MalformedPolicy")

		wMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-such-policy-bucket?policy",
				publicPolicy,
				nil,
			),
		)
		requireStatus(t, wMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wMissing, "NoSuchBucket")
	})

	t.Run("put/get/delete policy success", func(t *testing.T) {
		headers := map[string]string{"Authorization": authHeader("minis3-access-key")}
		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/policy-branch?policy",
				publicPolicy,
				headers,
			),
		)
		requireStatus(t, wPut, http.StatusNoContent)

		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/policy-branch?policy", "", headers),
		)
		requireStatus(t, wGet, http.StatusOK)

		wDelete := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/policy-branch?policy", "", headers),
		)
		requireStatus(t, wDelete, http.StatusNoContent)
	})

	t.Run("get policy no such bucket and no policy", func(t *testing.T) {
		wMissingBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-policy-bucket?policy", "", nil),
		)
		requireStatus(t, wMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wMissingBucket, "NoSuchBucket")

		mustCreateBucket(t, b, "no-policy-yet")
		wNoPolicy := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-policy-yet?policy", "", nil),
		)
		requireStatus(t, wNoPolicy, http.StatusNotFound)
		requireS3ErrorCode(t, wNoPolicy, "NoSuchBucketPolicy")
	})
}

func TestGetDeleteBucketPolicyDenySelf(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "deny-policy")
	b.SetBucketOwner("deny-policy", "minis3-access-key")

	ownerHeaders := map[string]string{"Authorization": authHeader("minis3-access-key")}

	// Set a policy that denies GetBucketPolicy and DeleteBucketPolicy for everyone.
	// Without ConfirmRemoveSelfBucketAccess, the owner is exempt from deny.
	denyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:GetBucketPolicy","s3:DeleteBucketPolicy"],"Resource":"arn:aws:s3:::deny-policy"}]}`
	wPut := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/deny-policy?policy",
			denyPolicy,
			ownerHeaders,
		),
	)
	requireStatus(t, wPut, http.StatusNoContent)

	t.Run("GET policy allowed for owner without ConfirmRemoveSelfBucketAccess", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/deny-policy?policy", "", ownerHeaders),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run(
		"DELETE policy allowed for owner without ConfirmRemoveSelfBucketAccess",
		func(t *testing.T) {
			// Re-set the policy first since delete clears it
			_ = b.PutBucketPolicy("deny-policy", denyPolicy, false)
			w := doRequest(
				h,
				newRequest(
					http.MethodDelete,
					"http://example.test/deny-policy?policy",
					"",
					ownerHeaders,
				),
			)
			requireStatus(t, w, http.StatusNoContent)
		},
	)

	t.Run("GET policy access denied for non-owner", func(t *testing.T) {
		_ = b.PutBucketPolicy("deny-policy", denyPolicy, false)
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/deny-policy?policy", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("DELETE policy access denied for non-owner", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/deny-policy?policy", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("owner denied with ConfirmRemoveSelfBucketAccess", func(t *testing.T) {
		// Set the policy with ConfirmRemoveSelfBucketAccess=true
		_ = b.PutBucketPolicy("deny-policy", denyPolicy, true)

		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/deny-policy?policy", "", ownerHeaders),
		)
		requireStatus(t, wGet, http.StatusForbidden)
		requireS3ErrorCode(t, wGet, "AccessDenied")

		wDel := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/deny-policy?policy",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wDel, http.StatusForbidden)
		requireS3ErrorCode(t, wDel, "AccessDenied")
	})
}

func TestBucketPolicyStatusBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "policy-status")
	b.SetBucketOwner("policy-status", "minis3-access-key")

	t.Run("access denied for non-owner", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/policy-status?policyStatus", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("missing bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such?policyStatus", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	ownerHeaders := map[string]string{"Authorization": authHeader("minis3-access-key")}

	t.Run("public acl contributes when ignorePublicAcls is false", func(t *testing.T) {
		if err := b.PutBucketPolicy(
			"policy-status",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":{"AWS":"arn:aws:iam::123456789012:user/u"},"Resource":"arn:aws:s3:::policy-status/*"}]}`,
			false,
		); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
		if err := b.PutBucketACL("policy-status", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		if err := b.PutPublicAccessBlock(
			"policy-status",
			&backend.PublicAccessBlockConfiguration{IgnorePublicAcls: false},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/policy-status?policyStatus",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, w, http.StatusOK)

		var ps backend.PolicyStatus
		if err := xml.Unmarshal(w.Body.Bytes(), &ps); err != nil {
			t.Fatalf("failed to decode policy status: %v body=%s", err, w.Body.String())
		}
		if !ps.IsPublic {
			t.Fatalf("expected IsPublic=true, got %+v", ps)
		}
	})

	t.Run("ignore public acls excludes acl contribution", func(t *testing.T) {
		if err := b.PutBucketPolicy(
			"policy-status",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Principal":{"AWS":"arn:aws:iam::123456789012:user/u"},"Resource":"arn:aws:s3:::policy-status/*"}]}`,
			false,
		); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
		if err := b.PutPublicAccessBlock(
			"policy-status",
			&backend.PublicAccessBlockConfiguration{IgnorePublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/policy-status?policyStatus",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, w, http.StatusOK)

		var ps backend.PolicyStatus
		if err := xml.Unmarshal(w.Body.Bytes(), &ps); err != nil {
			t.Fatalf("failed to decode policy status: %v body=%s", err, w.Body.String())
		}
		if ps.IsPublic {
			t.Fatalf("expected IsPublic=false, got %+v", ps)
		}
	})
}
