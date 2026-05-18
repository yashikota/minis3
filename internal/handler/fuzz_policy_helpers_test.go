package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzPolicyResourceARN(f *testing.F) {
	f.Add("my-bucket", "key/path")
	f.Add("my-bucket", "")
	f.Add("tenant:bucket", "key")
	f.Add("", "")
	f.Add("bucket", "deep/nested/key/with/slashes")

	f.Fuzz(func(t *testing.T, bucketName, key string) {
		_ = policyResourceARN(bucketName, key)
	})
}

func FuzzOwnerBypassesObjectACL(f *testing.F) {
	f.Add("s3:GetObject")
	f.Add("s3:PutObject")
	f.Add("s3:GetObjectAcl")
	f.Add("s3:PutObjectAcl")
	f.Add("s3:DeleteObject")
	f.Add("")

	f.Fuzz(func(t *testing.T, action string) {
		_ = ownerBypassesObjectACL(action)
	})
}

func FuzzIsBucketPolicyAction(f *testing.F) {
	f.Add("s3:GetBucketPolicy")
	f.Add("s3:PutBucketPolicy")
	f.Add("s3:DeleteBucketPolicy")
	f.Add("s3:GetObject")
	f.Add("")

	f.Fuzz(func(t *testing.T, action string) {
		_ = isBucketPolicyAction(action)
	})
}

func FuzzIsPublicACL(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ")
	f.Add("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "WRITE")
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "FULL_CONTROL")
	f.Add("", "READ")
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ_ACP")

	f.Fuzz(func(t *testing.T, uri, perm string) {
		acl := &backend.AccessControlPolicy{
			AccessControlList: backend.AccessControlList{
				Grants: []backend.Grant{
					{
						Grantee:    &backend.Grantee{Type: "Group", URI: uri},
						Permission: perm,
					},
				},
			},
		}
		_ = isPublicACL(acl)
	})
}

func FuzzExtractPolicyHeaders(f *testing.F) {
	f.Add("x-amz-content-sha256", "abc123")
	f.Add("host", "s3.amazonaws.com")
	f.Add("content-type", "application/xml")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, headerName, headerValue string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if headerName != "" {
			req.Header.Set(headerName, headerValue)
		}
		_ = extractPolicyHeaders(req)
	})
}
