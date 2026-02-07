package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandlePutBucketACLBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "acl-bucket")
	b.SetBucketOwner("acl-bucket", "minis3-access-key")

	t.Run("access denied for non-owner", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/acl-bucket?acl",
				"",
				map[string]string{"x-amz-acl": "private"},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	headers := map[string]string{
		"Authorization": "AWS minis3-access-key:sig",
		"x-amz-acl":     "private",
	}
	t.Run("canned acl success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/acl-bucket?acl", "", headers),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("canned acl no such bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/missing?acl", "", headers),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("block public acls canned", func(t *testing.T) {
		if err := b.PutPublicAccessBlock(
			"acl-bucket",
			&backend.PublicAccessBlockConfiguration{BlockPublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/acl-bucket?acl",
				"",
				map[string]string{
					"Authorization": "AWS minis3-access-key:sig",
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("block public acls xml body", func(t *testing.T) {
		payload := `<AccessControlPolicy><Owner><ID>` +
			`0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Owner>` +
			`<AccessControlList><Grant><Grantee xsi:type="Group" ` +
			`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><URI>` +
			backend.AllUsersURI +
			`</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/acl-bucket?acl",
				payload,
				map[string]string{"Authorization": "AWS minis3-access-key:sig"},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})
}
