package handler

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestDeleteObjectsResponseBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "delobj-branch")
	if err := b.SetBucketVersioning("delobj-branch", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	_, err := b.PutObject("delobj-branch", "normal", []byte("n"), backend.PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject(normal) failed: %v", err)
	}
	specificObj, err := b.PutObject(
		"delobj-branch",
		"specific",
		[]byte("s"),
		backend.PutObjectOptions{},
	)
	if err != nil {
		t.Fatalf("PutObject(specific) failed: %v", err)
	}
	retain := time.Now().UTC().Add(24 * time.Hour)
	lockedObj, err := b.PutObject(
		"delobj-branch",
		"locked",
		[]byte("l"),
		backend.PutObjectOptions{
			RetentionMode:   backend.RetentionModeCompliance,
			RetainUntilDate: &retain,
		},
	)
	if err != nil {
		t.Fatalf("PutObject(locked) failed: %v", err)
	}

	t.Run("request body read error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/delobj-branch?delete", nil)
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("mixed success and locked error result", func(t *testing.T) {
		body := fmt.Sprintf(
			"<Delete>"+
				"<Object><Key>locked</Key><VersionId>%s</VersionId></Object>"+
				"<Object><Key>normal</Key></Object>"+
				"<Object><Key>specific</Key><VersionId>%s</VersionId></Object>"+
				"</Delete>",
			lockedObj.VersionId,
			specificObj.VersionId,
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/delobj-branch?delete",
				body,
				map[string]string{"x-amz-bypass-governance-retention": "true"},
			),
		)
		requireStatus(t, w, http.StatusOK)

		var resp backend.DeleteResult
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse DeleteResult: %v body=%s", err, w.Body.String())
		}
		if len(resp.Errors) != 1 {
			t.Fatalf("expected exactly one error, got %+v", resp.Errors)
		}
		if resp.Errors[0].Code != "AccessDenied" {
			t.Fatalf("expected AccessDenied for locked object, got %+v", resp.Errors[0])
		}

		var normalDeleted *backend.DeletedObject
		var specificDeleted *backend.DeletedObject
		for i := range resp.Deleted {
			switch resp.Deleted[i].Key {
			case "normal":
				normalDeleted = &resp.Deleted[i]
			case "specific":
				specificDeleted = &resp.Deleted[i]
			}
		}
		if normalDeleted == nil || !normalDeleted.DeleteMarker ||
			normalDeleted.DeleteMarkerVersionId == "" {
			t.Fatalf("expected delete marker details for normal object, got %+v", normalDeleted)
		}
		if specificDeleted == nil || specificDeleted.VersionId != specificObj.VersionId {
			t.Fatalf("expected specific version to be deleted, got %+v", specificDeleted)
		}
	})

	t.Run("quiet delete omits deleted entries", func(t *testing.T) {
		mustPutObject(t, b, "delobj-branch", "quiet", "q")
		body := "<Delete><Quiet>true</Quiet><Object><Key>quiet</Key></Object></Delete>"
		w := doRequest(
			h,
			newRequest(http.MethodPost, "http://example.test/delobj-branch?delete", body, nil),
		)
		requireStatus(t, w, http.StatusOK)

		var resp backend.DeleteResult
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse quiet DeleteResult: %v body=%s", err, w.Body.String())
		}
		if len(resp.Deleted) != 0 {
			t.Fatalf("quiet delete should not include Deleted entries, got %+v", resp.Deleted)
		}
		if len(resp.Errors) != 0 {
			t.Fatalf("quiet delete should not include errors here, got %+v", resp.Errors)
		}
	})
}

func TestObjectACLBranchExpansion(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-acl-branch")
	b.SetBucketOwner("obj-acl-branch", "owner-ak")
	mustPutObject(t, b, "obj-acl-branch", "k", "v")

	t.Run("get acl access denied for non-owner", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-acl-branch/k?acl", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	ownerHeaders := map[string]string{"Authorization": authHeader("owner-ak")}

	t.Run("get acl no such bucket, key, version", func(t *testing.T) {
		wBucket := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-such-obj-acl/k?acl",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wBucket, "NoSuchBucket")

		wKey := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-acl-branch/missing?acl",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wKey, http.StatusNotFound)
		requireS3ErrorCode(t, wKey, "NoSuchKey")

		wVersion := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-acl-branch/k?acl&versionId=missing",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wVersion, "NoSuchVersion")
	})

	t.Run("put acl error branches and success", func(t *testing.T) {
		wDenied := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl",
				"",
				map[string]string{"x-amz-acl": "private"},
			),
		)
		requireStatus(t, wDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wDenied, "AccessDenied")

		if err := b.PutPublicAccessBlock(
			"obj-acl-branch",
			&backend.PublicAccessBlockConfiguration{BlockPublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		wBlocked := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl",
				"",
				map[string]string{
					"Authorization": authHeader("owner-ak"),
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, wBlocked, http.StatusForbidden)
		requireS3ErrorCode(t, wBlocked, "AccessDenied")
		if err := b.DeletePublicAccessBlock("obj-acl-branch"); err != nil {
			t.Fatalf("DeletePublicAccessBlock failed: %v", err)
		}

		wMissingKey := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/no-key?acl",
				"",
				map[string]string{
					"Authorization": authHeader("owner-ak"),
					"x-amz-acl":     "private",
				},
			),
		)
		requireStatus(t, wMissingKey, http.StatusNotFound)
		requireS3ErrorCode(t, wMissingKey, "NoSuchKey")

		wMissingVersion := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl&versionId=missing",
				"",
				map[string]string{
					"Authorization": authHeader("owner-ak"),
					"x-amz-acl":     "private",
				},
			),
		)
		requireStatus(t, wMissingVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wMissingVersion, "NoSuchVersion")

		reqReadErr := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/obj-acl-branch/k?acl",
			nil,
		)
		reqReadErr.Header.Set("Authorization", authHeader("owner-ak"))
		reqReadErr.Body = io.NopCloser(failingReader{})
		wReadErr := doRequest(h, reqReadErr)
		requireStatus(t, wReadErr, http.StatusBadRequest)
		requireS3ErrorCode(t, wReadErr, "InvalidRequest")

		wMalformed := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl",
				"<bad",
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, wMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wMalformed, "MalformedACLError")

		if err := b.PutPublicAccessBlock(
			"obj-acl-branch",
			&backend.PublicAccessBlockConfiguration{BlockPublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		publicACLXML := `<AccessControlPolicy><Owner><ID>` +
			`0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Owner>` +
			`<AccessControlList><Grant><Grantee xsi:type="Group" ` +
			`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><URI>` +
			backend.AllUsersURI +
			`</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>`
		wBodyBlocked := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl",
				publicACLXML,
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, wBodyBlocked, http.StatusForbidden)
		requireS3ErrorCode(t, wBodyBlocked, "AccessDenied")
		if err := b.DeletePublicAccessBlock("obj-acl-branch"); err != nil {
			t.Fatalf("DeletePublicAccessBlock failed: %v", err)
		}

		wSuccess := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-acl-branch/k?acl",
				"<AccessControlPolicy></AccessControlPolicy>",
				map[string]string{"Authorization": authHeader("owner-ak")},
			),
		)
		requireStatus(t, wSuccess, http.StatusOK)

		wGet := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-acl-branch/k?acl",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wGet, http.StatusOK)
	})

	t.Run("writePutObjectACLError maps known errors", func(t *testing.T) {
		cases := []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{
				name:   "bucket not found",
				err:    backend.ErrBucketNotFound,
				status: http.StatusNotFound,
				code:   "NoSuchBucket",
			},
			{
				name:   "object not found",
				err:    backend.ErrObjectNotFound,
				status: http.StatusNotFound,
				code:   "NoSuchKey",
			},
			{
				name:   "version not found",
				err:    backend.ErrVersionNotFound,
				status: http.StatusNotFound,
				code:   "NoSuchVersion",
			},
			{
				name:   "internal",
				err:    errors.New("boom"),
				status: http.StatusInternalServerError,
				code:   "InternalError",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				h.writePutObjectACLError(w, tc.err)
				requireStatus(t, w, tc.status)
				requireS3ErrorCode(t, w, tc.code)
			})
		}
	})
}

func TestListObjectsBranchExpansion(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "list-branch")
	b.SetBucketOwner("list-branch", "owner-ak")

	if _, err := b.PutObject(
		"list-branch",
		"root space.txt",
		[]byte("root"),
		backend.PutObjectOptions{ChecksumAlgorithm: "SHA256", ChecksumSHA256: "dummy"},
	); err != nil {
		t.Fatalf("PutObject(root space) failed: %v", err)
	}
	mustPutObject(t, b, "list-branch", "dir/a.txt", "a")
	mustPutObject(t, b, "list-branch", "dir/b.txt", "b")

	headers := map[string]string{"Authorization": authHeader("owner-ak")}

	t.Run("allow-unordered with delimiter is rejected for v2 and v1", func(t *testing.T) {
		wV2 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-branch?list-type=2&allow-unordered=true&delimiter=/",
				"",
				headers,
			),
		)
		requireStatus(t, wV2, http.StatusBadRequest)
		requireS3ErrorCode(t, wV2, "InvalidArgument")

		wV1 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-branch?allow-unordered=true&delimiter=/",
				"",
				headers,
			),
		)
		requireStatus(t, wV1, http.StatusBadRequest)
		requireS3ErrorCode(t, wV1, "InvalidArgument")
	})

	t.Run("v2 continuation token, owner, optional attrs and requester headers", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-branch?list-type=2&delimiter=/&encoding-type=url&continuation-token=&fetch-owner=true",
				"",
				map[string]string{
					"Authorization":                    authHeader("owner-ak"),
					"x-amz-request-payer":              "requester",
					"x-amz-optional-object-attributes": "ChecksumAlgorithm",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-request-charged"); got != "requester" {
			t.Fatalf("unexpected request charged header: %q", got)
		}

		var resp backend.ListBucketV2Result
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse ListBucketV2Result: %v body=%s", err, w.Body.String())
		}
		if resp.ContinuationToken == nil || *resp.ContinuationToken != "" {
			t.Fatalf("expected empty continuation token pointer, got %+v", resp.ContinuationToken)
		}
		if resp.EncodingType != "url" {
			t.Fatalf("expected EncodingType=url, got %q", resp.EncodingType)
		}
		if len(resp.Contents) != 1 {
			t.Fatalf("expected one top-level content, got %+v", resp.Contents)
		}
		if resp.Contents[0].Key != "root%20space.txt" {
			t.Fatalf("expected url-encoded key, got %q", resp.Contents[0].Key)
		}
		if resp.Contents[0].StorageClass != "STANDARD" {
			t.Fatalf(
				"expected default storage class STANDARD, got %q",
				resp.Contents[0].StorageClass,
			)
		}
		if resp.Contents[0].Owner == nil {
			t.Fatalf("expected owner in v2 contents, got %+v", resp.Contents[0])
		}
		if len(resp.Contents[0].ChecksumAlgorithm) != 1 ||
			resp.Contents[0].ChecksumAlgorithm[0] != "SHA256" {
			t.Fatalf(
				"expected checksum algorithm in optional attributes, got %+v",
				resp.Contents[0].ChecksumAlgorithm,
			)
		}
		if len(resp.CommonPrefixes) != 1 || resp.CommonPrefixes[0].Prefix != "dir/" {
			t.Fatalf("expected one common prefix dir/, got %+v", resp.CommonPrefixes)
		}
	})

	t.Run("v1 requester header and max-keys zero", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/list-branch?max-keys=0&encoding-type=url",
				"",
				map[string]string{
					"Authorization":       authHeader("owner-ak"),
					"x-amz-request-payer": "requester",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-request-charged"); got != "requester" {
			t.Fatalf("unexpected request charged header: %q", got)
		}

		var resp backend.ListBucketV1Result
		if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse ListBucketV1Result: %v body=%s", err, w.Body.String())
		}
		if len(resp.Contents) != 0 || len(resp.CommonPrefixes) != 0 {
			t.Fatalf(
				"max-keys=0 should return no entries, got contents=%+v prefixes=%+v",
				resp.Contents,
				resp.CommonPrefixes,
			)
		}
	})
}

func TestObjectTaggingAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "tag-branch")
	b.SetBucketOwner("tag-branch", "owner-ak")
	if err := b.SetBucketVersioning("tag-branch", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	mustPutObject(t, b, "tag-branch", "k", "v")

	t.Run("get and put tagging access denied for non-owner", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/tag-branch/k?tagging", "", nil),
		)
		requireStatus(t, wGet, http.StatusForbidden)
		requireS3ErrorCode(t, wGet, "AccessDenied")

		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/tag-branch/k?tagging",
				`<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`,
				nil,
			),
		)
		requireStatus(t, wPut, http.StatusForbidden)
		requireS3ErrorCode(t, wPut, "AccessDenied")
	})

	ownerHeaders := map[string]string{"Authorization": authHeader("owner-ak")}

	t.Run("put tagging read body error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://example.test/tag-branch/k?tagging", nil)
		req.Header.Set("Authorization", authHeader("owner-ak"))
		req.Body = io.NopCloser(failingReader{})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("put/get/delete tagging include version headers", func(t *testing.T) {
		putPayload := `<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`
		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/tag-branch/k?tagging",
				putPayload,
				ownerHeaders,
			),
		)
		requireStatus(t, wPut, http.StatusOK)
		putVersionID := wPut.Header().Get("x-amz-version-id")
		if putVersionID == "" {
			t.Fatal("expected x-amz-version-id on PutObjectTagging for versioned bucket")
		}

		wGet := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/tag-branch/k?tagging",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wGet, http.StatusOK)
		getVersionID := wGet.Header().Get("x-amz-version-id")
		if getVersionID == "" {
			t.Fatal("expected x-amz-version-id on GetObjectTagging for versioned bucket")
		}

		wDelete := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/tag-branch/k?tagging&versionId="+putVersionID,
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wDelete, http.StatusNoContent)
		if got := wDelete.Header().Get("x-amz-version-id"); got != putVersionID {
			t.Fatalf("unexpected delete tagging version header: got %q want %q", got, putVersionID)
		}
	})

	t.Run("object tagging error mapping for bucket, key, version", func(t *testing.T) {
		wNoBucket := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-such-tag-bucket/k?tagging",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wNoBucket, "NoSuchBucket")

		wNoKey := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/tag-branch/missing?tagging",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wNoKey, http.StatusNotFound)
		requireS3ErrorCode(t, wNoKey, "NoSuchKey")

		wNoVersion := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/tag-branch/k?tagging&versionId=missing",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wNoVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wNoVersion, "NoSuchVersion")
	})
}
