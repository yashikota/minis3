package handler

import (
	"net/http"
	"testing"
)

func TestBucketHTTPBranches(t *testing.T) {
	h, b := newTestHandler(t)

	t.Run("bucket acl get and acl method not allowed", func(t *testing.T) {
		mustCreateBucket(t, b, "acl-get-bucket")

		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/acl-get-bucket?acl", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)

		wMissing := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-bucket?acl", "", nil),
		)
		requireStatus(t, wMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wMissing, "NoSuchBucket")

		wMethod := doRequest(
			h,
			newRequest(http.MethodPost, "http://example.test/acl-get-bucket?acl", "", nil),
		)
		requireStatus(t, wMethod, http.StatusMethodNotAllowed)
		requireS3ErrorCode(t, wMethod, "MethodNotAllowed")
	})

	t.Run("create bucket malformed xml", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/malformed-bucket", "<bad", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("create bucket invalid name", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/Invalid_Name", "", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidBucketName")
	})

	t.Run("create bucket success with owner and canned acl then idempotent", func(t *testing.T) {
		headers := map[string]string{
			"Authorization": authHeader("minis3-access-key"),
			"x-amz-acl":     "public-read",
		}
		wCreate := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-branch-bucket", "", headers),
		)
		requireStatus(t, wCreate, http.StatusOK)
		if got := wCreate.Header().Get("Location"); got != "/create-branch-bucket" {
			t.Fatalf("unexpected location header: %q", got)
		}

		bucket, ok := b.GetBucket("create-branch-bucket")
		if !ok {
			t.Fatal("bucket should exist after create")
		}
		if bucket.OwnerAccessKey != "minis3-access-key" {
			t.Fatalf("unexpected owner: %q", bucket.OwnerAccessKey)
		}

		acl, err := b.GetBucketACL("create-branch-bucket")
		if err != nil {
			t.Fatalf("GetBucketACL failed: %v", err)
		}
		if !isPublicACL(acl) {
			t.Fatalf("expected public-read canned ACL, got %+v", acl)
		}

		wCreateAgain := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-branch-bucket", "", headers),
		)
		requireStatus(t, wCreateAgain, http.StatusOK)
	})

	t.Run("head bucket missing and read stats", func(t *testing.T) {
		wMissing := doRequest(
			h,
			newRequest(http.MethodHead, "http://example.test/no-such-head", "", nil),
		)
		requireStatus(t, wMissing, http.StatusNotFound)
		if got := wMissing.Header().Get("x-amz-bucket-region"); got != "us-east-1" {
			t.Fatalf("unexpected region header: %q", got)
		}

		mustCreateBucket(t, b, "head-stats-bucket")
		mustPutObject(t, b, "head-stats-bucket", "obj", "data")
		headStatsURL := "http://example.test/head-stats-bucket?read-stats=true"
		wStats := doRequest(
			h,
			newRequest(http.MethodHead, headStatsURL, "", nil),
		)
		requireStatus(t, wStats, http.StatusOK)
		if got := wStats.Header().Get("X-RGW-Object-Count"); got != "1" {
			t.Fatalf("unexpected object count header: %q", got)
		}
		if got := wStats.Header().Get("X-RGW-Bytes-Used"); got != "4" {
			t.Fatalf("unexpected bytes-used header: %q", got)
		}
	})

	t.Run("delete bucket not empty then success then missing", func(t *testing.T) {
		mustCreateBucket(t, b, "delete-branch-bucket")
		mustPutObject(t, b, "delete-branch-bucket", "obj", "data")

		wNotEmpty := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/delete-branch-bucket", "", nil),
		)
		requireStatus(t, wNotEmpty, http.StatusConflict)
		requireS3ErrorCode(t, wNotEmpty, "BucketNotEmpty")

		if _, err := b.DeleteObject("delete-branch-bucket", "obj", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}

		wDeleted := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/delete-branch-bucket", "", nil),
		)
		requireStatus(t, wDeleted, http.StatusNoContent)

		wMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/delete-branch-bucket", "", nil),
		)
		requireStatus(t, wMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wMissing, "NoSuchBucket")
	})

	t.Run("unsupported bucket method", func(t *testing.T) {
		mustCreateBucket(t, b, "method-branch-bucket")
		w := doRequest(
			h,
			newRequest(http.MethodPatch, "http://example.test/method-branch-bucket", "", nil),
		)
		requireStatus(t, w, http.StatusMethodNotAllowed)
		requireS3ErrorCode(t, w, "MethodNotAllowed")
	})
}

func TestPublicAccessBlockAccessBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "pab-branch")
	b.SetBucketOwner("pab-branch", "minis3-access-key")

	t.Run("access denied for anonymous get put delete", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/pab-branch?publicAccessBlock", "", nil),
		)
		requireStatus(t, wGet, http.StatusForbidden)
		requireS3ErrorCode(t, wGet, "AccessDenied")

		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/pab-branch?publicAccessBlock",
				`<PublicAccessBlockConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPut, http.StatusForbidden)
		requireS3ErrorCode(t, wPut, "AccessDenied")

		pabURL := "http://example.test/pab-branch?publicAccessBlock"
		wDelete := doRequest(
			h,
			newRequest(http.MethodDelete, pabURL, "", nil),
		)
		requireStatus(t, wDelete, http.StatusForbidden)
		requireS3ErrorCode(t, wDelete, "AccessDenied")
	})

	t.Run("malformed xml for put public access block", func(t *testing.T) {
		headers := map[string]string{"Authorization": authHeader("minis3-access-key")}
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/pab-branch?publicAccessBlock",
				"<bad",
				headers,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})
}
