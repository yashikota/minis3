package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestObjectHelperUncoveredBranches(t *testing.T) {
	if got := parseTaggingHeader("&"); got != nil {
		t.Fatalf("parseTaggingHeader(\"&\") = %#v, want nil", got)
	}

	code, msg := validateTagSet([]backend.Tag{{
		Key:   "k",
		Value: strings.Repeat("v", maxTagValLength+1),
	}})
	if code != "InvalidTag" || msg == "" {
		t.Fatalf("validateTagSet long value = (%q,%q), want InvalidTag", code, msg)
	}

	h, _ := newTestHandler(t)
	w := httptest.NewRecorder()
	h.setLifecycleExpirationHeader(w, "bucket", "key", nil)
	if got := w.Header().Get("x-amz-expiration"); got != "" {
		t.Fatalf("unexpected lifecycle expiration header: %q", got)
	}

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.Header.Set(
		"x-amz-copy-source-if-unmodified-since",
		time.Now().Add(-2*time.Hour).UTC().Format(http.TimeFormat),
	)
	cond := evaluateCopySourceConditionals(req, &backend.Object{
		ETag:         "\"etag\"",
		LastModified: time.Now().UTC(),
	})
	if !cond.ShouldReturn || cond.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("unexpected copy-source conditional result: %+v", cond)
	}

	if !matchesETag("abc", "abc") {
		t.Fatal("matchesETag should match unquoted candidate and unquoted ETag")
	}

	if _, _, err := parseRangeHeader("bytes=-x", 10); err == nil {
		t.Fatal("parseRangeHeader should fail for invalid suffix")
	}
	if _, _, err := parseRangeHeader("bytes=1", 10); err == nil {
		t.Fatal("parseRangeHeader should fail when dash is missing")
	}
	if _, _, err := parseRangeHeader("bytes=10-", 10); err == nil {
		t.Fatal("parseRangeHeader should fail when start is out of range")
	}
	if _, _, err := parseRangeHeader("bytes=1-a", 10); err == nil {
		t.Fatal("parseRangeHeader should fail for invalid end")
	}
}

func TestHandleObjectPutAdditionalBranchesUncovered(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-put-branch")

	t.Run("put object with legal-hold and checksum headers then acl parse error", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/obj-put-branch/key",
			"body",
			map[string]string{
				"x-amz-object-lock-legal-hold": "ON",
				"x-amz-checksum-crc32":         "AAAAAA==",
				"x-amz-checksum-crc32c":        "AAAAAA==",
				"x-amz-checksum-sha1":          "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"x-amz-checksum-sha256":        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"x-amz-grant-read":             "badformat",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("put object ACL write failure after put", func(t *testing.T) {
		origPutACL := putObjectACLFn
		putObjectACLFn = func(*Handler, string, string, string, *backend.AccessControlPolicy) error {
			return errors.New("put object acl boom")
		}
		t.Cleanup(func() {
			putObjectACLFn = origPutACL
		})

		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/obj-put-branch/key2", "body", nil),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})
}

func TestHandleObjectReadDeleteHeadAdditionalBranchesUncovered(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-rdh")
	if err := b.SetBucketVersioning("obj-rdh", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	putReq := newRequest(
		http.MethodPut,
		"http://example.test/obj-rdh/k",
		"body",
		map[string]string{
			"x-amz-website-redirect-location": "/redirect",
			"x-amz-checksum-algorithm":        "CRC32",
			"x-amz-checksum-crc32":            "AAAAAA==",
		},
	)
	putW := doRequest(h, putReq)
	requireStatus(t, putW, http.StatusOK)
	versionID := putW.Header().Get("x-amz-version-id")
	if versionID == "" || versionID == backend.NullVersionId {
		t.Fatalf("expected non-null version id, got %q", versionID)
	}
	etag := putW.Header().Get("ETag")

	t.Run("get object missing key returns NoSuchKey", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj-rdh/missing", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("get object conditional 304 with version header", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/obj-rdh/k",
			"",
			map[string]string{"If-None-Match": etag},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotModified)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("x-amz-version-id should be set on conditional response")
		}
	})

	t.Run("get object normal path includes version and redirect headers", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj-rdh/k", "", nil))
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("x-amz-version-id should be set")
		}
		if got := w.Header().Get("x-amz-website-redirect-location"); got != "/redirect" {
			t.Fatalf("x-amz-website-redirect-location = %q, want /redirect", got)
		}
	})

	t.Run("delete denied by access check", func(t *testing.T) {
		b.SetBucketOwner("obj-rdh", "owner-ak")
		req := newRequest(
			http.MethodDelete,
			"http://example.test/obj-rdh/k",
			"",
			map[string]string{"Authorization": authHeader("other-ak")},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
		b.SetBucketOwner("obj-rdh", "")
	})

	t.Run("delete with unknown version returns NoSuchVersion", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/obj-rdh/k?versionId=nope",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("head denied by access check", func(t *testing.T) {
		b.SetBucketOwner("obj-rdh", "owner-ak")
		req := newRequest(
			http.MethodHead,
			"http://example.test/obj-rdh/k",
			"",
			map[string]string{"Authorization": authHeader("other-ak")},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
		b.SetBucketOwner("obj-rdh", "")
	})

	t.Run("head conditional 304 with version header", func(t *testing.T) {
		req := newRequest(
			http.MethodHead,
			"http://example.test/obj-rdh/k",
			"",
			map[string]string{"If-None-Match": etag},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotModified)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("x-amz-version-id should be set")
		}
	})

	t.Run("head normal path includes version checksum and redirect", func(t *testing.T) {
		req := newRequest(
			http.MethodHead,
			"http://example.test/obj-rdh/k",
			"",
			map[string]string{"x-amz-checksum-mode": "ENABLED"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("x-amz-version-id should be set")
		}
		if got := w.Header().Get("x-amz-website-redirect-location"); got != "/redirect" {
			t.Fatalf("x-amz-website-redirect-location = %q, want /redirect", got)
		}
		if got := w.Header().Get("x-amz-checksum-crc32"); got == "" {
			t.Fatal("checksum header should be present in HEAD response when enabled")
		}
	})

	t.Run("head invalid and missing part number", func(t *testing.T) {
		wInvalid := doRequest(
			h,
			newRequest(http.MethodHead, "http://example.test/obj-rdh/k?partNumber=abc", "", nil),
		)
		requireStatus(t, wInvalid, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalid, "InvalidArgument")

		wMissing := doRequest(
			h,
			newRequest(http.MethodHead, "http://example.test/obj-rdh/k?partNumber=99", "", nil),
		)
		requireStatus(t, wMissing, http.StatusBadRequest)
		requireS3ErrorCode(t, wMissing, "InvalidPart")
	})

	t.Run("sanity keep versioned object available", func(t *testing.T) {
		if versionID == "" {
			t.Fatal("versionID should not be empty")
		}
	})
}

func TestHandleCopyObjectAdditionalBranchesUncovered(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "copy-src")
	mustCreateBucket(t, b, "copy-dst")
	mustPutObject(t, b, "copy-src", "k", "data")

	t.Run("copy conditional source bucket not found", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out1",
			"",
			map[string]string{
				"x-amz-copy-source":          "/no-such-bucket/k",
				"x-amz-copy-source-if-match": "*",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("copy conditional source version not found", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out2",
			"",
			map[string]string{
				"x-amz-copy-source":                     "/copy-src/k?versionId=nope",
				"x-amz-copy-source-if-unmodified-since": time.Now().UTC().Format(http.TimeFormat),
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("copy conditional source key not found", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out2b",
			"",
			map[string]string{
				"x-amz-copy-source":          "/copy-src/missing",
				"x-amz-copy-source-if-match": "*",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("copy with copy options headers and grant parse error", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out3",
			"",
			map[string]string{
				"x-amz-copy-source":                               "/copy-src/k",
				"x-amz-object-lock-legal-hold":                    "ON",
				"x-amz-server-side-encryption":                    "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id":     "kms-key",
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key-md5":   "abc",
				"x-amz-grant-read":                                "badformat",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("copy with header ACL branch", func(t *testing.T) {
		owner := backend.OwnerForAccessKey("minis3-access-key")
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out4",
			"",
			map[string]string{
				"x-amz-copy-source": "/copy-src/k",
				"x-amz-grant-read":  "id=" + owner.ID,
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("copy blocked by public access block with canned ACL", func(t *testing.T) {
		if err := b.PutPublicAccessBlock(
			"copy-dst",
			&backend.PublicAccessBlockConfiguration{BlockPublicAcls: true},
		); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out5",
			"",
			map[string]string{
				"x-amz-copy-source": "/copy-src/k",
				"x-amz-acl":         "public-read",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("copy unexpected backend error", func(t *testing.T) {
		origCopy := copyObjectFn
		copyObjectFn = func(
			*Handler,
			string,
			string,
			string,
			string,
			string,
			backend.CopyObjectOptions,
		) (*backend.Object, string, error) {
			return nil, "", errors.New("copy boom")
		}
		t.Cleanup(func() {
			copyObjectFn = origCopy
		})

		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out6",
			"",
			map[string]string{"x-amz-copy-source": "/copy-src/k"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		copyObjectFn = origCopy
	})

	t.Run("copy put object ACL failure after copy", func(t *testing.T) {
		origCopy := copyObjectFn
		origPutACL := putObjectACLFn
		copyObjectFn = func(
			*Handler,
			string,
			string,
			string,
			string,
			string,
			backend.CopyObjectOptions,
		) (*backend.Object, string, error) {
			return &backend.Object{
				ETag:         "\"etag\"",
				LastModified: time.Now().UTC(),
				VersionId:    backend.NullVersionId,
			}, "", nil
		}
		putObjectACLFn = func(*Handler, string, string, string, *backend.AccessControlPolicy) error {
			return errors.New("put acl after copy boom")
		}
		t.Cleanup(func() {
			copyObjectFn = origCopy
			putObjectACLFn = origPutACL
		})

		req := newRequest(
			http.MethodPut,
			"http://example.test/copy-dst/out7",
			"",
			map[string]string{"x-amz-copy-source": "/copy-src/k"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		copyObjectFn = origCopy
		putObjectACLFn = origPutACL
	})
}

func TestObjectACLAndAttributesAdditionalBranchesUncovered(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-acl-attr")
	if err := b.SetBucketVersioning("obj-acl-attr", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	putReq := newRequest(
		http.MethodPut,
		"http://example.test/obj-acl-attr/k",
		"body",
		map[string]string{
			"x-amz-checksum-algorithm": "CRC32",
			"x-amz-checksum-crc32":     "AAAAAA==",
		},
	)
	putW := doRequest(h, putReq)
	requireStatus(t, putW, http.StatusOK)
	if got := putW.Header().Get("x-amz-version-id"); got == "" {
		t.Fatal("version id must be set")
	}

	t.Run("get object ACL internal error", func(t *testing.T) {
		orig := getObjectACLFn
		getObjectACLFn = func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
			return nil, errors.New("get acl boom")
		}
		t.Cleanup(func() {
			getObjectACLFn = orig
		})

		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-acl-attr/k?acl", "", nil),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		getObjectACLFn = orig
	})

	t.Run("put object ACL body path key not found", func(t *testing.T) {
		body := `<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/obj-acl-attr/missing?acl", body, nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("get object attributes checksum, storage default, and version header", func(t *testing.T) {
		obj, err := b.GetObject("obj-acl-attr", "k")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		obj.StorageClass = ""

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-acl-attr/k?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "Checksum,ObjectSize,StorageClass"},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-version-id"); got == "" {
			t.Fatal("x-amz-version-id should be set")
		}
		if !strings.Contains(w.Body.String(), "<Checksum>") {
			t.Fatalf("response should include Checksum block: %s", w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "<StorageClass>STANDARD</StorageClass>") {
			t.Fatalf("response should include default StorageClass: %s", w.Body.String())
		}
	})
}
