package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func patchReadAllForTest(t *testing.T, fn func(io.Reader) ([]byte, error)) {
	t.Helper()
	orig := readAllFn
	readAllFn = fn
	t.Cleanup(func() {
		readAllFn = orig
	})
}

func patchXMLMarshalForTest(t *testing.T, fn func(any) ([]byte, error)) {
	t.Helper()
	orig := xmlMarshalFn
	xmlMarshalFn = fn
	t.Cleanup(func() {
		xmlMarshalFn = orig
	})
}

func TestReadAllErrorHookBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "hook-bucket")
	mustPutObject(t, b, "hook-bucket", "obj", "value")
	mustCreateObjectLockBucket(t, b, "hook-lock")
	mustPutObject(t, b, "hook-lock", "obj", "value")

	patchReadAllForTest(t, func(io.Reader) ([]byte, error) {
		return nil, errors.New("read boom")
	})

	t.Run("bucket create body read error", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/new-hook-bucket", "<x/>", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("post form upload file read error", func(t *testing.T) {
		w := postMultipartForm(
			t,
			h,
			"http://example.test/hook-bucket",
			map[string]string{"key": "k"},
			"f.txt",
			"data",
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("bucket config body read errors", func(t *testing.T) {
		cases := []string{
			"http://example.test/hook-bucket?versioning",
			"http://example.test/hook-bucket?tagging",
			"http://example.test/hook-bucket?policy",
			"http://example.test/hook-bucket?lifecycle",
			"http://example.test/hook-bucket?encryption",
			"http://example.test/hook-bucket?cors",
			"http://example.test/hook-bucket?website",
			"http://example.test/hook-bucket?publicAccessBlock",
		}
		for _, target := range cases {
			w := doRequest(h, newRequest(http.MethodPut, target, "<x/>", nil))
			requireStatus(t, w, http.StatusBadRequest)
			requireS3ErrorCode(t, w, "InvalidRequest")
		}
	})

	t.Run("object body read errors", func(t *testing.T) {
		wACL := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/hook-bucket/obj?acl", "<x/>", nil),
		)
		requireStatus(t, wACL, http.StatusBadRequest)
		requireS3ErrorCode(t, wACL, "InvalidRequest")

		wTagging := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/hook-bucket/obj?tagging", "<x/>", nil),
		)
		requireStatus(t, wTagging, http.StatusBadRequest)
		requireS3ErrorCode(t, wTagging, "InvalidRequest")

		wDelete := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/hook-bucket?delete",
				`<Delete><Object><Key>obj</Key></Object></Delete>`,
				nil,
			),
		)
		requireStatus(t, wDelete, http.StatusBadRequest)
		requireS3ErrorCode(t, wDelete, "InvalidRequest")
	})

	t.Run("multipart body read errors", func(t *testing.T) {
		wUploadPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-bucket/mp?uploadId=u&partNumber=1",
				"part-data",
				nil,
			),
		)
		requireStatus(t, wUploadPart, http.StatusInternalServerError)
		requireS3ErrorCode(t, wUploadPart, "InternalError")

		wComplete := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/hook-bucket/mp?uploadId=u",
				`<CompleteMultipartUpload/>`,
				nil,
			),
		)
		requireStatus(t, wComplete, http.StatusBadRequest)
		requireS3ErrorCode(t, wComplete, "InvalidRequest")
	})

	t.Run("object lock body read errors", func(t *testing.T) {
		wConfig := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/hook-lock?object-lock", "<x/>", nil),
		)
		requireStatus(t, wConfig, http.StatusBadRequest)
		requireS3ErrorCode(t, wConfig, "InvalidRequest")

		wRetention := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-lock/obj?retention",
				"<x/>",
				nil,
			),
		)
		requireStatus(t, wRetention, http.StatusBadRequest)
		requireS3ErrorCode(t, wRetention, "InvalidRequest")

		wLegalHold := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/hook-lock/obj?legal-hold",
				"<x/>",
				nil,
			),
		)
		requireStatus(t, wLegalHold, http.StatusBadRequest)
		requireS3ErrorCode(t, wLegalHold, "InvalidRequest")
	})
}

func TestXMLMarshalErrorHookBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "marshal-bucket")
	mustCreateBucket(t, b, "marshal-src")
	mustCreateObjectLockBucket(t, b, "marshal-lock")
	mustPutObject(t, b, "marshal-bucket", "obj", "value")
	mustPutObject(t, b, "marshal-bucket", "delete-target", "value")
	mustPutObject(t, b, "marshal-src", "src", "copy")
	mustPutObject(t, b, "marshal-lock", "obj", "value")

	if err := b.SetBucketVersioning(
		"marshal-bucket",
		backend.VersioningEnabled,
		backend.MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if err := b.PutBucketTagging("marshal-bucket", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("PutBucketTagging failed: %v", err)
	}
	if err := b.PutBucketPolicy(
		"marshal-bucket",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::marshal-bucket/*"}]}`,
	); err != nil {
		t.Fatalf("PutBucketPolicy failed: %v", err)
	}
	if err := b.PutBucketLifecycleConfiguration(
		"marshal-bucket",
		&backend.LifecycleConfiguration{Rules: []backend.LifecycleRule{{
			ID:     "r",
			Status: backend.LifecycleStatusEnabled,
			Expiration: &backend.LifecycleExpiration{
				Days: 1,
			},
		}}},
	); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}
	if err := b.PutBucketEncryption(
		"marshal-bucket",
		&backend.ServerSideEncryptionConfiguration{
			Rules: []backend.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &backend.ServerSideEncryptionByDefault{
					SSEAlgorithm: "AES256",
				},
			}},
		},
	); err != nil {
		t.Fatalf("PutBucketEncryption failed: %v", err)
	}
	if err := b.PutBucketCORS(
		"marshal-bucket",
		&backend.CORSConfiguration{
			CORSRules: []backend.CORSRule{{
				AllowedMethods: []string{"GET"},
				AllowedOrigins: []string{"*"},
			}},
		},
	); err != nil {
		t.Fatalf("PutBucketCORS failed: %v", err)
	}
	if err := b.PutBucketWebsite(
		"marshal-bucket",
		&backend.WebsiteConfiguration{
			IndexDocument: &backend.IndexDocument{Suffix: "index.html"},
		},
	); err != nil {
		t.Fatalf("PutBucketWebsite failed: %v", err)
	}
	if err := b.PutPublicAccessBlock(
		"marshal-bucket",
		&backend.PublicAccessBlockConfiguration{},
	); err != nil {
		t.Fatalf("PutPublicAccessBlock failed: %v", err)
	}
	if _, err := b.PutObjectTagging("marshal-bucket", "obj", "", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("PutObjectTagging failed: %v", err)
	}

	uploadComplete, err := b.CreateMultipartUpload(
		"marshal-bucket",
		"mp-complete",
		backend.CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload complete failed: %v", err)
	}
	completePart, err := b.UploadPart(
		"marshal-bucket",
		"mp-complete",
		uploadComplete.UploadId,
		1,
		[]byte(strings.Repeat("a", 5*1024*1024)),
	)
	if err != nil {
		t.Fatalf("UploadPart complete failed: %v", err)
	}
	uploadList, err := b.CreateMultipartUpload(
		"marshal-bucket",
		"mp-list",
		backend.CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload list failed: %v", err)
	}
	if _, err := b.UploadPart(
		"marshal-bucket",
		"mp-list",
		uploadList.UploadId,
		1,
		[]byte("part"),
	); err != nil {
		t.Fatalf("UploadPart list failed: %v", err)
	}
	uploadCopy, err := b.CreateMultipartUpload(
		"marshal-bucket",
		"mp-copy",
		backend.CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload copy failed: %v", err)
	}

	if err := b.PutObjectLockConfiguration(
		"marshal-lock",
		&backend.ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
		},
	); err != nil {
		t.Fatalf("PutObjectLockConfiguration failed: %v", err)
	}
	if err := b.PutObjectRetention(
		"marshal-lock",
		"obj",
		"",
		&backend.ObjectLockRetention{
			Mode:            backend.RetentionModeGovernance,
			RetainUntilDate: "2099-01-01T00:00:00Z",
		},
		false,
	); err != nil {
		t.Fatalf("PutObjectRetention failed: %v", err)
	}
	if err := b.PutObjectLegalHold(
		"marshal-lock",
		"obj",
		"",
		&backend.ObjectLockLegalHold{Status: backend.LegalHoldStatusOn},
	); err != nil {
		t.Fatalf("PutObjectLegalHold failed: %v", err)
	}

	patchXMLMarshalForTest(t, func(any) ([]byte, error) {
		return nil, errors.New("marshal boom")
	})

	assertInternalError := func(t *testing.T, req *http.Request) {
		t.Helper()
		w := doRequest(h, req)
		if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 200 or 500, body=%s", w.Code, w.Body.String())
		}
		requireS3ErrorCode(t, w, "InternalError")
	}

	t.Run("service marshal error", func(t *testing.T) {
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/", "", nil))
	})

	t.Run("bucket marshal errors", func(t *testing.T) {
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?list-type=2", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?versions", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?versioning", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?location", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?tagging", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?policyStatus", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?acl", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?lifecycle", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?encryption", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?cors", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?website", "", nil))
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket?publicAccessBlock", "", nil))
	})

	t.Run("object marshal errors", func(t *testing.T) {
		assertInternalError(
			t,
			newRequest(
				http.MethodPost,
				"http://example.test/marshal-bucket?delete",
				`<Delete><Object><Key>delete-target</Key></Object></Delete>`,
				nil,
			),
		)
		assertInternalError(
			t,
			newRequest(
				http.MethodPut,
				"http://example.test/marshal-bucket/copied",
				"",
				map[string]string{"x-amz-copy-source": "/marshal-src/src"},
			),
		)
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-bucket/obj?acl", "", nil))
		assertInternalError(
			t,
			newRequest(http.MethodGet, "http://example.test/marshal-bucket/obj?tagging", "", nil),
		)
		assertInternalError(
			t,
			newRequest(
				http.MethodGet,
				"http://example.test/marshal-bucket/obj?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag,ObjectSize,StorageClass,Checksum"},
			),
		)
	})

	t.Run("multipart marshal errors", func(t *testing.T) {
		assertInternalError(
			t,
			newRequest(http.MethodPost, "http://example.test/marshal-bucket/mp-new?uploads", "", nil),
		)
		assertInternalError(
			t,
			newRequest(
				http.MethodPost,
				fmt.Sprintf(
					"http://example.test/marshal-bucket/mp-complete?uploadId=%s",
					uploadComplete.UploadId,
				),
				fmt.Sprintf(
					`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`,
					completePart.ETag,
				),
				nil,
			),
		)
		assertInternalError(
			t,
			newRequest(http.MethodGet, "http://example.test/marshal-bucket?uploads", "", nil),
		)
		assertInternalError(
			t,
			newRequest(
				http.MethodGet,
				fmt.Sprintf(
					"http://example.test/marshal-bucket/mp-list?uploadId=%s",
					uploadList.UploadId,
				),
				"",
				nil,
			),
		)
		assertInternalError(
			t,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/marshal-bucket/mp-copy?uploadId=%s&partNumber=1",
					uploadCopy.UploadId,
				),
				"",
				map[string]string{"x-amz-copy-source": "/marshal-src/src"},
			),
		)
	})

	t.Run("object lock marshal errors", func(t *testing.T) {
		assertInternalError(t, newRequest(http.MethodGet, "http://example.test/marshal-lock?object-lock", "", nil))
		assertInternalError(
			t,
			newRequest(http.MethodGet, "http://example.test/marshal-lock/obj?retention", "", nil),
		)
		assertInternalError(
			t,
			newRequest(http.MethodGet, "http://example.test/marshal-lock/obj?legal-hold", "", nil),
		)
	})
}
