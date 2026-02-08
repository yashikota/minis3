package handler

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestCoverageGapAuthAndService(t *testing.T) {
	t.Run("verifyAuthorizationHeader v4 body read error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/bucket/key", nil)
		req.Host = "example.test"
		req.Body = io.NopCloser(failingReader{})
		req.Header.Set("x-amz-date", "20260208T000000Z")
		req.Header.Set(
			"Authorization",
			"AWS4-HMAC-SHA256 Credential=minis3-access-key/20260208/us-east-1/s3/aws4_request, "+
				"SignedHeaders=host;x-amz-date, Signature=deadbeef",
		)

		err := verifyAuthorizationHeader(req)
		requirePresignedErrCode(t, err, "AccessDenied")
	})

	t.Run("handleService owner and prefix filter continue branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "alpha")
		mustCreateBucket(t, b, "beta")
		b.SetBucketOwner("alpha", "minis3-access-key")
		b.SetBucketOwner("beta", "root-access-key")

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/?prefix=zzz",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if body := w.Body.String(); body == "" {
			t.Fatal("expected XML response body")
		}
	})
}

func TestCoverageGapBucketHelpersAndCreateBranches(t *testing.T) {
	t.Run("bucket helper branch fill", func(t *testing.T) {
		if !wildcardMatch("a**c", "ac") {
			t.Fatal("a**c should match ac")
		}
		if !wildcardMatch("a*b*c", "axbyc") {
			t.Fatal("a*b*c should match axbyc")
		}
		if wildcardMatch("a*b*c", "axc") {
			t.Fatal("a*b*c should not match axc")
		}
		if got := qualifiedBucketARN("bucket", "obj"); got != "arn:aws:s3:::bucket/obj" {
			t.Fatalf("qualifiedBucketARN(bucket,obj) = %q", got)
		}
		if got := qualifiedBucketARN("tenant:bucket", ""); got != "arn:aws:s3::tenant:bucket" {
			t.Fatalf("qualifiedBucketARN(tenant:bucket) = %q", got)
		}

		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "src-h")
		mustCreateBucket(t, b, "dst-h")
		if got := h.resolveLoggingTargetBucketName("tenant-access-key", " "); got != "" {
			t.Fatalf("resolveLoggingTargetBucketName(empty) = %q, want empty", got)
		}
		mustPutBucketPolicy(t, b, "dst-h", `{"Statement":["not-map"]}`)
		if ok, code := h.bucketLoggingTargetAllowed("src-h", "dst-h", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("bucketLoggingTargetAllowed invalid statement elem = (%v,%q)", ok, code)
		}

		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{{
				ID:     "r1",
				Status: backend.LifecycleStatusEnabled,
				NoncurrentVersionTransition: []backend.NoncurrentVersionTransition{{
					NoncurrentDays:          1,
					NewerNoncurrentVersions: -1,
					StorageClass:            "STANDARD_IA",
				}},
			}},
		}
		if code, _, ok := validateLifecycleConfiguration(cfg); ok || code != "InvalidArgument" {
			t.Fatalf(
				"validateLifecycleConfiguration negative newer versions = (%s,%v), want InvalidArgument,false",
				code,
				ok,
			)
		}
	})

	t.Run("create bucket ownership and acl branches", func(t *testing.T) {
		h, b := newTestHandler(t)

		wInvalidOwnership := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-own-invalid",
				"",
				map[string]string{
					"Authorization":          authHeader("minis3-access-key"),
					"x-amz-object-ownership": "invalid",
				},
			),
		)
		requireStatus(t, wInvalidOwnership, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalidOwnership, "InvalidArgument")

		wEnforcedACL := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-own-enforced",
				"",
				map[string]string{
					"Authorization":          authHeader("minis3-access-key"),
					"x-amz-object-ownership": backend.ObjectOwnershipBucketOwnerEnforced,
					"x-amz-acl":              "public-read",
				},
			),
		)
		requireStatus(t, wEnforcedACL, http.StatusBadRequest)
		requireS3ErrorCode(t, wEnforcedACL, "AccessControlListNotSupported")

		origCreateBucket := createBucketFn
		createBucketFn = func(*Handler, string) error {
			return nil
		}
		t.Cleanup(func() {
			createBucketFn = origCreateBucket
		})
		wLocationErr := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-location-fail",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wLocationErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wLocationErr, "InternalError")
		createBucketFn = origCreateBucket

		origPutBucketACL := putBucketACLFn
		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			return backend.ErrAccessControlListNotSupported
		}
		t.Cleanup(func() {
			putBucketACLFn = origPutBucketACL
		})

		wCreateACL := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-create-acl-fail",
				"",
				map[string]string{
					"Authorization": authHeader("minis3-access-key"),
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, wCreateACL, http.StatusBadRequest)
		requireS3ErrorCode(t, wCreateACL, "AccessControlListNotSupported")

		mustCreateBucket(t, b, "bucket-put-acl")
		b.SetBucketOwner("bucket-put-acl", "minis3-access-key")

		wPutCanned := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-put-acl?acl",
				"",
				map[string]string{
					"Authorization": authHeader("minis3-access-key"),
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, wPutCanned, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutCanned, "AccessControlListNotSupported")

		bodyACL := backend.NewDefaultACLForOwner(backend.OwnerForAccessKey("minis3-access-key"))
		bodyBytes, err := xml.Marshal(bodyACL)
		if err != nil {
			t.Fatalf("xml.Marshal ACL failed: %v", err)
		}
		wPutBody := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-put-acl?acl",
				string(bodyBytes),
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutBody, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutBody, "AccessControlListNotSupported")
		putBucketACLFn = origPutBucketACL
	})
}

func TestCoverageGapMultipartBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustPublicWriteBucket(t, b, "mp-gap", "minis3-access-key")

	t.Run("computeCompositeChecksum sha1 path", func(t *testing.T) {
		if got, ok := computeCompositeChecksum("SHA1", []string{"AAAAAA=="}); !ok || got == "" {
			t.Fatalf("computeCompositeChecksum(SHA1) = (%q,%v), want non-empty,true", got, ok)
		}
	})

	t.Run("create multipart ownership and checksum header branches", func(t *testing.T) {
		if err := b.PutBucketACL("mp-gap", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL mp-gap private failed: %v", err)
		}
		if err := b.PutBucketOwnershipControls("mp-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls enforced failed: %v", err)
		}
		wACLNotSupported := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/e1?uploads",
				"",
				map[string]string{
					"Authorization": authHeader("minis3-access-key"),
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, wACLNotSupported, http.StatusBadRequest)
		requireS3ErrorCode(t, wACLNotSupported, "AccessControlListNotSupported")

		if err := b.PutBucketOwnershipControls("mp-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerPreferred}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls preferred failed: %v", err)
		}
		wCreate := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/ok?uploads",
				"",
				map[string]string{
					"Authorization":                authHeader("minis3-access-key"),
					"x-amz-acl":                    string(backend.ACLBucketOwnerFull),
					"x-amz-sdk-checksum-algorithm": "SHA256",
					"x-amz-checksum-type":          "FULL_OBJECT",
					"x-amz-checksum-crc32":         "c1",
					"x-amz-checksum-crc32c":        "c2",
					"x-amz-checksum-crc64nvme":     "c3",
					"x-amz-checksum-sha1":          "c4",
					"x-amz-checksum-sha256":        "c5",
					"x-amz-object-lock-legal-hold": "ON",
					"x-amz-storage-class":          "STANDARD_IA",
					"x-amz-object-lock-mode":       backend.RetentionModeGovernance,
					"x-amz-object-lock-retain-until-date": time.Now().
						UTC().
						Add(24 * time.Hour).
						Format(
							time.RFC3339,
						),
				},
			),
		)
		requireStatus(t, wCreate, http.StatusOK)
		if got := wCreate.Header().Get("x-amz-checksum-algorithm"); got != "SHA256" {
			t.Fatalf("x-amz-checksum-algorithm = %q, want SHA256", got)
		}
		if got := wCreate.Header().Get("x-amz-checksum-type"); got != "FULL_OBJECT" {
			t.Fatalf("x-amz-checksum-type = %q, want FULL_OBJECT", got)
		}
	})

	t.Run("upload part emits checksum headers from part info", func(t *testing.T) {
		origUploadPart := uploadPartFn
		uploadPartFn = func(*Handler, string, string, string, int, []byte) (*backend.PartInfo, error) {
			return &backend.PartInfo{
				ETag:              "\"etag\"",
				ChecksumCRC32:     "a",
				ChecksumCRC32C:    "b",
				ChecksumCRC64NVME: "c",
				ChecksumSHA1:      "d",
				ChecksumSHA256:    "e",
			}, nil
		}
		t.Cleanup(func() {
			uploadPartFn = origUploadPart
		})
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/mp-gap/u?uploadId=fake&partNumber=1",
				"p",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-checksum-crc64nvme"); got != "c" {
			t.Fatalf("x-amz-checksum-crc64nvme = %q, want c", got)
		}
		if got := w.Header().Get("x-amz-checksum-sha1"); got != "d" {
			t.Fatalf("x-amz-checksum-sha1 = %q, want d", got)
		}
		if got := w.Header().Get("x-amz-checksum-sha256"); got != "e" {
			t.Fatalf("x-amz-checksum-sha256 = %q, want e", got)
		}
		uploadPartFn = origUploadPart
	})

	t.Run("complete multipart preconditions and checksum branches", func(t *testing.T) {
		completeBody := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`

		wIfMatchNoObj := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/noobj?uploadId=u1",
				completeBody,
				map[string]string{"If-Match": `"etag"`},
			),
		)
		requireStatus(t, wIfMatchNoObj, http.StatusNotFound)
		requireS3ErrorCode(t, wIfMatchNoObj, "NoSuchKey")

		mustPutObject(t, b, "mp-gap", "exists", "v")
		wIfMatchMismatch := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/exists?uploadId=u2",
				completeBody,
				map[string]string{"If-Match": `"other"`},
			),
		)
		requireStatus(t, wIfMatchMismatch, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, wIfMatchMismatch, "PreconditionFailed")

		obj, err := b.GetObject("mp-gap", "exists")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		wIfNoneMatch := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/exists?uploadId=u3",
				completeBody,
				map[string]string{"If-None-Match": obj.ETag},
			),
		)
		requireStatus(t, wIfNoneMatch, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, wIfNoneMatch, "PreconditionFailed")

		uploadID := createMultipartUpload(
			t,
			h,
			"mp-gap",
			"checksum",
			map[string]string{
				"Authorization":                authHeader("minis3-access-key"),
				"x-amz-checksum-algorithm":     "SHA256",
				"x-amz-sdk-checksum-algorithm": "SHA256",
			},
		)
		wPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-gap/checksum?uploadId=%s&partNumber=1",
					uploadID,
				),
				"part",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart, http.StatusOK)
		partETag := wPart.Header().Get("ETag")

		wBadPartDigest := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-gap/checksum?uploadId=%s", uploadID),
				`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+partETag+`</ETag><ChecksumSHA256>bad</ChecksumSHA256></Part></CompleteMultipartUpload>`,
				nil,
			),
		)
		requireStatus(t, wBadPartDigest, http.StatusBadRequest)
		requireS3ErrorCode(t, wBadPartDigest, "BadDigest")

		uploadID2 := createMultipartUpload(
			t,
			h,
			"mp-gap",
			"checksum2",
			map[string]string{
				"Authorization":            authHeader("minis3-access-key"),
				"x-amz-checksum-algorithm": "SHA256",
			},
		)
		wPart2 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-gap/checksum2?uploadId=%s&partNumber=1",
					uploadID2,
				),
				"part-2",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart2, http.StatusOK)
		partETag2 := wPart2.Header().Get("ETag")

		wHeaderBadDigest := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-gap/checksum2?uploadId=%s", uploadID2),
				`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+partETag2+`</ETag></Part></CompleteMultipartUpload>`,
				map[string]string{"x-amz-checksum-sha256": "wrong"},
			),
		)
		requireStatus(t, wHeaderBadDigest, http.StatusBadRequest)
		requireS3ErrorCode(t, wHeaderBadDigest, "BadDigest")

		uploadID3 := createMultipartUpload(
			t,
			h,
			"mp-gap",
			"missing-part",
			map[string]string{
				"Authorization":            authHeader("minis3-access-key"),
				"x-amz-checksum-algorithm": "SHA256",
			},
		)
		wMissingPart := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-gap/missing-part?uploadId=%s", uploadID3),
				`<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`,
				nil,
			),
		)
		requireStatus(t, wMissingPart, http.StatusBadRequest)
		requireS3ErrorCode(t, wMissingPart, "InvalidPart")

		uploadID4 := createMultipartUpload(
			t,
			h,
			"mp-gap",
			"unknown-algo",
			map[string]string{
				"Authorization":            authHeader("minis3-access-key"),
				"x-amz-checksum-algorithm": "SHA256",
			},
		)
		wPart4 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-gap/unknown-algo?uploadId=%s&partNumber=1",
					uploadID4,
				),
				"part-4",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart4, http.StatusOK)
		if up, ok := b.GetUpload(uploadID4); ok {
			up.ChecksumAlgorithm = "UNKNOWN"
		}
		partETag4 := wPart4.Header().Get("ETag")
		wUnknownAlgo := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-gap/unknown-algo?uploadId=%s", uploadID4),
				`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+partETag4+`</ETag></Part></CompleteMultipartUpload>`,
				nil,
			),
		)
		requireStatus(t, wUnknownAlgo, http.StatusOK)

		origComplete := completeMultipartUploadFn
		completeMultipartUploadFn = func(*Handler, string, string, string, []backend.CompletePart) (*backend.Object, error) {
			return nil, backend.ErrBadDigest
		}
		t.Cleanup(func() {
			completeMultipartUploadFn = origComplete
		})
		wCompleteBadDigest := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-gap/complete-hook?uploadId=u-hook",
				completeBody,
				nil,
			),
		)
		requireStatus(t, wCompleteBadDigest, http.StatusBadRequest)
		requireS3ErrorCode(t, wCompleteBadDigest, "BadDigest")
		completeMultipartUploadFn = origComplete
	})
}

func TestCoverageGapObjectBranches(t *testing.T) {
	t.Run("checksum response helpers and torrent", func(t *testing.T) {
		w := httptest.NewRecorder()
		setChecksumResponseHeaders(w, &backend.Object{
			ChecksumType:      "FULL_OBJECT",
			ChecksumCRC64NVME: "crc64",
		})
		if got := w.Header().Get("x-amz-checksum-type"); got != "FULL_OBJECT" {
			t.Fatalf("x-amz-checksum-type = %q, want FULL_OBJECT", got)
		}
		if got := w.Header().Get("x-amz-checksum-crc64nvme"); got != "crc64" {
			t.Fatalf("x-amz-checksum-crc64nvme = %q, want crc64", got)
		}
		setPartChecksumResponseHeaders(w, "FULL_OBJECT", nil)

		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-gap")
		mustPutObject(t, b, "obj-gap", "k", "v")
		wTorrent := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj-gap/k?torrent", "", nil),
		)
		requireStatus(t, wTorrent, http.StatusNotFound)
		requireS3ErrorCode(t, wTorrent, "NoSuchKey")
	})

	t.Run("put object and copy acl branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-put")
		b.SetBucketOwner("obj-put", "minis3-access-key")
		if err := b.PutBucketACL("obj-put", backend.CannedACLToPolicy("public-read-write")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		if err := b.PutBucketACL("obj-put", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL obj-put private failed: %v", err)
		}

		if err := b.PutBucketOwnershipControls("obj-put", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls enforced failed: %v", err)
		}
		wPutDenied := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put/a",
				"v",
				map[string]string{
					"Authorization": authHeader("minis3-access-key"),
					"x-amz-acl":     "public-read",
				},
			),
		)
		requireStatus(t, wPutDenied, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutDenied, "AccessControlListNotSupported")

		if err := b.PutBucketOwnershipControls("obj-put", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerPreferred}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls preferred failed: %v", err)
		}
		wPutOK := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put/b",
				"v",
				map[string]string{
					"Authorization":            authHeader("minis3-access-key"),
					"x-amz-acl":                string(backend.ACLBucketOwnerFull),
					"x-amz-checksum-crc64nvme": "crc64",
					"x-amz-checksum-sha1":      "sha1",
				},
			),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		origPutObject := putObjectFn
		putObjectFn = func(*Handler, string, string, []byte, backend.PutObjectOptions) (*backend.Object, error) {
			return nil, backend.ErrBadDigest
		}
		t.Cleanup(func() {
			putObjectFn = origPutObject
		})
		wPutBadDigest := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-put/c",
				"v",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutBadDigest, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutBadDigest, "BadDigest")
		putObjectFn = origPutObject

		mustCreateBucket(t, b, "src-copy-gap")
		mustPutObject(t, b, "src-copy-gap", "k", "v")
		if err := b.PutObjectACL("src-copy-gap", "k", "", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutObjectACL source failed: %v", err)
		}

		mustCreateBucket(t, b, "dst-copy-gap")
		b.SetBucketOwner("dst-copy-gap", "minis3-access-key")
		if err := b.PutBucketACL("dst-copy-gap", backend.CannedACLToPolicy("public-read-write")); err != nil {
			t.Fatalf("PutBucketACL dst failed: %v", err)
		}
		if err := b.PutBucketACL("dst-copy-gap", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL dst private failed: %v", err)
		}
		if err := b.PutBucketOwnershipControls("dst-copy-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls dst enforced failed: %v", err)
		}
		wCopyDenied := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-copy-gap/k",
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-copy-gap/k",
					"x-amz-acl":         "public-read",
				},
			),
		)
		requireStatus(t, wCopyDenied, http.StatusBadRequest)
		requireS3ErrorCode(t, wCopyDenied, "AccessControlListNotSupported")

		if err := b.PutBucketOwnershipControls("dst-copy-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipObjectWriter}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls dst writer failed: %v", err)
		}
		origPutObjectACL := putObjectACLFn
		putObjectACLFn = func(*Handler, string, string, string, *backend.AccessControlPolicy) error {
			return backend.ErrAccessControlListNotSupported
		}
		t.Cleanup(func() {
			putObjectACLFn = origPutObjectACL
		})
		wCopyACLFail := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-copy-gap/k2",
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-copy-gap/k",
				},
			),
		)
		requireStatus(t, wCopyACLFail, http.StatusBadRequest)
		requireS3ErrorCode(t, wCopyACLFail, "AccessControlListNotSupported")
		putObjectACLFn = origPutObjectACL

		rec := httptest.NewRecorder()
		h.writePutObjectACLError(rec, backend.ErrAccessControlListNotSupported)
		requireStatus(t, rec, http.StatusBadRequest)
		requireS3ErrorCode(t, rec, "AccessControlListNotSupported")
	})

	t.Run("delete objects and get object attributes branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-attrs-gap")
		mustPutObject(t, b, "obj-attrs-gap", "k", "abc")
		if err := b.SetBucketVersioning(
			"obj-attrs-gap",
			backend.VersioningEnabled,
			backend.MFADeleteDisabled,
		); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if _, err := b.DeleteObject("obj-attrs-gap", "only-delete-marker", false); err != nil {
			t.Fatalf("DeleteObject only-delete-marker failed: %v", err)
		}

		wDeleteWithPrecond := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/obj-attrs-gap/only-delete-marker",
				"",
				map[string]string{"If-Match": `"mismatch"`},
			),
		)
		requireStatus(t, wDeleteWithPrecond, http.StatusNoContent)

		mustPutObject(t, b, "obj-attrs-gap", "precond", "v")
		wDeletePrecondFail := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/obj-attrs-gap/precond",
				"",
				map[string]string{"If-Match": `"other"`},
			),
		)
		requireStatus(t, wDeletePrecondFail, http.StatusPreconditionFailed)
		requireS3ErrorCode(t, wDeletePrecondFail, "PreconditionFailed")

		etagMismatchBody := `<Delete><Object><Key></Key></Object><Object><Key>precond</Key><ETag>"other"</ETag></Object></Delete>`
		wDeleteObjects := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/obj-attrs-gap?delete",
				etagMismatchBody,
				nil,
			),
		)
		requireStatus(t, wDeleteObjects, http.StatusOK)
		if !bytes.Contains(wDeleteObjects.Body.Bytes(), []byte("<Code>PreconditionFailed</Code>")) {
			t.Fatalf(
				"expected PreconditionFailed in DeleteObjects response: %s",
				wDeleteObjects.Body.String(),
			)
		}

		obj, err := b.GetObject("obj-attrs-gap", "k")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		obj.Parts = []backend.ObjectPart{{
			PartNumber:        1,
			Size:              10,
			ChecksumCRC32:     "c1",
			ChecksumCRC32C:    "c2",
			ChecksumCRC64NVME: "c3",
			ChecksumSHA1:      "c4",
			ChecksumSHA256:    "c5",
		}}

		wAttrsHeaderFallback := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-attrs-gap/k?attributes",
				"",
				map[string]string{
					"x-amz-object-attributes":  "ObjectParts,Checksum",
					"x-amz-max-parts":          "0",
					"x-amz-part-number-marker": "0",
				},
			),
		)
		requireStatus(t, wAttrsHeaderFallback, http.StatusOK)
		if !bytes.Contains(wAttrsHeaderFallback.Body.Bytes(), []byte("<ObjectParts>")) {
			t.Fatalf(
				"expected ObjectParts in attributes response: %s",
				wAttrsHeaderFallback.Body.String(),
			)
		}

		wAttrsMarkerLoop := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-attrs-gap/k?attributes",
				"",
				map[string]string{
					"x-amz-object-attributes":  "ObjectParts",
					"x-amz-part-number-marker": "1",
				},
			),
		)
		requireStatus(t, wAttrsMarkerLoop, http.StatusOK)
	})
}

func TestCoverageGapRemainingServiceHandlerBucketMultipartObject(t *testing.T) {
	t.Run("service iam fallback and marshal branches", func(t *testing.T) {
		h, _ := newTestHandler(t)

		origOwner := ownerForAccessKeyFn
		origMarshal := xmlMarshalFn
		t.Cleanup(func() {
			ownerForAccessKeyFn = origOwner
			xmlMarshalFn = origMarshal
		})

		ownerForAccessKeyFn = func(string) *backend.Owner { return nil }
		wNilOwner := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/?Action=GetUser", "", map[string]string{
				"Authorization": authHeader("unknown"),
			}),
		)
		requireStatus(t, wNilOwner, http.StatusOK)

		ownerForAccessKeyFn = func(string) *backend.Owner {
			return &backend.Owner{ID: "id-only", DisplayName: ""}
		}
		wEmptyName := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/?Action=GetUser", "", map[string]string{
				"Authorization": authHeader("unknown"),
			}),
		)
		requireStatus(t, wEmptyName, http.StatusOK)
		if !bytes.Contains(wEmptyName.Body.Bytes(), []byte("<UserName>user</UserName>")) {
			t.Fatalf("expected fallback username in body: %s", wEmptyName.Body.String())
		}

		ownerForAccessKeyFn = origOwner
		xmlMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
		wMarshalErr := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/?Action=GetUser", "", map[string]string{
				"Authorization": authHeader("iam-access-key"),
			}),
		)
		requireS3ErrorCode(t, wMarshalErr, "InternalError")
	})

	t.Run("handler logging and checkAccess remaining branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "src-h2")
		mustCreateBucket(t, b, "dst-h2")
		b.SetBucketOwner("src-h2", "minis3-access-key")
		b.SetBucketOwner("dst-h2", "minis3-access-key")
		owner := backend.OwnerForAccessKey("minis3-access-key")
		if owner == nil {
			t.Fatal("owner must not be nil")
		}
		mustPutBucketPolicy(
			t,
			b,
			"dst-h2",
			allowLoggingPolicy("src-h2", "dst-h2", "logs/", owner.ID),
		)

		origOwner := ownerForAccessKeyFn
		origGetBucketForLogging := getBucketForLoggingFn
		origRequestURI := requestURIForLoggingFn
		origGetBucketLogging := getBucketLoggingFn
		origGetBucketACL := getBucketACLForAccessCheckFn
		t.Cleanup(func() {
			ownerForAccessKeyFn = origOwner
			getBucketForLoggingFn = origGetBucketForLogging
			requestURIForLoggingFn = origRequestURI
			getBucketLoggingFn = origGetBucketLogging
			getBucketACLForAccessCheckFn = origGetBucketACL
		})

		ownerForAccessKeyFn = func(string) *backend.Owner { return nil }
		if got := tenantFromAccessKey("tenant-access-key"); got != "" {
			t.Fatalf("tenantFromAccessKey with nil owner = %q, want empty", got)
		}
		ownerForAccessKeyFn = origOwner

		getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
			return &backend.BucketLoggingStatus{
				LoggingEnabled: &backend.LoggingEnabled{
					TargetBucket: "dst-h2",
					TargetPrefix: "logs/",
				},
			}, nil
		}
		getBucketForLoggingFn = func(*Handler, string) (*backend.Bucket, bool) {
			return nil, false
		}
		reqMissingSrc := newRequest(http.MethodGet, "http://example.test/src-h2/k", "", nil)
		h.emitServerAccessLog(reqMissingSrc, http.StatusOK, 1, "r", "h")
		getBucketForLoggingFn = origGetBucketForLogging

		getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
			return &backend.BucketLoggingStatus{
				LoggingEnabled: &backend.LoggingEnabled{
					TargetBucket: "",
					TargetPrefix: "logs/",
				},
			}, nil
		}
		reqEmptyTarget := newRequest(http.MethodGet, "http://example.test/src-h2/k", "", nil)
		h.emitServerAccessLog(reqEmptyTarget, http.StatusOK, 1, "r", "h")

		getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
			return &backend.BucketLoggingStatus{
				LoggingEnabled: &backend.LoggingEnabled{
					TargetBucket: "dst-h2",
					TargetPrefix: "logs/",
				},
			}, nil
		}
		requestURIForLoggingFn = func(*http.Request) string { return "" }
		reqEmit := newRequest(
			http.MethodGet,
			"http://example.test/src-h2/k?X-Amz-Signature=s",
			"",
			nil,
		)
		reqEmit.RemoteAddr = ""
		h.emitServerAccessLog(reqEmit, http.StatusOK, 1, "r", "h")
		requestURIForLoggingFn = origRequestURI

		getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
			return &backend.BucketLoggingStatus{
				LoggingEnabled: &backend.LoggingEnabled{
					TargetBucket: "dst-h2",
					TargetPrefix: "logs/",
					TargetObjectKeyFormat: &backend.TargetObjectKeyFormat{
						PartitionedPrefix: &backend.PartitionedPrefix{
							PartitionDateSource: "DeliveryTime",
						},
					},
				},
			}, nil
		}
		reqPartitioned := newRequest(http.MethodGet, "http://example.test/src-h2/k", "", nil)
		reqPartitioned.RemoteAddr = ""
		h.emitServerAccessLog(reqPartitioned, http.StatusOK, 1, "r", "h")
		getBucketLoggingFn = origGetBucketLogging

		// not-due branch
		h.loggingMu.Lock()
		h.pendingLogBatches["not-due"] = &serverAccessLogBatch{
			TargetBucket: "dst-h2",
			TargetPrefix: "logs/",
			FirstEventAt: time.Now().UTC(),
			Entries: []serverAccessLogEntry{{
				SourceBucket: "src-h2",
				Line:         "l",
			}},
		}
		h.loggingMu.Unlock()
		if err := h.flushServerAccessLogsIfDue("src-h2"); err != nil {
			t.Fatalf("flush not-due failed: %v", err)
		}

		// flush error branch
		h.loggingMu.Lock()
		h.pendingLogBatches["denied"] = &serverAccessLogBatch{
			TargetBucket: "dst-denied-h2",
			TargetPrefix: "logs/",
			FirstEventAt: time.Now().UTC().Add(-10 * time.Second),
			Entries: []serverAccessLogEntry{{
				SourceBucket: "src-h2",
				Line:         "l",
			}},
		}
		h.loggingMu.Unlock()
		if err := h.flushServerAccessLogsIfDue("src-h2"); err == nil {
			t.Fatal("expected flushServerAccessLogsIfDue error")
		}

		// flush partitioned object key path
		if err := h.flushServerAccessLogBatch(&serverAccessLogBatch{
			TargetBucket: "dst-h2",
			TargetPrefix: "logs/",
			ObjectKeyFormat: &backend.TargetObjectKeyFormat{
				PartitionedPrefix: &backend.PartitionedPrefix{PartitionDateSource: "EventTime"},
			},
			Entries: []serverAccessLogEntry{{
				SourceBucket: "src-h2",
				Line:         "line",
			}},
		}, time.Now().UTC()); err != nil {
			t.Fatalf("flushServerAccessLogBatch partitioned failed: %v", err)
		}

		reqPutObj := newRequest(http.MethodPut, "http://example.test/src-h2/k", "", nil)
		if got := mapRequestToLoggingOperation(reqPutObj, "k"); got != "REST.PUT.OBJECT" {
			t.Fatalf("mapRequestToLoggingOperation put object = %q, want REST.PUT.OBJECT", got)
		}

		allowPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::src-h2/*"}]}`
		mustPutBucketPolicy(t, b, "src-h2", allowPolicy)
		if got := h.loggingACLRequired(newRequest(http.MethodGet, "http://example.test/src-h2/k", "", nil), "src-h2", "k"); got != "-" {
			t.Fatalf("loggingACLRequired policy allow = %q, want -", got)
		}
		mustPutBucketPolicy(t, b, "src-h2", `{"Version":"2012-10-17","Statement":[]}`)
		if got := h.loggingACLRequired(
			newRequest(http.MethodGet, "http://example.test/src-h2/k", "", map[string]string{
				"Authorization": authHeader("root-access-key"),
			}),
			"src-h2",
			"k",
		); got != "-" {
			t.Fatalf("loggingACLRequired non-owner fallback = %q, want -", got)
		}

		getBucketACLForAccessCheckFn = func(*Handler, string) (*backend.AccessControlPolicy, error) {
			return nil, errors.New("acl read failed")
		}
		if ok := h.checkAccess(
			newRequest(http.MethodGet, "http://example.test/src-h2", "", map[string]string{
				"Authorization": authHeader("root-access-key"),
			}),
			"src-h2",
			"s3:GetBucketOwnershipControls",
			"",
		); ok {
			t.Fatal("checkAccess should fail when bucket ACL read fails (get)")
		}
		if ok := h.checkAccess(
			newRequest(http.MethodPut, "http://example.test/src-h2", "", map[string]string{
				"Authorization": authHeader("root-access-key"),
			}),
			"src-h2",
			"s3:PutBucketOwnershipControls",
			"",
		); ok {
			t.Fatal("checkAccess should fail when bucket ACL read fails (put)")
		}
		getBucketACLForAccessCheckFn = origGetBucketACL

		if err := b.PutBucketOwnershipControls("src-h2", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls enforced failed: %v", err)
		}
		if ok := h.checkAccess(
			newRequest(http.MethodGet, "http://example.test/src-h2/k", "", map[string]string{
				"Authorization": authHeader("root-access-key"),
			}),
			"src-h2",
			"s3:GetObject",
			"k",
		); ok {
			t.Fatal("checkAccess should deny on BucketOwnerEnforced without policy allow")
		}
	})

	t.Run("bucket ownership/logging control handler branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "ctl")
		b.SetBucketOwner("ctl", "minis3-access-key")

		// denied branches
		for _, tc := range []struct {
			method string
			target string
		}{
			{http.MethodPut, "http://example.test/ctl?ownershipControls"},
			{http.MethodDelete, "http://example.test/ctl?ownershipControls"},
			{http.MethodPut, "http://example.test/ctl?requestPayment"},
			{http.MethodPut, "http://example.test/ctl?logging"},
			{http.MethodDelete, "http://example.test/ctl?logging"},
		} {
			w := doRequest(h, newRequest(tc.method, tc.target, `<x/>`, nil))
			requireStatus(t, w, http.StatusForbidden)
			requireS3ErrorCode(t, w, "AccessDenied")
		}

		// create bucket ownership success path (requestedOwnership -> PutBucketOwnershipControls success)
		wCreateWithOwnership := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/created-own-success",
				"",
				map[string]string{
					"Authorization":          authHeader("minis3-access-key"),
					"x-amz-object-ownership": backend.ObjectOwnershipBucketOwnerPreferred,
				},
			),
		)
		requireStatus(t, wCreateWithOwnership, http.StatusOK)

		origPutOwnership := putBucketOwnershipControlsFn
		putBucketOwnershipControlsFn = func(*Handler, string, *backend.OwnershipControls) error {
			return errors.New("create ownership boom")
		}
		t.Cleanup(func() {
			putBucketOwnershipControlsFn = origPutOwnership
		})
		wCreateWithOwnershipErr := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/created-own-fail",
				"",
				map[string]string{
					"Authorization":          authHeader("minis3-access-key"),
					"x-amz-object-ownership": backend.ObjectOwnershipBucketOwnerPreferred,
				},
			),
		)
		requireStatus(t, wCreateWithOwnershipErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wCreateWithOwnershipErr, "InternalError")
		putBucketOwnershipControlsFn = origPutOwnership

		wNoBucketPutOwnership := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-bucket-ctl?ownershipControls",
				`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerPreferred</ObjectOwnership></Rule></OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wNoBucketPutOwnership, http.StatusNotFound)
		requireS3ErrorCode(t, wNoBucketPutOwnership, "NoSuchBucket")

		wNoBucketPutLogging := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-bucket-ctl?logging",
				`<BucketLoggingStatus/>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wNoBucketPutLogging, http.StatusNotFound)
		requireS3ErrorCode(t, wNoBucketPutLogging, "NoSuchBucket")

		origGetOwnership := getBucketOwnershipControlsFn
		origPutOwnership = putBucketOwnershipControlsFn
		origDeleteOwnership := deleteBucketOwnershipControlsFn
		origGetPayment := getBucketRequestPaymentFn
		origPutPayment := putBucketRequestPaymentFn
		origGetLogging := getBucketLoggingFn
		origPutLogging := putBucketLoggingFn
		origDeleteLogging := deleteBucketLoggingFn
		origMarshal := xmlMarshalFn
		t.Cleanup(func() {
			getBucketOwnershipControlsFn = origGetOwnership
			putBucketOwnershipControlsFn = origPutOwnership
			deleteBucketOwnershipControlsFn = origDeleteOwnership
			getBucketRequestPaymentFn = origGetPayment
			putBucketRequestPaymentFn = origPutPayment
			getBucketLoggingFn = origGetLogging
			putBucketLoggingFn = origPutLogging
			deleteBucketLoggingFn = origDeleteLogging
			xmlMarshalFn = origMarshal
		})

		if err := b.PutBucketOwnershipControls("ctl", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerPreferred}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls setup failed: %v", err)
		}

		getBucketOwnershipControlsFn = func(*Handler, string) (*backend.OwnershipControls, error) {
			return nil, errors.New("get ownership boom")
		}
		wGetOwnershipErr := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetOwnershipErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetOwnershipErr, "InternalError")
		getBucketOwnershipControlsFn = origGetOwnership

		xmlMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
		wGetOwnershipMarshal := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireS3ErrorCode(t, wGetOwnershipMarshal, "InternalError")
		xmlMarshalFn = origMarshal

		putBucketOwnershipControlsFn = func(*Handler, string, *backend.OwnershipControls) error {
			return errors.New("put ownership boom")
		}
		wPutOwnershipErr := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/ctl?ownershipControls",
				`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerPreferred</ObjectOwnership></Rule></OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutOwnershipErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutOwnershipErr, "InternalError")
		putBucketOwnershipControlsFn = origPutOwnership

		deleteBucketOwnershipControlsFn = func(*Handler, string) error {
			return errors.New("delete ownership boom")
		}
		wDeleteOwnershipErr := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/ctl?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeleteOwnershipErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteOwnershipErr, "InternalError")
		deleteBucketOwnershipControlsFn = origDeleteOwnership

		getBucketRequestPaymentFn = func(*Handler, string) (*backend.RequestPaymentConfiguration, error) {
			return nil, errors.New("get payment boom")
		}
		wGetPaymentErr := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?requestPayment",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetPaymentErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetPaymentErr, "InternalError")
		getBucketRequestPaymentFn = origGetPayment

		xmlMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
		wGetPaymentMarshal := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?requestPayment",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireS3ErrorCode(t, wGetPaymentMarshal, "InternalError")
		xmlMarshalFn = origMarshal

		putBucketRequestPaymentFn = func(*Handler, string, *backend.RequestPaymentConfiguration) error {
			return errors.New("put payment boom")
		}
		wPutPaymentErr := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/ctl?requestPayment",
				`<RequestPaymentConfiguration><Payer>BucketOwner</Payer></RequestPaymentConfiguration>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutPaymentErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutPaymentErr, "InternalError")
		putBucketRequestPaymentFn = origPutPayment

		getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
			return nil, errors.New("get logging boom")
		}
		wGetLoggingErr := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetLoggingErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetLoggingErr, "InternalError")
		getBucketLoggingFn = origGetLogging

		xmlMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
		wGetLoggingMarshal := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/ctl?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireS3ErrorCode(t, wGetLoggingMarshal, "InternalError")
		xmlMarshalFn = origMarshal

		putBucketLoggingFn = func(*Handler, string, *backend.BucketLoggingStatus) error {
			return backend.ErrBucketNotFound
		}
		wPutLoggingNoBucket := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/ctl?logging",
				`<BucketLoggingStatus/>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutLoggingNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutLoggingNoBucket, "NoSuchBucket")

		putBucketLoggingFn = func(*Handler, string, *backend.BucketLoggingStatus) error {
			return backend.ErrObjectNotFound
		}
		wPutLoggingNoKey := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/ctl?logging",
				`<BucketLoggingStatus/>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutLoggingNoKey, http.StatusNotFound)
		requireS3ErrorCode(t, wPutLoggingNoKey, "NoSuchKey")

		putBucketLoggingFn = func(*Handler, string, *backend.BucketLoggingStatus) error {
			return errors.New("put logging boom")
		}
		wPutLoggingErr := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/ctl?logging",
				`<BucketLoggingStatus/>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutLoggingErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutLoggingErr, "InternalError")
		putBucketLoggingFn = origPutLogging

		deleteBucketLoggingFn = func(*Handler, string) error {
			return errors.New("delete logging boom")
		}
		wDeleteLoggingErr := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/ctl?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeleteLoggingErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteLoggingErr, "InternalError")
	})

	t.Run("post object form and remaining multipart/object branches", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "post-gap")
		b.SetBucketOwner("post-gap", "minis3-access-key")

		origOwner := ownerForAccessKeyFn
		origPostPutACL := postObjectPutACLFn
		origPutObjectACL := putObjectACLFn
		t.Cleanup(func() {
			ownerForAccessKeyFn = origOwner
			postObjectPutACLFn = origPostPutACL
			putObjectACLFn = origPutObjectACL
		})

		if err := b.PutBucketOwnershipControls("post-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls enforced failed: %v", err)
		}
		reqPostACLUnsupported := makeMultipartReqWithFilename(
			t,
			"http://example.test/post-gap",
			map[string]string{"key": "k1", "acl": "public-read"},
			"file",
			"f.txt",
			"body",
		)
		wPostACLUnsupported := doRequest(h, reqPostACLUnsupported)
		requireStatus(t, wPostACLUnsupported, http.StatusBadRequest)
		requireS3ErrorCode(t, wPostACLUnsupported, "AccessControlListNotSupported")

		reqPostBOEOk := makeMultipartReqWithFilename(
			t,
			"http://example.test/post-gap",
			map[string]string{"key": "k2", "acl": string(backend.ACLBucketOwnerFull)},
			"file",
			"f.txt",
			"body",
		)
		wPostBOEOk := doRequest(h, reqPostBOEOk)
		requireStatus(t, wPostBOEOk, http.StatusNoContent)

		if err := b.PutBucketOwnershipControls("post-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerPreferred}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls preferred failed: %v", err)
		}
		reqPostPreferred := makeMultipartReqWithFilename(
			t,
			"http://example.test/post-gap",
			map[string]string{"key": "k3", "acl": string(backend.ACLBucketOwnerFull)},
			"file",
			"f.txt",
			"body",
		)
		wPostPreferred := doRequest(h, reqPostPreferred)
		requireStatus(t, wPostPreferred, http.StatusNoContent)

		if err := b.PutBucketOwnershipControls("post-gap", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipObjectWriter}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls writer failed: %v", err)
		}
		postObjectPutACLFn = func(*Handler, string, string, string, *backend.AccessControlPolicy) error {
			return backend.ErrAccessControlListNotSupported
		}
		reqPostACLPutFail := makeMultipartReqWithFilename(
			t,
			"http://example.test/post-gap",
			map[string]string{"key": "k4", "acl": "public-read"},
			"file",
			"f.txt",
			"body",
		)
		wPostACLPutFail := doRequest(h, reqPostACLPutFail)
		requireStatus(t, wPostACLPutFail, http.StatusBadRequest)
		requireS3ErrorCode(t, wPostACLPutFail, "AccessControlListNotSupported")
		postObjectPutACLFn = origPostPutACL

		ownerForAccessKeyFn = func(string) *backend.Owner { return nil }
		reqPostNilOwner := makeMultipartReqWithFilename(
			t,
			"http://example.test/post-gap",
			map[string]string{"key": "k5"},
			"file",
			"f.txt",
			"body",
		)
		wPostNilOwner := doRequest(h, reqPostNilOwner)
		requireStatus(t, wPostNilOwner, http.StatusNoContent)
		ownerForAccessKeyFn = origOwner

		// Multipart remaining lines: BOE owner assignment and FULL_OBJECT checksum finalization.
		mustPublicWriteBucket(t, b, "mp-left", "minis3-access-key")
		if err := b.PutBucketACL("mp-left", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL mp-left private failed: %v", err)
		}
		if err := b.PutBucketOwnershipControls("mp-left", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls mp-left failed: %v", err)
		}
		wCreateBOE := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-left/obj?uploads",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wCreateBOE, http.StatusOK)

		mustPublicWriteBucket(t, b, "mp-full", "minis3-access-key")
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-full",
			"obj",
			map[string]string{
				"Authorization":            authHeader("minis3-access-key"),
				"x-amz-checksum-algorithm": "SHA256",
				"x-amz-checksum-type":      "FULL_OBJECT",
			},
		)
		wPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-full/obj?uploadId=%s&partNumber=1", uploadID),
				"part-data",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart, http.StatusOK)
		etag := wPart.Header().Get("ETag")
		wComplete := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-full/obj?uploadId=%s", uploadID),
				`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>`+etag+`</ETag></Part></CompleteMultipartUpload>`,
				nil,
			),
		)
		requireStatus(t, wComplete, http.StatusOK)
		if up, ok := b.GetUpload(uploadID); ok && up != nil {
			t.Fatalf("upload should be removed after complete: %s", uploadID)
		}

		// Object remaining lines.
		mustCreateBucket(t, b, "obj-left")
		b.SetBucketOwner("obj-left", "minis3-access-key")
		if err := b.PutBucketACL("obj-left", backend.CannedACLToPolicy("public-read-write")); err != nil {
			t.Fatalf("PutBucketACL obj-left failed: %v", err)
		}
		if err := b.PutBucketACL("obj-left", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL obj-left private failed: %v", err)
		}
		if err := b.PutBucketOwnershipControls("obj-left", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls obj-left enforced failed: %v", err)
		}
		wPutBOE := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-left/boe",
				"v",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutBOE, http.StatusOK)

		if err := b.PutBucketOwnershipControls("obj-left", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipObjectWriter}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls obj-left writer failed: %v", err)
		}
		ownerForAccessKeyFn = func(string) *backend.Owner { return nil }
		wPutNilOwner := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-left/nil-owner",
				"v",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutNilOwner, http.StatusOK)
		ownerForAccessKeyFn = origOwner

		putObjectACLFn = func(*Handler, string, string, string, *backend.AccessControlPolicy) error {
			return backend.ErrAccessControlListNotSupported
		}
		wPutACLFail := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-left/acl-fail",
				"v",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutACLFail, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutACLFail, "AccessControlListNotSupported")
		putObjectACLFn = origPutObjectACL

		mustPutObject(t, b, "obj-left", "part", "abc")
		wBadPartNumber := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-left/part?partNumber=0",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wBadPartNumber, http.StatusBadRequest)
		requireS3ErrorCode(t, wBadPartNumber, "InvalidArgument")

		wMissingPart := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-left/part?partNumber=2",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wMissingPart, http.StatusBadRequest)
		requireS3ErrorCode(t, wMissingPart, "InvalidPart")

		if err := b.SetBucketVersioning("obj-left", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning obj-left failed: %v", err)
		}
		if _, err := b.DeleteObject("obj-left", "dm", false); err != nil {
			t.Fatalf("DeleteObject dm#1 failed: %v", err)
		}
		if _, err := b.DeleteObject("obj-left", "dm", false); err != nil {
			t.Fatalf("DeleteObject dm#2 failed: %v", err)
		}
		wDeleteDM := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/obj-left/dm",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeleteDM, http.StatusNoContent)

		mustCreateBucket(t, b, "src-left")
		mustPutObject(t, b, "src-left", "k", "v")
		if err := b.PutObjectACL("src-left", "k", "", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutObjectACL src-left failed: %v", err)
		}
		mustCreateBucket(t, b, "dst-left")
		b.SetBucketOwner("dst-left", "minis3-access-key")
		if err := b.PutBucketACL("dst-left", backend.CannedACLToPolicy("public-read-write")); err != nil {
			t.Fatalf("PutBucketACL dst-left failed: %v", err)
		}
		if err := b.PutBucketACL("dst-left", backend.CannedACLToPolicy("private")); err != nil {
			t.Fatalf("PutBucketACL dst-left private failed: %v", err)
		}
		if err := b.PutBucketOwnershipControls("dst-left", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls dst-left enforced failed: %v", err)
		}
		wCopyBOE := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-left/boe",
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-left/k",
					"x-amz-acl":         string(backend.ACLBucketOwnerFull),
				},
			),
		)
		requireStatus(t, wCopyBOE, http.StatusOK)

		if err := b.PutBucketOwnershipControls("dst-left", &backend.OwnershipControls{
			Rules: []backend.OwnershipControlsRule{{ObjectOwnership: backend.ObjectOwnershipBucketOwnerPreferred}},
		}); err != nil {
			t.Fatalf("PutBucketOwnershipControls dst-left preferred failed: %v", err)
		}
		wCopyPreferred := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-left/preferred",
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-left/k",
					"x-amz-acl":         string(backend.ACLBucketOwnerFull),
				},
			),
		)
		requireStatus(t, wCopyPreferred, http.StatusOK)

		wAttrsDenied := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-left/part?attributes",
				"",
				map[string]string{
					"x-amz-object-attributes": "ETag",
				},
			),
		)
		requireStatus(t, wAttrsDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wAttrsDenied, "AccessDenied")

		obj, err := b.GetObject("obj-left", "part")
		if err != nil {
			t.Fatalf("GetObject part failed: %v", err)
		}
		obj.Parts = []backend.ObjectPart{
			{
				PartNumber:        1,
				Size:              10,
				ChecksumCRC32:     "a",
				ChecksumCRC32C:    "b",
				ChecksumCRC64NVME: "c",
				ChecksumSHA1:      "d",
				ChecksumSHA256:    "e",
			},
			{
				PartNumber: 2,
				Size:       1,
			},
		}
		wAttrsParts := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-left/part?attributes&max-parts=1&part-number-marker=0",
				"",
				map[string]string{
					"Authorization":           authHeader("minis3-access-key"),
					"x-amz-object-attributes": "ObjectParts,Checksum",
				},
			),
		)
		requireStatus(t, wAttrsParts, http.StatusOK)
		if !bytes.Contains(
			wAttrsParts.Body.Bytes(),
			[]byte("<NextPartNumberMarker>1</NextPartNumberMarker>"),
		) {
			t.Fatalf("expected NextPartNumberMarker in response: %s", wAttrsParts.Body.String())
		}
	})
}

func TestCoverageGapFlushLogPutPath(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-flush-gap")
	b.SetBucketOwner("obj-flush-gap", "minis3-access-key")
	h.loggingMu.Lock()
	h.pendingLogBatches["flush-denied"] = &serverAccessLogBatch{
		TargetBucket: "missing-target",
		TargetPrefix: "logs/",
		FirstEventAt: time.Now().UTC().Add(-10 * time.Second),
		Entries: []serverAccessLogEntry{{
			SourceBucket: "obj-flush-gap",
			Line:         "line",
		}},
	}
	h.loggingMu.Unlock()

	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/obj-flush-gap/k",
			"v",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "AccessDenied")
}

func TestCoverageGapEmitRequestURIFallbackBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "uri-gap")
	mustCreateBucket(t, b, "uri-gap-target")
	b.SetBucketOwner("uri-gap", "minis3-access-key")
	b.SetBucketOwner("uri-gap-target", "minis3-access-key")
	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
	}
	mustPutBucketPolicy(
		t,
		b,
		"uri-gap-target",
		allowLoggingPolicy("uri-gap", "uri-gap-target", "logs/", owner.ID),
	)

	origGetLogging := getBucketLoggingFn
	origReqURI := requestURIForLoggingFn
	t.Cleanup(func() {
		getBucketLoggingFn = origGetLogging
		requestURIForLoggingFn = origReqURI
	})

	getBucketLoggingFn = func(*Handler, string) (*backend.BucketLoggingStatus, error) {
		return &backend.BucketLoggingStatus{
			LoggingEnabled: &backend.LoggingEnabled{
				TargetBucket: "uri-gap-target",
				TargetPrefix: "logs/",
			},
		}, nil
	}
	requestURIForLoggingFn = func(*http.Request) string { return "" }
	req := &http.Request{
		Method:     http.MethodGet,
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/uri-gap/key"},
		RemoteAddr: "",
		Host:       "example.test",
		Proto:      "HTTP/1.1",
	}
	h.emitServerAccessLog(req, http.StatusOK, 1, "r", "h")
}

func TestCoverageGapObjectPartAndDeleteMarkerBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-part-branch")
	b.SetBucketOwner("obj-part-branch", "minis3-access-key")
	if err := b.PutBucketACL("obj-part-branch", backend.CannedACLToPolicy("public-read-write")); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}
	mustPutObject(t, b, "obj-part-branch", "k", "abc")

	wInvalidPartNumber := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/obj-part-branch/k?partNumber=abc",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wInvalidPartNumber, http.StatusBadRequest)
	requireS3ErrorCode(t, wInvalidPartNumber, "InvalidArgument")

	wMissingPart := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/obj-part-branch/k?partNumber=2",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wMissingPart, http.StatusBadRequest)
	requireS3ErrorCode(t, wMissingPart, "InvalidPart")

	if err := b.SetBucketVersioning("obj-part-branch", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	mustPutObject(t, b, "obj-part-branch", "dm-live", "v")
	if _, err := b.DeleteObject("obj-part-branch", "dm-live", false); err != nil {
		t.Fatalf("DeleteObject dm-live failed: %v", err)
	}
	wDeleteLive := doRequest(
		h,
		newRequest(
			http.MethodDelete,
			"http://example.test/obj-part-branch/dm-live",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wDeleteLive, http.StatusNoContent)

	if _, err := b.DeleteObject("obj-part-branch", "dm", false); err != nil {
		t.Fatalf("DeleteObject #1 failed: %v", err)
	}
	if _, err := b.DeleteObject("obj-part-branch", "dm", false); err != nil {
		t.Fatalf("DeleteObject #2 failed: %v", err)
	}
	wDelete := doRequest(
		h,
		newRequest(
			http.MethodDelete,
			"http://example.test/obj-part-branch/dm",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wDelete, http.StatusNoContent)
}
