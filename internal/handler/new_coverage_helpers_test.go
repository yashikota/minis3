package handler

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestAuthV4ReadsNonNilBodyWhenPayloadHashMissing(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"http://example.test/bucket/key",
		strings.NewReader("abc"),
	)
	req.Host = "example.test"
	req.Header.Set("x-amz-date", "20260207T000000Z")
	req.Header.Set(
		"Authorization",
		"AWS4-HMAC-SHA256 Credential=minis3-access-key/20260207/us-east-1/s3/aws4_request, "+
			"SignedHeaders=host;x-amz-date, Signature=deadbeef",
	)

	err := verifyAuthorizationHeader(req)
	requirePresignedErrCode(t, err, "SignatureDoesNotMatch")

	// verifyAuthorizationHeaderV4 rewinds body after hashing.
	body, readErr := io.ReadAll(req.Body)
	if readErr != nil {
		t.Fatalf("ReadAll(req.Body) failed: %v", readErr)
	}
	if got := string(body); got != "abc" {
		t.Fatalf("request body after verification = %q, want abc", got)
	}
}

func TestServiceIAMBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "svc-iam")

	t.Run("iam action from query", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/?Action=GetUser",
			"",
			map[string]string{
				"Authorization": authHeader("iam-access-key"),
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("Content-Type"); got != "text/xml" {
			t.Fatalf("Content-Type = %q, want text/xml", got)
		}
		if !strings.Contains(w.Body.String(), "<GetUserResponse") {
			t.Fatalf("unexpected body: %s", w.Body.String())
		}
	})

	t.Run("iam root action from query", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/?Action=GetUser", "", map[string]string{
			"Authorization": authHeader("root-access-key"),
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::123456789012:root</Arn>") {
			t.Fatalf("unexpected root arn in body: %s", w.Body.String())
		}
	})

	t.Run("iam root arn by display name fallback", func(t *testing.T) {
		origOwnerForAccessKeyFn := ownerForAccessKeyFn
		t.Cleanup(func() {
			ownerForAccessKeyFn = origOwnerForAccessKeyFn
		})
		ownerForAccessKeyFn = func(string) *backend.Owner {
			return &backend.Owner{ID: "custom-account", DisplayName: "root"}
		}

		req := newRequest(http.MethodGet, "http://example.test/?Action=GetUser", "", map[string]string{
			"Authorization": authHeader("custom-access-key"),
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::123456789012:root</Arn>") {
			t.Fatalf("unexpected root arn in body: %s", w.Body.String())
		}
	})

	t.Run("iam action from post form", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"http://example.test/",
			"Action=GetUser",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("unknown iam action", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/?Action=UnknownAction", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "Unknown")
	})

	t.Run("iamAction empty", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/", "", nil)
		if got := iamAction(req); got != "" {
			t.Fatalf("iamAction = %q, want empty", got)
		}
	})
}

func TestMultipartChecksumHelpers(t *testing.T) {
	part := backend.CompletePart{
		ChecksumCRC32:     "crc32",
		ChecksumCRC32C:    "crc32c",
		ChecksumCRC64NVME: "crc64",
		ChecksumSHA1:      "sha1",
		ChecksumSHA256:    "sha256",
	}
	partInfo := &backend.PartInfo{
		ChecksumCRC32:     "crc32",
		ChecksumCRC32C:    "crc32c",
		ChecksumCRC64NVME: "crc64",
		ChecksumSHA1:      "sha1",
		ChecksumSHA256:    "sha256",
	}

	if got := normalizeChecksumType("sha256", ""); got != "COMPOSITE" {
		t.Fatalf("normalizeChecksumType(sha256, empty) = %q, want COMPOSITE", got)
	}
	if got := normalizeChecksumType("crc32", ""); got != "FULL_OBJECT" {
		t.Fatalf("normalizeChecksumType(crc32, empty) = %q, want FULL_OBJECT", got)
	}
	if got := normalizeChecksumType("sha1", "full_object"); got != "FULL_OBJECT" {
		t.Fatalf("normalizeChecksumType explicit = %q, want FULL_OBJECT", got)
	}

	algorithms := []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256", "UNKNOWN"}
	for _, algo := range algorithms {
		_ = checksumFromCompletePart(algo, part)
		_ = checksumFromPartInfo(algo, partInfo)
		_ = checksumFromPartInfo(algo, nil)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	req.Header.Set("x-amz-checksum-crc32", "v1")
	req.Header.Set("x-amz-checksum-crc32c", "v2")
	req.Header.Set("x-amz-checksum-crc64nvme", "v3")
	req.Header.Set("x-amz-checksum-sha1", "v4")
	req.Header.Set("x-amz-checksum-sha256", "v5")
	for _, algo := range algorithms {
		_ = checksumFromCompleteHeaders(algo, req)
	}

	upload := &backend.MultipartUpload{}
	for _, algo := range algorithms {
		setUploadFinalChecksum(upload, algo, "x")
	}

	if _, ok := computeCompositeChecksum("SHA1", nil); ok {
		t.Fatal("computeCompositeChecksum should fail for empty part list")
	}
	if _, ok := computeCompositeChecksum("CRC32", []string{"AAAAAA=="}); ok {
		t.Fatal("computeCompositeChecksum should fail for unsupported algorithm")
	}
	if _, ok := computeCompositeChecksum("SHA1", []string{"%%%"}); ok {
		t.Fatal("computeCompositeChecksum should fail for invalid base64")
	}
	if got, ok := computeCompositeChecksum("SHA256", []string{"AAAAAA=="}); !ok || got == "" {
		t.Fatalf("computeCompositeChecksum success = (%q, %v), want non-empty true", got, ok)
	}

	for _, algo := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"} {
		if got, ok := computeFullObjectChecksum(algo, []byte("payload")); !ok || got == "" {
			t.Fatalf("computeFullObjectChecksum(%s) = (%q, %v), want non-empty true", algo, got, ok)
		}
	}
	if _, ok := computeFullObjectChecksum("UNKNOWN", []byte("payload")); ok {
		t.Fatal("computeFullObjectChecksum should fail for unknown algorithm")
	}
}

func TestObjectHelperAdditionalBranchesForCoverage(t *testing.T) {
	t.Run("parseTimestampFlexible variants", func(t *testing.T) {
		now := time.Now().UTC()
		cases := []string{
			now.Format(time.RFC3339Nano),
			now.Format(time.RFC3339),
			now.Format(http.TimeFormat),
		}
		for _, c := range cases {
			if parsed, err := parseTimestampFlexible(c); err != nil || parsed == nil {
				t.Fatalf("parseTimestampFlexible(%q) failed: %v", c, err)
			}
		}
		if _, err := parseTimestampFlexible("not-a-time"); err == nil {
			t.Fatal("parseTimestampFlexible should fail for invalid input")
		}
	})

	t.Run("evaluateDeletePreconditions branches", func(t *testing.T) {
		// nil object keeps delete idempotent.
		if status, _, _ := evaluateDeletePreconditions(httptest.NewRequest(http.MethodDelete, "/", nil), nil); status != 0 {
			t.Fatalf("status for nil object = %d, want 0", status)
		}

		obj := &backend.Object{
			ETag:         "\"etag\"",
			LastModified: time.Now().UTC().Truncate(time.Second),
			Size:         3,
		}
		if status, _, _ := evaluateDeletePreconditions(
			newRequest(http.MethodDelete, "http://example.test/", "", map[string]string{"If-Match": "\"other\""}),
			obj,
		); status != http.StatusPreconditionFailed {
			t.Fatalf("If-Match mismatch status = %d, want 412", status)
		}
		if status, _, _ := evaluateDeletePreconditions(
			newRequest(http.MethodDelete, "http://example.test/", "", map[string]string{"If-Match": "*"}),
			obj,
		); status != 0 {
			t.Fatalf("If-Match wildcard status = %d, want 0", status)
		}

		reqInvalidTime := newRequest(
			http.MethodDelete,
			"http://example.test/",
			"",
			map[string]string{"x-amz-if-match-last-modified-time": "invalid"},
		)
		if status, code, _ := evaluateDeletePreconditions(reqInvalidTime, obj); status != http.StatusBadRequest ||
			code != "InvalidArgument" {
			t.Fatalf(
				"invalid last-modified result = (%d,%s), want (400,InvalidArgument)",
				status,
				code,
			)
		}

		reqTimeMismatch := newRequest(
			http.MethodDelete,
			"http://example.test/",
			"",
			map[string]string{
				"x-amz-if-match-last-modified-time": time.Now().
					UTC().
					Add(-time.Hour).
					Format(time.RFC3339),
			},
		)
		if status, code, _ := evaluateDeletePreconditions(reqTimeMismatch, obj); status != http.StatusPreconditionFailed ||
			code != "PreconditionFailed" {
			t.Fatalf("time mismatch result = (%d,%s), want (412,PreconditionFailed)", status, code)
		}

		reqInvalidSize := newRequest(
			http.MethodDelete,
			"http://example.test/",
			"",
			map[string]string{"x-amz-if-match-size": "-1"},
		)
		if status, code, _ := evaluateDeletePreconditions(reqInvalidSize, obj); status != http.StatusBadRequest ||
			code != "InvalidArgument" {
			t.Fatalf("invalid size result = (%d,%s), want (400,InvalidArgument)", status, code)
		}

		reqSizeMismatch := newRequest(
			http.MethodDelete,
			"http://example.test/",
			"",
			map[string]string{"x-amz-if-match-size": "9"},
		)
		if status, code, _ := evaluateDeletePreconditions(reqSizeMismatch, obj); status != http.StatusPreconditionFailed ||
			code != "PreconditionFailed" {
			t.Fatalf("size mismatch result = (%d,%s), want (412,PreconditionFailed)", status, code)
		}
	})

	t.Run("computePartChecksums all algorithms", func(t *testing.T) {
		for _, algo := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256", "UNKNOWN"} {
			_ = computePartChecksums([]byte("hello"), algo)
		}
	})

	t.Run("setPartChecksumResponseHeaders with full checksums", func(t *testing.T) {
		w := httptest.NewRecorder()
		part := &backend.ObjectPart{
			ChecksumCRC32:     "a",
			ChecksumCRC32C:    "b",
			ChecksumCRC64NVME: "c",
			ChecksumSHA1:      "d",
			ChecksumSHA256:    "e",
		}
		setPartChecksumResponseHeaders(w, "FULL_OBJECT", part)
		if got := w.Header().Get("x-amz-checksum-type"); got != "FULL_OBJECT" {
			t.Fatalf("x-amz-checksum-type = %q, want FULL_OBJECT", got)
		}
	})

	t.Run("inferChecksumAlgorithmFromTrailer covers crc64", func(t *testing.T) {
		if got := inferChecksumAlgorithmFromTrailer("x-amz-checksum-crc64nvme"); got != "CRC64NVME" {
			t.Fatalf("inferChecksumAlgorithmFromTrailer crc64 = %q, want CRC64NVME", got)
		}
	})
}

func TestGetObjectAttributesAdditionalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "attr-bkt")
	mustPutObject(t, b, "attr-bkt", "k", "hello")

	t.Run("missing attributes header", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/attr-bkt/k?attributes", "", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("invalid attributes header value", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag,Unknown"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("invalid max-parts and marker", func(t *testing.T) {
		wBadMax := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes&max-parts=-1",
				"",
				map[string]string{"x-amz-object-attributes": "ObjectParts"},
			),
		)
		requireStatus(t, wBadMax, http.StatusBadRequest)
		requireS3ErrorCode(t, wBadMax, "InvalidArgument")

		wBadMarker := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes&part-number-marker=-1",
				"",
				map[string]string{"x-amz-object-attributes": "ObjectParts"},
			),
		)
		requireStatus(t, wBadMarker, http.StatusBadRequest)
		requireS3ErrorCode(t, wBadMarker, "InvalidArgument")
	})

	t.Run("sse-c access required branch", func(t *testing.T) {
		obj, err := b.GetObject("attr-bkt", "k")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		origAlgo := obj.SSECustomerAlgorithm
		origMD5 := obj.SSECustomerKeyMD5
		t.Cleanup(func() {
			obj.SSECustomerAlgorithm = origAlgo
			obj.SSECustomerKeyMD5 = origMD5
		})
		obj.SSECustomerAlgorithm = "AES256"
		obj.SSECustomerKeyMD5 = "abc"

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("delete marker branch", func(t *testing.T) {
		if err := b.SetBucketVersioning("attr-bkt", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if _, err := b.DeleteObject("attr-bkt", "k", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
		if got := w.Header().Get("x-amz-delete-marker"); got != "true" {
			t.Fatalf("x-amz-delete-marker = %q, want true", got)
		}
	})

	t.Run("version not found branch", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes&versionId=nope",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("xml marshal failure branch", func(t *testing.T) {
		origMarshal := xmlMarshalFn
		xmlMarshalFn = func(v any) ([]byte, error) {
			return nil, io.ErrUnexpectedEOF
		}
		t.Cleanup(func() {
			xmlMarshalFn = origMarshal
		})

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/k?attributes&versionId="+backend.NullVersionId,
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<Code>InternalError</Code>") {
			t.Fatalf("expected InternalError in body, got: %s", w.Body.String())
		}
		xmlMarshalFn = origMarshal
	})

	t.Run("object parts success path", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"http://example.test/attr-bkt/multipart?uploads",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		wCreate := doRequest(h, req)
		requireStatus(t, wCreate, http.StatusOK)
		var initResp backend.InitiateMultipartUploadResult
		if err := xml.Unmarshal(wCreate.Body.Bytes(), &initResp); err != nil {
			t.Fatalf("unmarshal initiate response failed: %v", err)
		}
		if initResp.UploadId == "" {
			t.Fatal("empty upload id")
		}

		wPart := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/attr-bkt/multipart?uploadId="+initResp.UploadId+"&partNumber=1",
				"part-data",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPart, http.StatusOK)
		partETag := wPart.Header().Get("ETag")

		completeBody := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + partETag + `</ETag></Part></CompleteMultipartUpload>`
		wComplete := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/attr-bkt/multipart?uploadId="+initResp.UploadId,
				completeBody,
				nil,
			),
		)
		requireStatus(t, wComplete, http.StatusOK)

		wAttr := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attr-bkt/multipart?attributes&max-parts=1&part-number-marker=0",
				"",
				map[string]string{
					"x-amz-object-attributes": "ObjectParts,Checksum,StorageClass,ObjectSize,ETag",
				},
			),
		)
		requireStatus(t, wAttr, http.StatusOK)
		if !strings.Contains(wAttr.Body.String(), "<ObjectParts>") {
			t.Fatalf("expected ObjectParts in response body: %s", wAttr.Body.String())
		}
	})
}
