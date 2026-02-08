package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func makeMultipartReqWithFilename(
	t *testing.T,
	target string,
	fields map[string]string,
	fileField, fileName, fileBody string,
) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%q) failed: %v", k, err)
		}
	}
	fw, err := mw.CreateFormFile(fileField, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := fw.Write([]byte(fileBody)); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close multipart failed: %v", err)
	}

	req := newRequest(http.MethodPost, target, body.String(), nil)
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func makeMultipartReqWithExplicitEmptyFilename(
	t *testing.T,
	target string,
	fields map[string]string,
	fileBody string,
) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%q) failed: %v", k, err)
		}
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename=""`)
	h.Set("Content-Type", "application/octet-stream")
	fw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart failed: %v", err)
	}
	if _, err := fw.Write([]byte(fileBody)); err != nil {
		t.Fatalf("write file part failed: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("Close multipart failed: %v", err)
	}

	req := newRequest(http.MethodPost, target, body.String(), nil)
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func signPostPolicyForTest(policy string) string {
	mac := hmac.New(sha1.New, []byte("minis3-secret-key"))
	_, _ = mac.Write([]byte(policy))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func encodePolicyForTest(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal policy failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestBucketHelperUncoveredBranches(t *testing.T) {
	t.Run("parseMultipartFormFields skips file when read fails", func(t *testing.T) {
		req := makeMultipartReqWithFilename(
			t,
			"http://example.test/x",
			map[string]string{},
			"x-amz-signature",
			"sig.txt",
			"signature",
		)
		if err := req.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("ParseMultipartForm failed: %v", err)
		}

		origReadAll := readAllFn
		readAllFn = func(io.Reader) ([]byte, error) {
			return nil, errors.New("read boom")
		}
		defer func() { readAllFn = origReadAll }()

		got := parseMultipartFormFields(req)
		if _, ok := got["x-amz-signature"]; ok {
			t.Fatalf("x-amz-signature should be omitted on read error: %+v", got)
		}
	})

	t.Run("validatePostPolicy eq invalid length and bucket condition in array", func(t *testing.T) {
		invalidLenPolicy := encodePolicyForTest(t, map[string]any{
			"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
			"conditions": []any{
				[]any{"eq", "$key"},
			},
		})
		if status, ok := validatePostPolicy(
			invalidLenPolicy,
			"bucket",
			"key",
			"",
			map[string]string{},
			1,
		); ok || status != http.StatusBadRequest {
			t.Fatalf("expected bad request for invalid eq length, got status=%d ok=%v", status, ok)
		}

		validPolicy := encodePolicyForTest(t, map[string]any{
			"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
			"conditions": []any{
				[]any{"eq", "$bucket", "bucket"},
				[]any{"eq", "$key", "key"},
			},
		})
		if status, ok := validatePostPolicy(
			validPolicy,
			"bucket",
			"key",
			"",
			map[string]string{},
			1,
		); !ok || status != 0 {
			t.Fatalf("expected valid policy, got status=%d ok=%v", status, ok)
		}
	})

	t.Run("lifecycle validation and date edge branches", func(t *testing.T) {
		if code, _, ok := validateLifecycleConfiguration(nil); ok || code != "MalformedXML" {
			t.Fatalf("nil config should fail with MalformedXML: ok=%v code=%s", ok, code)
		}

		cases := []backend.LifecycleConfiguration{
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: -1,
					},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						ExpiredObjectDeleteMarker: true,
						Days:                      1,
					},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{
						Days: 1,
						Date: "2025-01-01",
					},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Transition: []backend.LifecycleTransition{{
						Days:         -1,
						StorageClass: "GLACIER",
					}},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Transition: []backend.LifecycleTransition{{
						StorageClass: "GLACIER",
					}},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Transition: []backend.LifecycleTransition{{
						Days:         1,
						Date:         "2025-01-01",
						StorageClass: "GLACIER",
					}},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					Transition: []backend.LifecycleTransition{{
						Days: 1,
					}},
				}},
			},
			{
				Rules: []backend.LifecycleRule{{
					Status: backend.LifecycleStatusEnabled,
					NoncurrentVersionExpiration: &backend.NoncurrentVersionExpiration{
						NoncurrentDays: 0,
					},
				}},
			},
		}
		for i, cfg := range cases {
			if code, _, ok := validateLifecycleConfiguration(&cfg); ok ||
				code != "InvalidArgument" {
				t.Fatalf("case %d should fail InvalidArgument: ok=%v code=%s", i, ok, code)
			}
		}

		if _, err := parseLifecycleExpirationDate("1999-01-01T00:00:00Z"); err == nil {
			t.Fatal("RFC3339 year < 2000 should be invalid")
		}
		if _, err := parseLifecycleExpirationDate("1999-01-01"); err == nil {
			t.Fatal("date year < 2000 should be invalid")
		}
	})
}

func TestBucketCreateHeadAndPostUncoveredBranches(t *testing.T) {
	h, b := newTestHandler(t)

	t.Run("create bucket object lock enabled and existing-bucket branches", func(t *testing.T) {
		wLock := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-lock", "", map[string]string{
				"x-amz-bucket-object-lock-enabled": "true",
			}),
		)
		requireStatus(t, wLock, http.StatusOK)

		mustCreateBucket(t, b, "create-idempotent")
		wIdempotent := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-idempotent", "", nil),
		)
		requireStatus(t, wIdempotent, http.StatusOK)

		mustCreateBucket(t, b, "create-public")
		if err := b.PutBucketACL("create-public", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		wPublic := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-public", "", nil),
		)
		requireStatus(t, wPublic, http.StatusConflict)
		requireS3ErrorCode(t, wPublic, "BucketAlreadyExists")

		mustCreateBucket(t, b, "create-other-owner")
		b.SetBucketOwner("create-other-owner", "owner-ak")
		wOtherOwner := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-other-owner", "", nil),
		)
		requireStatus(t, wOtherOwner, http.StatusConflict)
		requireS3ErrorCode(t, wOtherOwner, "BucketAlreadyExists")
	})

	t.Run("create bucket backend and acl error branches", func(t *testing.T) {
		origCreate := createBucketFn
		origPutACL := putBucketACLFn
		defer func() {
			createBucketFn = origCreate
			putBucketACLFn = origPutACL
		}()

		createBucketFn = func(*Handler, string) error { return backend.ErrBucketAlreadyOwnedByYou }
		wOwned := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-owned", "", nil),
		)
		requireStatus(t, wOwned, http.StatusOK)

		createBucketFn = func(*Handler, string) error { return backend.ErrBucketAlreadyExists }
		wExists := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-exists", "", nil),
		)
		requireStatus(t, wExists, http.StatusConflict)
		requireS3ErrorCode(t, wExists, "BucketAlreadyExists")

		createBucketFn = func(*Handler, string) error { return errors.New("create boom") }
		wInternal := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-internal", "", nil),
		)
		requireStatus(t, wInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wInternal, "InternalError")

		createBucketFn = origCreate
		wACLParse := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/create-acl-parse",
				"",
				map[string]string{
					"x-amz-grant-read": "badformat",
				},
			),
		)
		requireStatus(t, wACLParse, http.StatusBadRequest)
		requireS3ErrorCode(t, wACLParse, "InvalidArgument")

		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			return errors.New("put acl boom")
		}
		wACLInternal := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/create-acl-internal", "", nil),
		)
		requireStatus(t, wACLInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wACLInternal, "InternalError")

		count := 0
		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			count++
			if count == 2 {
				return errors.New("put canned acl boom")
			}
			return nil
		}
		wCannedACLInternal := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/create-canned-acl",
				"",
				map[string]string{
					"x-amz-acl": "public-read",
				},
			),
		)
		requireStatus(t, wCannedACLInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wCannedACLInternal, "InternalError")
	})

	t.Run("delete and head additional error branches", func(t *testing.T) {
		mustCreateBucket(t, b, "delete-internal")
		origDeleteBucket := deleteBucketFn
		deleteBucketFn = func(*Handler, string) error { return errors.New("delete bucket boom") }
		wDelete := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/delete-internal", "", nil),
		)
		requireStatus(t, wDelete, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDelete, "InternalError")
		deleteBucketFn = origDeleteBucket

		mustCreateBucket(t, b, "head-denied")
		b.SetBucketOwner("head-denied", "owner-ak")
		wDenied := doRequest(
			h,
			newRequest(http.MethodHead, "http://example.test/head-denied", "", nil),
		)
		requireStatus(t, wDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wDenied, "AccessDenied")

		mustCreateBucket(t, b, "head-stats-error")
		origUsage := getBucketUsageFn
		getBucketUsageFn = func(*Handler, string) (int, int64, error) {
			return 0, 0, errors.New("usage boom")
		}
		wUsage := doRequest(
			h,
			newRequest(
				http.MethodHead,
				"http://example.test/head-stats-error?read-stats=true",
				"",
				nil,
			),
		)
		requireStatus(t, wUsage, http.StatusInternalServerError)
		requireS3ErrorCode(t, wUsage, "InternalError")
		getBucketUsageFn = origUsage
	})

	t.Run("post form additional branches", func(t *testing.T) {
		mustCreateBucket(t, b, "post-branch")

		reqEmptyKey := makeMultipartReqWithExplicitEmptyFilename(
			t,
			"http://example.test/post-branch",
			map[string]string{"key": "${filename}"},
			"data",
		)
		wEmptyKey := doRequest(h, reqEmptyKey)
		requireStatus(t, wEmptyKey, http.StatusBadRequest)
		requireS3ErrorCode(t, wEmptyKey, "InvalidArgument")

		policyForbidden := encodePolicyForTest(t, map[string]any{
			"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
			"conditions": []any{map[string]any{"bucket": "other-bucket"}},
		})
		reqForbiddenPolicy := makeMultipartReq(
			t,
			"http://example.test/post-branch",
			map[string]string{
				"key":            "k1",
				"AWSAccessKeyId": "minis3-access-key",
				"policy":         policyForbidden,
				"signature":      signPostPolicyForTest(policyForbidden),
			},
			true,
		)
		wForbiddenPolicy := doRequest(h, reqForbiddenPolicy)
		requireStatus(t, wForbiddenPolicy, http.StatusForbidden)
		requireS3ErrorCode(t, wForbiddenPolicy, "AccessDenied")

		invalidPolicy := "%%%invalid-base64%%%"
		reqInvalidPolicy := makeMultipartReq(
			t,
			"http://example.test/post-branch",
			map[string]string{
				"key":            "k2",
				"AWSAccessKeyId": "minis3-access-key",
				"policy":         invalidPolicy,
				"signature":      signPostPolicyForTest(invalidPolicy),
			},
			true,
		)
		wInvalidPolicy := doRequest(h, reqInvalidPolicy)
		requireStatus(t, wInvalidPolicy, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalidPolicy, "InvalidArgument")

		reqTagging := makeMultipartReq(
			t,
			"http://example.test/post-branch",
			map[string]string{
				"key":     "k3",
				"tagging": `<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`,
			},
			true,
		)
		wTagging := doRequest(h, reqTagging)
		requireStatus(t, wTagging, http.StatusNoContent)

		origPostPut := postObjectPutFn
		postObjectPutFn = func(
			*Handler,
			string,
			string,
			[]byte,
			backend.PutObjectOptions,
		) (*backend.Object, error) {
			return nil, errors.New("post put boom")
		}
		wPostPutInternal := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{"key": "k4"},
				true,
			),
		)
		requireStatus(t, wPostPutInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPostPutInternal, "InternalError")
		postObjectPutFn = func(
			*Handler,
			string,
			string,
			[]byte,
			backend.PutObjectOptions,
		) (*backend.Object, error) {
			return nil, backend.ErrBucketNotFound
		}
		wPostPutNoBucket := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{"key": "k5"},
				true,
			),
		)
		requireStatus(t, wPostPutNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPostPutNoBucket, "NoSuchBucket")
		postObjectPutFn = origPostPut

		origPostPutACL := postObjectPutACLFn
		postObjectPutACLFn = func(
			*Handler,
			string,
			string,
			string,
			*backend.AccessControlPolicy,
		) error {
			return errors.New("post acl boom")
		}
		wPostACL := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{
					"key": "k6",
					"acl": "public-read",
				},
				true,
			),
		)
		requireStatus(t, wPostACL, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPostACL, "InternalError")
		postObjectPutACLFn = origPostPutACL

		wRedirectWithQuery := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{
					"key":                     "k7",
					"success_action_redirect": "https://example.test/ok?x=1",
				},
				true,
			),
		)
		requireStatus(t, wRedirectWithQuery, http.StatusSeeOther)
		if loc := wRedirectWithQuery.Header().Get("Location"); !strings.Contains(loc, "&bucket=") {
			t.Fatalf("redirect location should append params to existing query: %q", loc)
		}

		wStatus200 := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{
					"key":                   "k8",
					"success_action_status": "200",
				},
				true,
			),
		)
		requireStatus(t, wStatus200, http.StatusOK)

		wStatusDefault := doRequest(
			h,
			makeMultipartReq(
				t,
				"http://example.test/post-branch",
				map[string]string{
					"key":                   "k9",
					"success_action_status": "999",
				},
				true,
			),
		)
		requireStatus(t, wStatusDefault, http.StatusNoContent)
	})
}

func TestBucketListVersioningAndConfigInternalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "cfg-err")

	t.Run("list handlers additional branches", func(t *testing.T) {
		mustPutObject(t, b, "cfg-err", "v2-obj", "data")
		if obj, err := b.GetObject("cfg-err", "v2-obj"); err == nil {
			obj.StorageClass = ""
		}
		if _, err := b.PutObject(
			"cfg-err",
			"v1-obj",
			[]byte("data"),
			backend.PutObjectOptions{ChecksumAlgorithm: "CRC32"},
		); err != nil {
			t.Fatalf("PutObject(v1-obj) failed: %v", err)
		}
		if obj, err := b.GetObject("cfg-err", "v1-obj"); err == nil {
			obj.StorageClass = ""
		}

		wV2 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/cfg-err?list-type=2&max-keys=5",
				"",
				nil,
			),
		)
		requireStatus(t, wV2, http.StatusOK)

		wV1 := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/cfg-err?max-keys=5",
				"",
				map[string]string{"x-amz-optional-object-attributes": "ChecksumAlgorithm"},
			),
		)
		requireStatus(t, wV1, http.StatusOK)

		if err := b.SetBucketVersioning("cfg-err", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		mustPutObject(t, b, "cfg-err", "ver-obj", "data")
		if obj, err := b.GetObject("cfg-err", "ver-obj"); err == nil {
			obj.StorageClass = ""
		}
		wVersions := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/cfg-err?versions&max-keys=2",
				"",
				nil,
			),
		)
		requireStatus(t, wVersions, http.StatusOK)
	})

	t.Run("put bucket versioning object-lock and internal error branches", func(t *testing.T) {
		mustCreateObjectLockBucket(t, b, "cfg-lock")

		wLockSuspend := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-lock?versioning",
				`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wLockSuspend, http.StatusConflict)
		requireS3ErrorCode(t, wLockSuspend, "InvalidBucketState")

		origSetVersioning := setBucketVersioningFn
		setBucketVersioningFn = func(
			*Handler,
			string,
			backend.VersioningStatus,
			backend.MFADeleteStatus,
		) error {
			return errors.New("set versioning boom")
		}
		wInternal := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?versioning",
				`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wInternal, "InternalError")
		setBucketVersioningFn = origSetVersioning

		wOK := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?versioning",
				`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wOK, http.StatusOK)
	})

	t.Run("bucket configuration internal error branches", func(t *testing.T) {
		ownerHeaders := map[string]string{"Authorization": authHeader("minis3-access-key")}
		b.SetBucketOwner("cfg-err", "minis3-access-key")

		origGetLocation := getBucketLocationFn
		getBucketLocationFn = func(*Handler, string) (string, error) { return "", errors.New("location boom") }
		wLocation := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?location", "", nil),
		)
		requireStatus(t, wLocation, http.StatusInternalServerError)
		requireS3ErrorCode(t, wLocation, "InternalError")
		getBucketLocationFn = origGetLocation

		origGetTagging := getBucketTaggingFn
		getBucketTaggingFn = func(*Handler, string) (map[string]string, error) {
			return nil, errors.New("tagging get boom")
		}
		wGetTag := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?tagging", "", nil),
		)
		requireStatus(t, wGetTag, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetTag, "InternalError")
		getBucketTaggingFn = origGetTagging

		origPutTagging := putBucketTaggingFn
		putBucketTaggingFn = func(*Handler, string, map[string]string) error {
			return errors.New("tagging put boom")
		}
		wPutTag := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?tagging",
				`<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`,
				nil,
			),
		)
		requireStatus(t, wPutTag, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutTag, "InternalError")
		putBucketTaggingFn = origPutTagging

		origDeleteTagging := deleteBucketTaggingFn
		deleteBucketTaggingFn = func(*Handler, string) error { return errors.New("tagging del boom") }
		wDeleteTag := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?tagging", "", nil),
		)
		requireStatus(t, wDeleteTag, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteTag, "InternalError")
		deleteBucketTaggingFn = origDeleteTagging

		origGetPolicy := getBucketPolicyFn
		getBucketPolicyFn = func(*Handler, string) (string, error) { return "", errors.New("policy get boom") }
		wGetPolicy := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?policy", "", nil),
		)
		requireStatus(t, wGetPolicy, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetPolicy, "InternalError")
		getBucketPolicyFn = origGetPolicy

		origPutPolicy := putBucketPolicyFn
		putBucketPolicyFn = func(*Handler, string, string) error { return errors.New("policy put boom") }
		wPutPolicy := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?policy",
				`{"Version":"2012-10-17","Statement":[]}`,
				ownerHeaders,
			),
		)
		requireStatus(t, wPutPolicy, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutPolicy, "InternalError")
		putBucketPolicyFn = origPutPolicy

		origDeletePolicy := deleteBucketPolicyFn
		deleteBucketPolicyFn = func(*Handler, string) error { return errors.New("policy del boom") }
		wDeletePolicy := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?policy", "", nil),
		)
		requireStatus(t, wDeletePolicy, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeletePolicy, "InternalError")
		deleteBucketPolicyFn = origDeletePolicy

		wGetACLDenied := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?acl", "", nil),
		)
		requireStatus(t, wGetACLDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wGetACLDenied, "AccessDenied")

		origGetACL := getBucketACLFn
		getBucketACLFn = func(*Handler, string) (*backend.AccessControlPolicy, error) {
			return nil, errors.New("acl get boom")
		}
		wGetACLInternal := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?acl", "", ownerHeaders),
		)
		requireStatus(t, wGetACLInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetACLInternal, "InternalError")
		getBucketACLFn = origGetACL

		origPutACL := putBucketACLFn
		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			return errors.New("acl put boom")
		}
		wPutACLCanned := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?acl",
				"",
				map[string]string{
					"Authorization": authHeader("minis3-access-key"),
					"x-amz-acl":     "private",
				},
			),
		)
		requireStatus(t, wPutACLCanned, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutACLCanned, "InternalError")

		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			return backend.ErrBucketNotFound
		}
		wPutACLNoBucket := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-bucket-for-acl?acl",
				`<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`,
				nil,
			),
		)
		requireStatus(t, wPutACLNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutACLNoBucket, "NoSuchBucket")

		putBucketACLFn = func(*Handler, string, *backend.AccessControlPolicy) error {
			return errors.New("acl put body boom")
		}
		wPutACLBodyInternal := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?acl",
				`<AccessControlPolicy><AccessControlList><Grant><Grantee><ID>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`,
				ownerHeaders,
			),
		)
		requireStatus(t, wPutACLBodyInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutACLBodyInternal, "InternalError")
		putBucketACLFn = origPutACL

		origGetLifecycle := getBucketLifecycleConfigurationFn
		getBucketLifecycleConfigurationFn = func(
			*Handler,
			string,
		) (*backend.LifecycleConfiguration, error) {
			return nil, errors.New("lc get boom")
		}
		wGetLC := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?lifecycle", "", nil),
		)
		requireStatus(t, wGetLC, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetLC, "InternalError")
		getBucketLifecycleConfigurationFn = origGetLifecycle

		wPutLCInvalid := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?lifecycle",
				`<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>-1</Days></Expiration></Rule></LifecycleConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wPutLCInvalid, http.StatusBadRequest)

		origPutLifecycle := putBucketLifecycleConfigurationFn
		putBucketLifecycleConfigurationFn = func(*Handler, string, *backend.LifecycleConfiguration) error {
			return errors.New("lc put boom")
		}
		wPutLCInternal := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?lifecycle",
				`<LifecycleConfiguration><Rule><ID>r</ID><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wPutLCInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutLCInternal, "InternalError")
		putBucketLifecycleConfigurationFn = origPutLifecycle

		origDeleteLifecycle := deleteBucketLifecycleConfigurationFn
		deleteBucketLifecycleConfigurationFn = func(*Handler, string) error {
			return errors.New("lc del boom")
		}
		wDeleteLC := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?lifecycle", "", nil),
		)
		requireStatus(t, wDeleteLC, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteLC, "InternalError")
		deleteBucketLifecycleConfigurationFn = origDeleteLifecycle

		origGetEnc := getBucketEncryptionFn
		getBucketEncryptionFn = func(*Handler, string) (*backend.ServerSideEncryptionConfiguration, error) {
			return nil, errors.New("enc get boom")
		}
		wGetEnc := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?encryption", "", nil),
		)
		requireStatus(t, wGetEnc, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetEnc, "InternalError")
		getBucketEncryptionFn = origGetEnc

		origPutEnc := putBucketEncryptionFn
		putBucketEncryptionFn = func(
			*Handler,
			string,
			*backend.ServerSideEncryptionConfiguration,
		) error {
			return errors.New("enc put boom")
		}
		wPutEnc := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?encryption",
				`<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wPutEnc, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutEnc, "InternalError")
		putBucketEncryptionFn = origPutEnc

		origDeleteEnc := deleteBucketEncryptionFn
		deleteBucketEncryptionFn = func(*Handler, string) error { return errors.New("enc del boom") }
		wDeleteEnc := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?encryption", "", nil),
		)
		requireStatus(t, wDeleteEnc, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteEnc, "InternalError")
		deleteBucketEncryptionFn = origDeleteEnc

		origGetCORS := getBucketCORSFn
		getBucketCORSFn = func(*Handler, string) (*backend.CORSConfiguration, error) {
			return nil, errors.New("cors get boom")
		}
		wGetCORS := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?cors", "", nil),
		)
		requireStatus(t, wGetCORS, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetCORS, "InternalError")
		getBucketCORSFn = origGetCORS

		origPutCORS := putBucketCORSFn
		putBucketCORSFn = func(*Handler, string, *backend.CORSConfiguration) error {
			return errors.New("cors put boom")
		}
		wPutCORS := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?cors",
				`<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wPutCORS, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutCORS, "InternalError")
		putBucketCORSFn = origPutCORS

		origDeleteCORS := deleteBucketCORSFn
		deleteBucketCORSFn = func(*Handler, string) error { return errors.New("cors del boom") }
		wDeleteCORS := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?cors", "", nil),
		)
		requireStatus(t, wDeleteCORS, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteCORS, "InternalError")
		deleteBucketCORSFn = origDeleteCORS

		origGetWebsite := getBucketWebsiteFn
		getBucketWebsiteFn = func(*Handler, string) (*backend.WebsiteConfiguration, error) {
			return nil, errors.New("website get boom")
		}
		wGetWebsite := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-err?website", "", nil),
		)
		requireStatus(t, wGetWebsite, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetWebsite, "InternalError")
		getBucketWebsiteFn = origGetWebsite

		origPutWebsite := putBucketWebsiteFn
		putBucketWebsiteFn = func(*Handler, string, *backend.WebsiteConfiguration) error {
			return errors.New("website put boom")
		}
		wPutWebsite := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?website",
				`<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>`,
				nil,
			),
		)
		requireStatus(t, wPutWebsite, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutWebsite, "InternalError")
		putBucketWebsiteFn = origPutWebsite

		origDeleteWebsite := deleteBucketWebsiteFn
		deleteBucketWebsiteFn = func(*Handler, string) error { return errors.New("website del boom") }
		wDeleteWebsite := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-err?website", "", nil),
		)
		requireStatus(t, wDeleteWebsite, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeleteWebsite, "InternalError")
		deleteBucketWebsiteFn = origDeleteWebsite

		origGetPAB := getPublicAccessBlockFn
		getPublicAccessBlockFn = func(*Handler, string) (*backend.PublicAccessBlockConfiguration, error) {
			return nil, errors.New("pab get boom")
		}
		wGetPAB := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/cfg-err?publicAccessBlock",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wGetPAB, http.StatusInternalServerError)
		requireS3ErrorCode(t, wGetPAB, "InternalError")
		getPublicAccessBlockFn = origGetPAB

		origPutPAB := putPublicAccessBlockFn
		putPublicAccessBlockFn = func(
			*Handler,
			string,
			*backend.PublicAccessBlockConfiguration,
		) error {
			return errors.New("pab put boom")
		}
		wPutPAB := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-err?publicAccessBlock",
				`<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`,
				ownerHeaders,
			),
		)
		requireStatus(t, wPutPAB, http.StatusInternalServerError)
		requireS3ErrorCode(t, wPutPAB, "InternalError")
		putPublicAccessBlockFn = origPutPAB

		origDeletePAB := deletePublicAccessBlockFn
		deletePublicAccessBlockFn = func(*Handler, string) error { return errors.New("pab del boom") }
		wDeletePAB := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/cfg-err?publicAccessBlock",
				"",
				ownerHeaders,
			),
		)
		requireStatus(t, wDeletePAB, http.StatusInternalServerError)
		requireS3ErrorCode(t, wDeletePAB, "InternalError")
		deletePublicAccessBlockFn = origDeletePAB
	})
}
