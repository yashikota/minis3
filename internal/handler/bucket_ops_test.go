package handler

import (
	"bytes"
	"encoding/xml"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func postMultipartForm(
	t *testing.T,
	h *Handler,
	url string,
	fields map[string]string,
	fileName, fileBody string,
) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%q) failed: %v", k, err)
		}
	}
	fw, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := fw.Write([]byte(fileBody)); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart failed: %v", err)
	}

	req := newRequest(http.MethodPost, url, body.String(), nil)
	req.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	req.ContentLength = int64(body.Len())
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return doRequest(h, req)
}

func TestBucketOperationHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket")
	mustPutObject(t, b, "bucket", "a/1.txt", "one")
	mustPutObject(t, b, "bucket", "a/2.txt", "two")

	if err := b.SetBucketVersioning("bucket", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	mustPutObject(t, b, "bucket", "versioned.txt", "v1")
	if _, err := b.DeleteObject("bucket", "versioned.txt", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	t.Run("post object form upload missing bucket", func(t *testing.T) {
		w := postMultipartForm(
			t,
			h,
			"http://example.test/nope",
			map[string]string{"key": "k"},
			"f.txt",
			"data",
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("post object form upload success", func(t *testing.T) {
		w := postMultipartForm(
			t,
			h,
			"http://example.test/bucket",
			map[string]string{"key": "upload/${filename}", "success_action_status": "201"},
			"f.txt",
			"data",
		)
		requireStatus(t, w, http.StatusCreated)
	})

	t.Run("list objects v2 invalid max-keys", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/bucket?list-type=2&max-keys=-1",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list objects v2 success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/bucket?list-type=2&prefix=a/&delimiter=/&encoding-type=url&fetch-owner=true",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("list objects v1 invalid max-keys", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?max-keys=-1", "", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list objects v1 success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/bucket?prefix=a/&delimiter=/&encoding-type=url",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("list object versions invalid max-keys", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?versions&max-keys=-1", "", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list object versions success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/bucket?versions&prefix=versioned&encoding-type=url",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("get bucket versioning success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?versioning", "", nil),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("put bucket versioning malformed xml", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?versioning", "<bad", nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("put bucket versioning mfa required invalid", func(t *testing.T) {
		payload := `<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?versioning", payload, nil),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("validate mfa header", func(t *testing.T) {
		if err := validateMFAHeader(""); err == nil {
			t.Fatal("expected error")
		}
		if err := validateMFAHeader("arn:aws:iam::123456789012:mfa/user 123456"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("get bucket location success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?location", "", nil),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("tagging put/get/delete", func(t *testing.T) {
		put := `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?tagging", put, nil),
		)
		requireStatus(t, wPut, http.StatusNoContent)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?tagging", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?tagging", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("policy put/get/status/delete", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?policy", policy, nil),
		)
		requireStatus(t, wPut, http.StatusNoContent)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?policy", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		wStatus := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?policyStatus", "", nil),
		)
		requireStatus(t, wStatus, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?policy", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("lifecycle put/get/delete", func(t *testing.T) {
		payload := `<LifecycleConfiguration><Rule><ID>r1</ID><Prefix>test1/</Prefix><Status>Enabled</Status></Rule></LifecycleConfiguration>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?lifecycle", payload, nil),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?lifecycle", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		var cfg backend.LifecycleConfiguration
		if err := xml.Unmarshal(wGet.Body.Bytes(), &cfg); err != nil {
			t.Fatalf("failed to parse lifecycle configuration: %v body=%s", err, wGet.Body.String())
		}
		if len(cfg.Rules) != 1 || cfg.Rules[0].Prefix != "test1/" {
			t.Fatalf("unexpected lifecycle rules: %+v", cfg.Rules)
		}
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?lifecycle", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("encryption put/get/delete", func(t *testing.T) {
		payload := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?encryption", payload, nil),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?encryption", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?encryption", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("cors put/get/delete", func(t *testing.T) {
		payload := `<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?cors", payload, nil),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(h, newRequest(http.MethodGet, "http://example.test/bucket?cors", "", nil))
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?cors", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("website put/get/delete", func(t *testing.T) {
		payload := `<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket?website", payload, nil),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?website", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?website", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("public access block put/get/delete", func(t *testing.T) {
		payload := `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>false</IgnorePublicAcls><BlockPublicPolicy>false</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket?publicAccessBlock",
				payload,
				nil,
			),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket?publicAccessBlock", "", nil),
		)
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/bucket?publicAccessBlock", "", nil),
		)
		requireStatus(t, wDel, http.StatusNoContent)
	})
}
