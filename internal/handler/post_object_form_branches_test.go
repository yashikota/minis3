package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"
)

func makeMultipartReq(
	t *testing.T,
	target string,
	fields map[string]string,
	includeFile bool,
) *http.Request {
	return makeMultipartReqWithFileName(t, target, fields, includeFile, "f.txt")
}

func makeMultipartReqWithFileName(
	t *testing.T,
	target string,
	fields map[string]string,
	includeFile bool,
	fileName string,
) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("WriteField(%q) failed: %v", k, err)
		}
	}
	if includeFile {
		fw, err := mw.CreateFormFile("file", fileName)
		if err != nil {
			t.Fatalf("CreateFormFile failed: %v", err)
		}
		if _, err := fw.Write([]byte("file-body")); err != nil {
			t.Fatalf("write file failed: %v", err)
		}
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

func encodeSimplePostPolicy(t *testing.T, bucket string) string {
	t.Helper()
	p := map[string]any{
		"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
		"conditions": []any{map[string]any{"bucket": bucket}},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func signPostPolicy(t *testing.T, accessKey, policyB64 string) string {
	t.Helper()
	secret, ok := DefaultCredentials()[accessKey]
	if !ok {
		t.Fatalf("missing credentials for access key %q", accessKey)
	}
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write([]byte(strings.TrimSpace(policyB64)))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestHandlePostObjectFormUploadBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "form-bucket")

	t.Run("invalid multipart body", func(t *testing.T) {
		req := newRequest(http.MethodPost, "http://example.test/form-bucket", "plain", nil)
		req.Header.Set("Content-Type", "text/plain")
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("missing file field", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "k"},
			false,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("missing key field", func(t *testing.T) {
		req := makeMultipartReq(t, "http://example.test/form-bucket", map[string]string{}, true)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("key resolves empty after filename substitution", func(t *testing.T) {
		req := makeMultipartReqWithFileName(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "${filename}"},
			true,
			"",
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("missing policy fields", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "k", "AWSAccessKeyId": "minis3-access-key"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("invalid policy signature", func(t *testing.T) {
		policy := encodeSimplePostPolicy(t, "form-bucket")
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":            "k",
				"AWSAccessKeyId": "minis3-access-key",
				"policy":         policy,
				"signature":      "bad",
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("policy validation fails with bad request", func(t *testing.T) {
		accessKey := "minis3-access-key"
		policyDoc := map[string]any{
			"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
			"conditions": []any{
				map[string]any{"bucket": "form-bucket"},
				[]any{"content-length-range", 100, 200},
			},
		}
		raw, err := json.Marshal(policyDoc)
		if err != nil {
			t.Fatalf("marshal policy failed: %v", err)
		}
		policy := base64.StdEncoding.EncodeToString(raw)
		signature := signPostPolicy(t, accessKey, policy)

		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":            "k",
				"AWSAccessKeyId": accessKey,
				"policy":         policy,
				"signature":      signature,
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("policy validation fails with forbidden", func(t *testing.T) {
		accessKey := "minis3-access-key"
		policyDoc := map[string]any{
			"expiration": time.Now().UTC().Add(-10 * time.Minute).Format("2006-01-02T15:04:05Z"),
			"conditions": []any{
				map[string]any{"bucket": "form-bucket"},
			},
		}
		raw, err := json.Marshal(policyDoc)
		if err != nil {
			t.Fatalf("marshal policy failed: %v", err)
		}
		policy := base64.StdEncoding.EncodeToString(raw)
		signature := signPostPolicy(t, accessKey, policy)

		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":            "k",
				"AWSAccessKeyId": accessKey,
				"policy":         policy,
				"signature":      signature,
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("invalid tagging xml", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "k", "tagging": "<bad"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("checksum validation failed", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "k", "x-amz-checksum-sha256": "wrong"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("success redirect", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "r", "success_action_redirect": "https://example.test/ok"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusSeeOther)
	})

	t.Run("success redirect appends query parameters", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":                     "r2",
				"success_action_redirect": "https://example.test/ok?x=1",
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusSeeOther)
		loc := w.Header().Get("Location")
		if !strings.Contains(loc, "x=1&") ||
			!strings.Contains(loc, "bucket=form-bucket") ||
			!strings.Contains(loc, "key=r2") {
			t.Fatalf("unexpected redirect location: %q", loc)
		}
	})

	t.Run("success with tagging sets object tags", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":     "tagged",
				"tagging": `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`,
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)

		obj, err := b.GetObject("form-bucket", "tagged")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if obj.Tags["k"] != "v" {
			t.Fatalf("unexpected tags: %+v", obj.Tags)
		}
	})

	t.Run("success status 200", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "ok200", "success_action_status": "200"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("invalid success status defaults to 204", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "default204", "success_action_status": "999"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)
	})

	t.Run("success default status", func(t *testing.T) {
		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{"key": "final"},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)
	})
}
