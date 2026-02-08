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
	"testing"
	"time"
)

func makeMultipartReq(
	t *testing.T,
	target string,
	fields map[string]string,
	includeFile bool,
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
		fw, err := mw.CreateFormFile("file", "f.txt")
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

func encodePostPolicyWithKeyPrefix(t *testing.T, bucket, keyPrefix string) string {
	t.Helper()
	p := map[string]any{
		"expiration": time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z"),
		"conditions": []any{
			map[string]any{"bucket": bucket},
			[]any{"starts-with", "$key", keyPrefix},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
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

	t.Run(
		"policy signature valid but missing form field condition is rejected",
		func(t *testing.T) {
			policy := encodeSimplePostPolicy(t, "form-bucket")
			mac := hmac.New(sha1.New, []byte("minis3-secret-key"))
			_, _ = mac.Write([]byte(policy))
			signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

			req := makeMultipartReq(
				t,
				"http://example.test/form-bucket",
				map[string]string{
					"key":            "k",
					"AWSAccessKeyId": "minis3-access-key",
					"policy":         policy,
					"signature":      signature,
				},
				true,
			)
			w := doRequest(h, req)
			requireStatus(t, w, http.StatusForbidden)
			requireS3ErrorCode(t, w, "AccessDenied")
		},
	)

	t.Run("policy signature valid with key condition succeeds", func(t *testing.T) {
		policy := encodePostPolicyWithKeyPrefix(t, "form-bucket", "ok/")
		mac := hmac.New(sha1.New, []byte("minis3-secret-key"))
		_, _ = mac.Write([]byte(policy))
		signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		req := makeMultipartReq(
			t,
			"http://example.test/form-bucket",
			map[string]string{
				"key":            "ok/file.txt",
				"AWSAccessKeyId": "minis3-access-key",
				"policy":         policy,
				"signature":      signature,
			},
			true,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNoContent)
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
