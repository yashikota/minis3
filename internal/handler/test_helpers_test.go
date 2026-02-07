package handler

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

type s3ErrorResponse struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func newTestHandler(t *testing.T) (*Handler, *backend.Backend) {
	t.Helper()
	b := backend.New()
	return New(b), b
}

func mustCreateBucket(t *testing.T, b *backend.Backend, name string) {
	t.Helper()
	if err := b.CreateBucket(name); err != nil {
		t.Fatalf("CreateBucket(%q) failed: %v", name, err)
	}
}

func mustCreateObjectLockBucket(t *testing.T, b *backend.Backend, name string) {
	t.Helper()
	if err := b.CreateBucketWithObjectLock(name); err != nil {
		t.Fatalf("CreateBucketWithObjectLock(%q) failed: %v", name, err)
	}
}

func mustPutObject(t *testing.T, b *backend.Backend, bucket, key, body string) {
	t.Helper()
	if _, err := b.PutObject(bucket, key, []byte(body), backend.PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject(%q/%q) failed: %v", bucket, key, err)
	}
}

func authHeader(accessKey string) string {
	if accessKey == "" {
		return ""
	}
	return "AWS " + accessKey + ":sig"
}

func newRequest(method, target, body string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func doRequest(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, want, w.Body.String())
	}
}

func requireS3ErrorCode(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var er s3ErrorResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &er); err != nil {
		t.Fatalf("failed to decode S3 error response: %v body=%s", err, w.Body.String())
	}
	if er.Code != wantCode {
		t.Fatalf("error code = %q, want %q, body=%s", er.Code, wantCode, w.Body.String())
	}
}
