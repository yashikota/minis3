package handler

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// placeholderSignature marks a SigV2 Authorization header that doRequest
// replaces with a real signature (see signTestRequest).
const placeholderSignature = "sig"

// authHeader returns a SigV2 Authorization header for accessKey with a
// placeholder signature; doRequest signs it for real.
func authHeader(accessKey string) string {
	if accessKey == "" {
		return ""
	}
	return "AWS " + accessKey + ":" + placeholderSignature
}

// signTestRequest replaces a placeholder SigV2 signature with a valid one,
// adding a Date header when the request has none. Access keys the handler
// does not know are registered with a derived secret first, so tests can
// use any key as a distinct caller.
func signTestRequest(h *Handler, r *http.Request) {
	auth := r.Header.Get("Authorization")
	accessKey, ok := strings.CutPrefix(auth, "AWS ")
	if !ok {
		return
	}
	accessKey, ok = strings.CutSuffix(accessKey, ":"+placeholderSignature)
	if !ok || accessKey == "" {
		return
	}
	secretKey, known := h.lookupCredential(accessKey)
	if !known {
		secretKey = "test-secret-" + accessKey
		h.addCredential(accessKey, secretKey)
	}
	date := ""
	if _, ok := r.Header["X-Amz-Date"]; !ok {
		if r.Header.Get("Date") == "" {
			r.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}
		date = r.Header.Get("Date")
	}
	signature := sigV2Signature(secretKey, sigV2StringsToSign(r, date)[0])
	r.Header.Set("Authorization", "AWS "+accessKey+":"+signature)
}

func newRequest(method, target, body string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func doRequest(h *Handler, req *http.Request) *httptest.ResponseRecorder {
	signTestRequest(h, req)
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
	if er.Code == "" {
		// IAM Query-protocol errors nest the code inside <ErrorResponse><Error>.
		var envelope struct {
			Error s3ErrorResponse `xml:"Error"`
		}
		if err := xml.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("failed to decode error response: %v body=%s", err, w.Body.String())
		}
		er = envelope.Error
	}
	if er.Code != wantCode {
		t.Fatalf("error code = %q, want %q, body=%s", er.Code, wantCode, w.Body.String())
	}
}

// mustUpdateObject changes stored object state no S3 operation sets.
func mustUpdateObject(
	t *testing.T,
	b *backend.Backend,
	bucketName, key string,
	fn func(*backend.Object),
) {
	t.Helper()
	if err := b.UpdateObject(bucketName, key, "", fn); err != nil {
		t.Fatalf("UpdateObject(%s/%s): %v", bucketName, key, err)
	}
}

// mustUpdateBucket changes stored bucket state no S3 operation sets.
func mustUpdateBucket(t *testing.T, b *backend.Backend, name string, fn func(*backend.Bucket)) {
	t.Helper()
	if err := b.UpdateBucket(name, fn); err != nil {
		t.Fatalf("UpdateBucket(%s): %v", name, err)
	}
}
