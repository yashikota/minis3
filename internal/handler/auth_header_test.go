package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newV4AuthHeaderRequest(t *testing.T, accessKey string, when time.Time) *http.Request {
	t.Helper()

	dateStamp := when.Format("20060102")
	amzDate := when.Format("20060102T150405Z")
	credential := accessKey + "/" + dateStamp + "/us-east-1/s3/aws4_request"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket/key?x=1", nil)
	req.Host = "example.test"
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")

	canonicalURI := req.URL.EscapedPath()
	canonicalQueryString := "x=1"
	canonicalHeaders := "host:example.test\n" +
		"x-amz-content-sha256:UNSIGNED-PAYLOAD\n" +
		"x-amz-date:" + amzDate + "\n"
	canonicalRequest := req.Method + "\n" + canonicalURI + "\n" + canonicalQueryString + "\n" +
		canonicalHeaders + "\n" + signedHeaders + "\n" + "UNSIGNED-PAYLOAD"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" +
		dateStamp + "/us-east-1/s3/aws4_request\n" + sha256Hash(canonicalRequest)

	secret := DefaultCredentials()[accessKey]
	signingKey := getSignatureKey(secret, dateStamp, "us-east-1", "s3")
	sig := hmacSHA256Hex(signingKey, stringToSign)

	req.Header.Set(
		"Authorization",
		"AWS4-HMAC-SHA256 Credential="+credential+", SignedHeaders="+signedHeaders+", Signature="+sig,
	)
	return req
}

func requirePresignedErrCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %q, got nil", want)
	}
	pe, ok := err.(*presignedError)
	if !ok {
		t.Fatalf("expected presignedError, got %T (%v)", err, err)
	}
	if pe.code != want {
		t.Fatalf("code = %q, want %q", pe.code, want)
	}
}

func TestVerifyAuthorizationHeader(t *testing.T) {
	t.Run("no authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unknown access key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		req.Header.Set("Authorization", "AWS unknown:sig")
		requirePresignedErrCode(t, verifyAuthorizationHeader(req), "InvalidAccessKeyId")
	})

	t.Run("unsupported authorization scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		req.Header.Set("Authorization", "Bearer token")
		requirePresignedErrCode(t, verifyAuthorizationHeader(req), "InvalidAccessKeyId")
	})

	t.Run("v2 malformed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		req.Header.Set("Authorization", "AWS minis3-access-key")
		requirePresignedErrCode(t, verifyAuthorizationHeader(req), "AccessDenied")
	})

	t.Run("v2 success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		req.Header.Set("Authorization", "AWS minis3-access-key:sig")
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("v4 missing fields", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
		req.Header.Set(
			"Authorization",
			"AWS4-HMAC-SHA256 Credential=minis3-access-key/20260207/us-east-1/s3/aws4_request",
		)
		requirePresignedErrCode(t, verifyAuthorizationHeader(req), "AccessDenied")
	})

	t.Run("v4 signature mismatch", func(t *testing.T) {
		req := newV4AuthHeaderRequest(t, "minis3-access-key", time.Now().UTC())
		req.Header.Set(
			"Authorization",
			"AWS4-HMAC-SHA256 Credential=minis3-access-key/20260207/us-east-1/s3/aws4_request, "+
				"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef",
		)
		requirePresignedErrCode(t, verifyAuthorizationHeader(req), "SignatureDoesNotMatch")
	})

	t.Run("v4 success", func(t *testing.T) {
		req := newV4AuthHeaderRequest(t, "minis3-access-key", time.Now().UTC())
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
