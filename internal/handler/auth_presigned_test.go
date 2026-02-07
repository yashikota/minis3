package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newV4PresignedRequest(
	t *testing.T,
	method, path, accessKey string,
	requestTime time.Time,
	expires int64,
) *http.Request {
	t.Helper()

	dateStamp := requestTime.Format("20060102")
	amzDate := requestTime.Format("20060102T150405Z")
	credential := accessKey + "/" + dateStamp + "/us-east-1/s3/aws4_request"

	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", strconv.FormatInt(expires, 10))
	query.Set("X-Amz-SignedHeaders", "host")

	req := httptest.NewRequest(method, "http://example.test"+path+"?"+query.Encode(), nil)
	req.Host = "example.test"

	secretKey := DefaultCredentials()[accessKey]
	signature := calculatePresignedSignatureV4(
		req,
		secretKey,
		dateStamp,
		"us-east-1",
		"s3",
		"host",
	)
	query.Set("X-Amz-Signature", signature)
	req.URL.RawQuery = query.Encode()
	return req
}

func requirePresignedErrorCode(t *testing.T, err error, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %q, got nil", wantCode)
	}
	pe, ok := err.(*presignedError)
	if !ok {
		t.Fatalf("expected *presignedError, got %T (%v)", err, err)
	}
	if pe.code != wantCode {
		t.Fatalf("unexpected error code: got %q, want %q", pe.code, wantCode)
	}
}

func TestIsPresignedURL(t *testing.T) {
	t.Run("detects v4 presigned URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key?X-Amz-Signature=sig", nil)
		if !isPresignedURL(req) {
			t.Fatal("expected request to be detected as presigned URL")
		}
	})

	t.Run("detects v2 presigned URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key?Signature=sig", nil)
		if !isPresignedURL(req) {
			t.Fatal("expected request to be detected as presigned URL")
		}
	})

	t.Run("non-presigned URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if isPresignedURL(req) {
			t.Fatal("expected request to not be detected as presigned URL")
		}
	})
}

func TestVerifyPresignedURLV4(t *testing.T) {
	now := time.Now().UTC().Add(-1 * time.Minute)

	t.Run("valid signature", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			300,
		)
		if err := verifyPresignedURL(req); err != nil {
			t.Fatalf("expected valid presigned URL, got %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			300,
		)
		values := req.URL.Query()
		values.Set("X-Amz-Signature", strings.Repeat("0", len(values.Get("X-Amz-Signature"))))
		req.URL.RawQuery = values.Encode()
		requirePresignedErrorCode(t, verifyPresignedURL(req), "SignatureDoesNotMatch")
	})

	t.Run("unknown access key", func(t *testing.T) {
		dateStamp := now.Format("20060102")
		amzDate := now.Format("20060102T150405Z")
		query := url.Values{}
		query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		query.Set("X-Amz-Credential", "unknown/"+dateStamp+"/us-east-1/s3/aws4_request")
		query.Set("X-Amz-Date", amzDate)
		query.Set("X-Amz-Expires", "300")
		query.Set("X-Amz-SignedHeaders", "host")
		query.Set("X-Amz-Signature", "deadbeef")

		req := httptest.NewRequest(
			http.MethodGet,
			"http://example.test/bucket/key?"+query.Encode(),
			nil,
		)
		req.Host = "example.test"

		requirePresignedErrorCode(t, verifyPresignedURL(req), "InvalidAccessKeyId")
	})

	t.Run("expired request", func(t *testing.T) {
		expiredTime := time.Now().UTC().Add(-2 * time.Hour)
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			expiredTime,
			60,
		)
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AccessDenied")
	})

	t.Run("expires larger than max", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			604801,
		)
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AuthorizationQueryParametersError")
	})

	t.Run("invalid algorithm", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			300,
		)
		values := req.URL.Query()
		values.Set("X-Amz-Algorithm", "INVALID")
		req.URL.RawQuery = values.Encode()
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AuthorizationQueryParametersError")
	})

	t.Run("missing x-amz-date", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			300,
		)
		values := req.URL.Query()
		values.Del("X-Amz-Date")
		req.URL.RawQuery = values.Encode()
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AuthorizationQueryParametersError")
	})

	t.Run("invalid expires format", func(t *testing.T) {
		req := newV4PresignedRequest(
			t,
			http.MethodGet,
			"/bucket/key",
			"minis3-access-key",
			now,
			300,
		)
		values := req.URL.Query()
		values.Set("X-Amz-Expires", "not-a-number")
		req.URL.RawQuery = values.Encode()
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AuthorizationQueryParametersError")
	})
}

func TestVerifyPresignedURLV2(t *testing.T) {
	t.Run("valid non-expired request", func(t *testing.T) {
		expires := time.Now().Add(5 * time.Minute).Unix()
		req := httptest.NewRequest(
			http.MethodGet,
			"/bucket/key?Signature=any&Expires="+strconv.FormatInt(expires, 10),
			nil,
		)
		if err := verifyPresignedURL(req); err != nil {
			t.Fatalf("expected valid v2 request, got %v", err)
		}
	})

	t.Run("expired request", func(t *testing.T) {
		expires := time.Now().Add(-5 * time.Minute).Unix()
		req := httptest.NewRequest(
			http.MethodGet,
			"/bucket/key?Signature=any&Expires="+strconv.FormatInt(expires, 10),
			nil,
		)
		requirePresignedErrorCode(t, verifyPresignedURL(req), "AccessDenied")
	})

	t.Run("missing expires", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key?Signature=any", nil)
		requirePresignedErrorCode(t, verifyPresignedURL(req), "MissingSecurityHeader")
	})
}
