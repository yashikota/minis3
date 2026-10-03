package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyAuthorizationHeaderV4MixedCaseSignedHeaders(t *testing.T) {
	req := newV4AuthHeaderRequest(t, "minis3-access-key", time.Now().UTC())
	auth := req.Header.Get("Authorization")
	const lower = "SignedHeaders=host;x-amz-content-sha256;x-amz-date"
	const mixed = "SignedHeaders=Host;X-Amz-Content-Sha256;X-Amz-Date"
	if !strings.Contains(auth, lower) {
		t.Fatalf("expected Authorization to contain %q, got %q", lower, auth)
	}
	req.Header.Set("Authorization", strings.Replace(auth, lower, mixed, 1))
	if err := verifyAuthorizationHeader(req); err != nil {
		t.Fatalf("mixed-case SignedHeaders should verify, got %v", err)
	}
}

func TestCalculatePresignedSignatureV4MixedCaseSignedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket/key?x=1", nil)
	req.Host = "example.test"

	lowerSig := calculatePresignedSignatureV4(
		req,
		"minis3-secret-key",
		"20260207",
		"us-east-1",
		"s3",
		"host;x-amz-date",
	)
	mixedSig := calculatePresignedSignatureV4(
		req,
		"minis3-secret-key",
		"20260207",
		"us-east-1",
		"s3",
		"Host;X-Amz-Date",
	)
	if lowerSig != mixedSig {
		t.Fatalf("expected mixed-case signature to match lowercase: %q vs %q", mixedSig, lowerSig)
	}
}

func TestVerifyPresignedURLV4MixedCaseSignedHeaders(t *testing.T) {
	requestTime := time.Now().UTC().Add(-1 * time.Minute)
	dateStamp := requestTime.Format("20060102")
	amzDate := requestTime.Format("20060102T150405Z")
	credential := "minis3-access-key/" + dateStamp + "/us-east-1/s3/aws4_request"

	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", strconv.FormatInt(300, 10))
	query.Set("X-Amz-SignedHeaders", "Host")

	req := httptest.NewRequest(
		http.MethodGet,
		"http://example.test/bucket/key?"+query.Encode(),
		nil,
	)
	req.Host = "example.test"

	secretKey := DefaultCredentials()["minis3-access-key"]
	signature := calculatePresignedSignatureV4(req, secretKey, dateStamp, "us-east-1", "s3", "Host")
	query.Set("X-Amz-Signature", signature)
	req.URL.RawQuery = query.Encode()

	if err := verifyPresignedURL(req); err != nil {
		t.Fatalf("mixed-case presigned SignedHeaders should verify, got %v", err)
	}
}

func TestVerifyPresignedURLV4EmptySignedHeaderSegment(t *testing.T) {
	requestTime := time.Now().UTC().Add(-1 * time.Minute)
	dateStamp := requestTime.Format("20060102")
	amzDate := requestTime.Format("20060102T150405Z")
	credential := "minis3-access-key/" + dateStamp + "/us-east-1/s3/aws4_request"

	// Empty segments (e.g. from "host;;x-amz-date") must be skipped when
	// building the canonical request instead of breaking verification.
	const signedHeaders = "host;;x-amz-date"

	query := url.Values{}
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", credential)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", strconv.FormatInt(300, 10))
	query.Set("X-Amz-SignedHeaders", signedHeaders)

	req := httptest.NewRequest(
		http.MethodGet,
		"http://example.test/bucket/key?"+query.Encode(),
		nil,
	)
	req.Host = "example.test"

	secretKey := DefaultCredentials()["minis3-access-key"]
	signature := calculatePresignedSignatureV4(
		req,
		secretKey,
		dateStamp,
		"us-east-1",
		"s3",
		signedHeaders,
	)
	query.Set("X-Amz-Signature", signature)
	req.URL.RawQuery = query.Encode()

	if err := verifyPresignedURL(req); err != nil {
		t.Fatalf("presigned SignedHeaders with empty segment should verify, got %v", err)
	}
}

func TestIso8601FromHTTPDateHeader(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"rfc1123 GMT", "Sat, 03 Oct 2026 17:56:02 GMT", "20261003T175602Z"},
		{"rfc1123 numeric zone", "Sat, 03 Oct 2026 17:56:02 -0000", "20261003T175602Z"},
		{"rfc1123 UTC", "Sat, 03 Oct 2026 17:56:02 UTC", "20261003T175602Z"},
		{"surrounding spaces", "  Sat, 03 Oct 2026 17:56:02 GMT  ", "20261003T175602Z"},
		{"empty", "", ""},
		{"blank", "   ", ""},
		{"garbage", "not-a-date", ""},
		{"iso8601 passthrough rejected", "20261003T175602Z", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := iso8601FromHTTPDateHeader(tc.value); got != tc.want {
				t.Fatalf("iso8601FromHTTPDateHeader(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// signV4HeaderRequest builds a SigV4 Authorization-header request signed over
// the given headers, mirroring how AWS SDKs sign when a Date header is used
// instead of X-Amz-Date.
func signV4HeaderRequest(
	t *testing.T,
	accessKey string,
	when time.Time,
	headers map[string]string,
	signedHeaders string,
) *http.Request {
	t.Helper()

	dateStamp := when.Format("20060102")
	amzDate := when.Format("20060102T150405Z")
	credential := accessKey + "/" + dateStamp + "/us-east-1/s3/aws4_request"

	req := httptest.NewRequest(http.MethodGet, "http://example.test/bucket/key?x=1", nil)
	req.Host = "example.test"
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	parts := strings.Split(signedHeaders, ";")
	sortedParts := append([]string(nil), parts...)
	sort.Strings(sortedParts)
	canonicalHeaders := ""
	for _, header := range sortedParts {
		var value string
		if header == "host" {
			value = req.Host
		} else {
			value = req.Header.Get(header)
		}
		canonicalHeaders += header + ":" + strings.TrimSpace(value) + "\n"
	}
	normalizedSignedHeaders := strings.Join(sortedParts, ";")
	canonicalRequest := req.Method + "\n" + req.URL.EscapedPath() + "\n" + "x=1" + "\n" +
		canonicalHeaders + "\n" + normalizedSignedHeaders + "\n" + "UNSIGNED-PAYLOAD"
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

func TestVerifyAuthorizationHeaderV4DateHeaderFallback(t *testing.T) {
	when := time.Date(2026, time.October, 3, 17, 56, 2, 0, time.UTC)

	t.Run("date only verifies", func(t *testing.T) {
		req := signV4HeaderRequest(t, "minis3-access-key", when, map[string]string{
			"Date":                 when.Format(time.RFC1123),
			"x-amz-content-sha256": "UNSIGNED-PAYLOAD",
		}, "date;host;x-amz-content-sha256")
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("Date-only SigV4 request should verify, got %v", err)
		}
	})

	t.Run("numeric zone date verifies", func(t *testing.T) {
		req := signV4HeaderRequest(t, "minis3-access-key", when, map[string]string{
			"Date":                 when.Format(time.RFC1123Z),
			"x-amz-content-sha256": "UNSIGNED-PAYLOAD",
		}, "date;host;x-amz-content-sha256")
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("numeric-zone Date SigV4 request should verify, got %v", err)
		}
	})

	t.Run("x-amz-date takes precedence", func(t *testing.T) {
		other := when.Add(time.Hour)
		req := signV4HeaderRequest(t, "minis3-access-key", when, map[string]string{
			"Date":                 other.Format(time.RFC1123),
			"x-amz-date":           when.Format("20060102T150405Z"),
			"x-amz-content-sha256": "UNSIGNED-PAYLOAD",
		}, "date;host;x-amz-content-sha256;x-amz-date")
		if err := verifyAuthorizationHeader(req); err != nil {
			t.Fatalf("x-amz-date precedence request should verify, got %v", err)
		}
	})
}
