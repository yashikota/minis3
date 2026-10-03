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

func TestVerifyAuthorizationHeaderV4EmptySignedHeaderSegment(t *testing.T) {
	req := newV4AuthHeaderRequest(t, "minis3-access-key", time.Now().UTC())
	auth := req.Header.Get("Authorization")
	const lower = "SignedHeaders=host;x-amz-content-sha256;x-amz-date"
	const emptied = "SignedHeaders=host;;x-amz-content-sha256;x-amz-date"
	if !strings.Contains(auth, lower) {
		t.Fatalf("expected Authorization to contain %q, got %q", lower, auth)
	}
	req.Header.Set("Authorization", strings.Replace(auth, lower, emptied, 1))
	if err := verifyAuthorizationHeader(req); err != nil {
		t.Fatalf("SignedHeaders with empty segment should verify, got %v", err)
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
