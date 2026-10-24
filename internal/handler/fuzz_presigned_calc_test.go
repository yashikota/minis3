package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func FuzzCalculatePresignedSignatureV4(f *testing.F) {
	f.Add(
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"20130524",
		"us-east-1",
		"s3",
		"host",
		"GET",
		"/bucket/key",
		"X-Amz-Date=20130524T000000Z&X-Amz-Credential=AKID/20130524/us-east-1/s3/aws4_request",
		"localhost",
	)
	f.Add(
		"secret",
		"20230101",
		"eu-west-1",
		"s3",
		"host;x-amz-content-sha256",
		"PUT",
		"/bucket/obj",
		"X-Amz-Date=20230101T120000Z",
		"s3.eu-west-1.amazonaws.com",
	)
	f.Add("", "", "", "", "", "GET", "/", "", "localhost")
	f.Add("key", "date", "region", "service", "host", "POST", "/bucket", "", "")

	f.Fuzz(
		func(t *testing.T, secretKey, dateStamp, region, service, signedHeaders, method, path, query, host string) {
			req, err := http.NewRequest(method, path+"?"+query, nil)
			if err != nil {
				return
			}
			req.Host = host
			_ = calculatePresignedSignatureV4(
				req,
				secretKey,
				dateStamp,
				region,
				service,
				signedHeaders,
			)
		},
	)
}

func FuzzVerifyAuthorizationHeaderV2(f *testing.F) {
	f.Add("GET", "/bucket/key", "acl", "x-amz-meta-a", "1", "text/plain", "AWS key:sig")
	f.Add("PUT", "/bucket/k%20ey", "versionId=3&prefix=p", "X-Amz-Acl", "private", "", "AWS a:b:c")
	f.Add("DELETE", "/b", "uploads", "x-amz-date", "", "", "")

	f.Fuzz(func(t *testing.T, method, path, rawQuery, header, value, contentType, auth string) {
		target := "http://example.test" + path
		if rawQuery != "" {
			target += "?" + rawQuery
		}
		req, err := http.NewRequest(method, target, nil)
		if err != nil || req.URL.Path == "" || strings.ContainsAny(header, "\r\n:") ||
			header == "" {
			return
		}
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		if strings.EqualFold(header, "x-amz-date") {
			return
		}
		req.Header.Set(header, value)
		req.Header.Set("Content-Type", contentType)

		// Arbitrary headers never pass unless they carry a valid signature.
		if err := verifyAuthorizationHeaderV2(req, auth); err == nil {
			parts := strings.SplitN(strings.TrimPrefix(auth, "AWS "), ":", 2)
			secret := DefaultCredentials()[parts[0]]
			if !verifySigV2Signature(req, secret, req.Header.Get("Date"), parts[1]) {
				t.Fatalf("%q accepted without a valid signature", auth)
			}
		}

		// Oracle: a request signed with the right secret verifies, and
		// with any other secret or a tampered element it does not.
		date := req.Header.Get("Date")
		signature := sigV2Signature("minis3-secret-key", sigV2StringsToSign(req, date)[0])
		signed := "AWS minis3-access-key:" + signature
		if err := verifyAuthorizationHeaderV2(req, signed); err != nil {
			t.Fatalf("own signature rejected: %v", err)
		}
		if verifyAuthorizationHeaderV2(req, "AWS minis3-access-key:"+
			sigV2Signature("minis3-alt-secret-key", sigV2StringsToSign(req, date)[0])) == nil {
			t.Fatal("signature from another secret accepted")
		}
		other := req.Clone(req.Context())
		other.Method = method + "X"
		if verifyAuthorizationHeaderV2(other, signed) == nil {
			t.Fatal("signature accepted for another method")
		}
	})
}

func FuzzDefaultCredentialLookup(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("")
	f.Add("nonexistent-key")
	f.Add("accessKey1")
	f.Add("minioadmin")

	f.Fuzz(func(t *testing.T, accessKey string) {
		_, _ = defaultCredentialLookup(accessKey)
	})
}

func FuzzGenerateRequestId(f *testing.F) {
	f.Add(1)
	f.Add(100)

	f.Fuzz(func(t *testing.T, _ int) {
		result := generateRequestId()
		if len(result) != 16 {
			t.Errorf("expected 16 chars, got %d", len(result))
		}
	})
}
