package handler

import (
	"net/http"
	"testing"
)

func FuzzCalculatePresignedSignatureV4(f *testing.F) {
	f.Add("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3", "host", "GET", "/bucket/key", "X-Amz-Date=20130524T000000Z&X-Amz-Credential=AKID/20130524/us-east-1/s3/aws4_request", "localhost")
	f.Add("secret", "20230101", "eu-west-1", "s3", "host;x-amz-content-sha256", "PUT", "/bucket/obj", "X-Amz-Date=20230101T120000Z", "s3.eu-west-1.amazonaws.com")
	f.Add("", "", "", "", "", "GET", "/", "", "localhost")
	f.Add("key", "date", "region", "service", "host", "POST", "/bucket", "", "")

	f.Fuzz(func(t *testing.T, secretKey, dateStamp, region, service, signedHeaders, method, path, query, host string) {
		req, err := http.NewRequest(method, path+"?"+query, nil)
		if err != nil {
			return
		}
		req.Host = host
		_ = calculatePresignedSignatureV4(req, secretKey, dateStamp, region, service, signedHeaders)
	})
}

func FuzzVerifyAuthorizationHeaderV2(f *testing.F) {
	f.Add("AWS AKIAIOSFODNN7EXAMPLE:signature")
	f.Add("AWS :empty")
	f.Add("AWS key:")
	f.Add("")
	f.Add("AWS AKID:sig123")
	f.Add("invalid")
	f.Add("AWS a:b:c")

	f.Fuzz(func(t *testing.T, auth string) {
		req, err := http.NewRequest(http.MethodGet, "/bucket/key", nil)
		if err != nil {
			return
		}
		_ = verifyAuthorizationHeaderV2(req, auth)
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
