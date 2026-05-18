package handler

import (
	"net/http"
	"testing"
)

func FuzzVerifyPresignedURLV2(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE", "1700000000", "signature-val", "/bucket/key")
	f.Add("", "", "", "/")
	f.Add("AKID", "not-a-number", "sig", "/bucket/key")
	f.Add("AKID", "9999999999", "sig", "/bucket/key?param=val")
	f.Add("key", "1700000000", "", "/bucket")

	f.Fuzz(func(t *testing.T, accessKeyID, expires, signature, path string) {
		req, err := http.NewRequest(
			http.MethodGet,
			path+"?AWSAccessKeyId="+accessKeyID+"&Expires="+expires+"&Signature="+signature,
			nil,
		)
		if err != nil {
			return
		}
		_ = verifyPresignedURLV2(req)
	})
}

func FuzzVerifyPresignedURLV4(f *testing.F) {
	f.Add(
		"AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/s3/aws4_request",
		"20230101T120000Z",
		"86400",
		"host",
		"abcdef1234567890",
		"/bucket/key",
	)
	f.Add("", "", "", "", "", "/")
	f.Add("AKID/date/region/svc/req", "20230101T000000Z", "0", "host", "sig", "/bucket/key")
	f.Add("bad-format", "invalid-date", "not-number", "", "", "/bucket")

	f.Fuzz(func(t *testing.T, credential, amzDate, expires, signedHeaders, signature, path string) {
		req, err := http.NewRequest(
			http.MethodGet,
			path+"?X-Amz-Credential="+credential+"&X-Amz-Date="+amzDate+"&X-Amz-Expires="+expires+"&X-Amz-SignedHeaders="+signedHeaders+"&X-Amz-Signature="+signature,
			nil,
		)
		if err != nil {
			return
		}
		req.Host = "localhost"
		_ = verifyPresignedURLV4(req)
	})
}

func FuzzVerifyAuthorizationHeaderV4(f *testing.F) {
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abcdef",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	)
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKID/20230101/eu-west-1/s3/aws4_request, SignedHeaders=host, Signature=sig",
		"secret",
	)
	f.Add("garbage format", "key")
	f.Add("", "")
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKID/bad/cred/format, SignedHeaders=host, Signature=sig",
		"key",
	)

	f.Fuzz(func(t *testing.T, auth, secretKey string) {
		req, err := http.NewRequest(http.MethodGet, "/bucket/key", nil)
		if err != nil {
			return
		}
		req.Host = "localhost"
		req.Header.Set("x-amz-date", "20230101T120000Z")
		req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
		_ = verifyAuthorizationHeaderV4(req, auth, secretKey)
	})
}
