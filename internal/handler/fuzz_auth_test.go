package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzVerifyAuthorizationHeader(f *testing.F) {
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKID/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
	)
	f.Add("AWS AKID:sig")
	f.Add("")
	f.Add("Bearer token")
	f.Add("AWS4-HMAC-SHA256 garbage")
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024",
	)
	f.Add("AWS4-HMAC-SHA256 Credential=/////")
	f.Add("AWS4-HMAC-SHA256 Credential=, SignedHeaders=, Signature=")
	f.Add("AWS4-HMAC-SHA256")
	f.Add("AWS ")
	f.Add("AWS :")
	f.Add("AWS4-HMAC-SHA256 ,,,")
	f.Add("AWS key:base64signature==")
	f.Add("Basic dXNlcjpwYXNz")

	f.Fuzz(func(t *testing.T, authHeader string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		req.Header.Set("Authorization", authHeader)
		req.Host = "localhost"
		_ = verifyAuthorizationHeader(req)
	})
}
