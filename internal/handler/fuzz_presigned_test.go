package handler

import (
	"net/http"
	"net/url"
	"testing"
)

func FuzzVerifyPresignedURL(f *testing.F) {
	f.Add("/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID/20230101/us-east-1/s3/aws4_request&X-Amz-Date=20230101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=abc123")
	f.Add("/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256")
	f.Add("/bucket/key?AWSAccessKeyId=AKID&Signature=sig&Expires=9999999999")
	f.Add("/bucket/key")
	f.Add("/bucket/key?X-Amz-Expires=0")
	f.Add("/bucket/key?X-Amz-Expires=-1")
	f.Add("/bucket/key?X-Amz-Expires=999999999999")
	f.Add("/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=&X-Amz-Date=&X-Amz-Expires=&X-Amz-SignedHeaders=&X-Amz-Signature=")

	f.Fuzz(func(t *testing.T, rawURL string) {
		u, err := url.ParseRequestURI(rawURL)
		if err != nil || u.Host != "" {
			return
		}
		if len(rawURL) == 0 || rawURL[0] != '/' {
			return
		}
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return
		}
		req.Host = "localhost"
		_ = verifyPresignedURL(req)
	})
}
