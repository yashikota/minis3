package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzExtractBucketAndKey(f *testing.F) {
	f.Add("/bucket/key")
	f.Add("/bucket/dir/subdir/key.txt")
	f.Add("/bucket")
	f.Add("/")
	f.Add("")
	f.Add("/bucket/")
	f.Add("bucket/key")
	f.Add("/a/b/c/d/e/f/g")
	f.Add("/bucket/key with spaces")
	f.Add("/bucket/日本語キー")
	f.Add("//double//slashes")

	f.Fuzz(func(t *testing.T, path string) {
		_, _ = extractBucketAndKey(path)
	})
}

func FuzzExtractAccessKey(f *testing.F) {
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKID/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=sig",
		"",
		"",
	)
	f.Add("AWS AKID:signature", "", "")
	f.Add("", "AKID/20230101/us-east-1/s3/aws4_request", "")
	f.Add("", "", "AKID")
	f.Add("", "", "")
	f.Add("Bearer token", "", "")
	f.Add("AWS4-HMAC-SHA256 garbage", "", "")
	f.Add("AWS :", "", "")

	f.Fuzz(func(t *testing.T, authHeader, credential, accessKeyId string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		q := req.URL.Query()
		if credential != "" {
			q.Set("X-Amz-Credential", credential)
		}
		if accessKeyId != "" {
			q.Set("AWSAccessKeyId", accessKeyId)
		}
		req.URL.RawQuery = q.Encode()
		_ = extractAccessKey(req)
	})
}

func FuzzQueryValueInsensitive(f *testing.F) {
	f.Add("X-Amz-Date", "20230101T000000Z")
	f.Add("x-amz-date", "20230101T000000Z")
	f.Add("MISSING", "")
	f.Add("", "")
	f.Add("Key", "value")

	f.Fuzz(func(t *testing.T, key, value string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if key != "" && value != "" {
			q := req.URL.Query()
			q.Set(key, value)
			req.URL.RawQuery = q.Encode()
		}
		_ = queryValueInsensitive(req, key)
	})
}

func FuzzHeaderValueAnyCase(f *testing.F) {
	f.Add("Content-Type", "application/json")
	f.Add("x-amz-date", "20230101T000000Z")
	f.Add("MISSING", "")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, name, value string) {
		hdr := http.Header{}
		if name != "" && value != "" {
			hdr.Set(name, value)
		}
		_ = headerValueAnyCase(hdr, name)
	})
}
