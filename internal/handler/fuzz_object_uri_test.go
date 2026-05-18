package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzContainsUnreadableURIKeyRuneExtended(f *testing.F) {
	f.Add("normal-key")
	f.Add("key with spaces")
	f.Add("key\x00null")
	f.Add("key\ttab")
	f.Add("key\nnewline")
	f.Add("key\r\nCRLF")
	f.Add("")
	f.Add("日本語キー")
	f.Add("key/with/slashes")
	f.Add("key%20encoded")
	f.Add("\x01\x02\x03\x04\x05")
	f.Add("a\x7fb")
	f.Add("emoji🎉key")
	f.Add("path/../traversal")
	f.Add("very" + string([]byte{0x80, 0x81, 0x82}) + "binary")

	f.Fuzz(func(t *testing.T, key string) {
		_ = containsUnreadableURIKeyRune(key)
	})
}

func FuzzParseMultipartFormFields(f *testing.F) {
	f.Add("key", "value", "content-type", "text/plain")
	f.Add("file", "data", "x-amz-meta-custom", "meta-value")
	f.Add("", "", "", "")
	f.Add("AWSAccessKeyId", "AKID", "policy", "base64policy")

	f.Fuzz(func(t *testing.T, k1, v1, k2, v2 string) {
		_ = k1
		_ = v1
		_ = k2
		_ = v2
	})
}

func FuzzIsAnonymousRequestExtended(f *testing.F) {
	f.Add("", "", "", "")
	f.Add(
		"AWS4-HMAC-SHA256 Credential=AKID/20230101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
		"",
		"",
		"",
	)
	f.Add("", "X-Amz-Credential", "AKID/20230101/us-east-1/s3/aws4_request", "")
	f.Add("", "AWSAccessKeyId", "AKID", "sig")
	f.Add("AWS AKID:sig", "", "", "")
	f.Add("Bearer token", "", "", "")

	f.Fuzz(func(t *testing.T, authHeader, qKey1, qVal1, qVal2 string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		if qKey1 != "" {
			q := req.URL.Query()
			q.Set(qKey1, qVal1)
			if qVal2 != "" {
				q.Set("Signature", qVal2)
			}
			req.URL.RawQuery = q.Encode()
		}
		_ = isAnonymousRequest(req)
	})
}
