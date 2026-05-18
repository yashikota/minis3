package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzValidateSSEHeaders(f *testing.F) {
	f.Add("", "", "", "", "")
	f.Add("AES256", "", "", "", "")
	f.Add("aws:kms", "arn:aws:kms:us-east-1:123456789012:key/abc", "", "", "")
	f.Add("aws:kms:dsse", "arn:aws:kms:us-east-1:123456789012:key/abc", "", "", "")
	f.Add("invalid", "", "", "", "")
	f.Add("", "", "AES256", "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleT0=", "SomeBase64MD5==")
	f.Add("AES256", "", "AES256", "key", "md5")
	f.Add("", "", "AES256", "", "")
	f.Add("", "keyid", "", "", "")

	f.Fuzz(func(t *testing.T, sse, kmsKeyId, sseCA, sseCKey, sseCKeyMD5 string) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if sse != "" {
			req.Header.Set("x-amz-server-side-encryption", sse)
		}
		if kmsKeyId != "" {
			req.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", kmsKeyId)
		}
		if sseCA != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-algorithm", sseCA)
		}
		if sseCKey != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-key", sseCKey)
		}
		if sseCKeyMD5 != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-key-md5", sseCKeyMD5)
		}
		_, _ = validateSSEHeaders(req)
	})
}
