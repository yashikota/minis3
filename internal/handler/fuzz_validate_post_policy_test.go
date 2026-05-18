package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzValidatePostPolicy(f *testing.F) {
	validPolicy := map[string]any{
		"expiration": time.Now().UTC().Add(1 * time.Hour).Format("2006-01-02T15:04:05Z"),
		"conditions": []any{
			map[string]any{"bucket": "my-bucket"},
			[]any{"starts-with", "$key", "uploads/"},
		},
	}
	policyJSON, _ := json.Marshal(validPolicy)
	policyB64 := base64.StdEncoding.EncodeToString(policyJSON)

	f.Add(policyB64, "my-bucket", "uploads/file.txt", "application/octet-stream", int64(1024))
	f.Add("", "bucket", "key", "", int64(0))
	f.Add("notbase64!", "bucket", "key", "", int64(100))
	f.Add(base64.StdEncoding.EncodeToString([]byte(`{}`)), "bucket", "key", "", int64(0))
	f.Add(base64.StdEncoding.EncodeToString([]byte(`{"expiration":"2020-01-01T00:00:00Z","conditions":[{"bucket":"b"}]}`)), "b", "k", "", int64(0))

	f.Fuzz(func(t *testing.T, policyB64, bucket, key, contentType string, size int64) {
		if size < 0 {
			return
		}
		formFields := map[string]string{
			"key":          key,
			"content-type": contentType,
		}
		_, _ = validatePostPolicy(policyB64, bucket, key, contentType, formFields, size)
	})
}

func FuzzValidateMultipartSSECustomerHeaders(f *testing.F) {
	f.Add("AES256", "md5hash123", "AES256", "md5hash123")
	f.Add("AES256", "md5hash123", "AES256", "different")
	f.Add("AES256", "md5hash123", "", "")
	f.Add("", "", "AES256", "md5hash")

	f.Fuzz(func(t *testing.T, uploadAlgo, uploadKeyMD5, reqAlgo, reqKeyMD5 string) {
		upload := &backend.MultipartUpload{
			SSECustomerAlgorithm: uploadAlgo,
			SSECustomerKeyMD5:    uploadKeyMD5,
		}
		req, err := http.NewRequest(http.MethodPut, "/bucket/key?uploadId=abc&partNumber=1", nil)
		if err != nil {
			return
		}
		if reqAlgo != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-algorithm", reqAlgo)
		}
		if reqKeyMD5 != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-key-md5", reqKeyMD5)
		}
		_, _ = validateMultipartSSECustomerHeaders(upload, req)
	})
}

func FuzzValidateCopySourceSSECustomerHeaders(f *testing.F) {
	f.Add("AES256", "md5hash123", "AES256", "md5hash123")
	f.Add("AES256", "md5hash123", "", "")
	f.Add("", "", "AES256", "md5hash")

	f.Fuzz(func(t *testing.T, srcAlgo, srcKeyMD5, reqAlgo, reqKeyMD5 string) {
		source := &backend.Object{
			SSECustomerAlgorithm: srcAlgo,
			SSECustomerKeyMD5:    srcKeyMD5,
		}
		req, err := http.NewRequest(http.MethodPut, "/bucket/key", nil)
		if err != nil {
			return
		}
		if reqAlgo != "" {
			req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", reqAlgo)
		}
		if reqKeyMD5 != "" {
			req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", reqKeyMD5)
		}
		_, _ = validateCopySourceSSECustomerHeaders(source, req)
	})
}
