package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzExtractMetadata(f *testing.F) {
	f.Add("x-amz-meta-key1", "value1", "x-amz-meta-key2", "value2")
	f.Add("x-amz-meta-", "", "", "")
	f.Add("x-amz-meta-日本語", "テスト", "", "")
	f.Add("X-Amz-Meta-CamelCase", "val", "", "")
	f.Add("x-amz-meta-a", "b", "x-amz-meta-c", "d")
	f.Add("not-meta", "ignored", "x-amz-meta-real", "kept")

	f.Fuzz(func(t *testing.T, header1, value1, header2, value2 string) {
		req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
		if header1 != "" {
			req.Header.Set(header1, value1)
		}
		if header2 != "" {
			req.Header.Set(header2, value2)
		}
		_ = extractMetadata(req)
	})
}
