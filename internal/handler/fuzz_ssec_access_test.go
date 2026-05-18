package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzValidateSSECAccess(f *testing.F) {
	f.Add("AES256", "md5hash123", "AES256", "md5hash123")
	f.Add("AES256", "md5hash123", "", "")
	f.Add("AES256", "md5hash123", "AES256", "wrong-md5")
	f.Add("", "", "AES256", "md5hash")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, objAlgo, objKeyMD5, reqAlgo, reqKeyMD5 string) {
		obj := &backend.Object{
			SSECustomerAlgorithm: objAlgo,
			SSECustomerKeyMD5:    objKeyMD5,
		}
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if reqAlgo != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-algorithm", reqAlgo)
		}
		if reqKeyMD5 != "" {
			req.Header.Set("x-amz-server-side-encryption-customer-key-md5", reqKeyMD5)
		}
		recorder := httptest.NewRecorder()
		_ = validateSSECAccess(recorder, req, obj)
	})
}
