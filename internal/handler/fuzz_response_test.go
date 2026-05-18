package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzApplyResponseOverrides(f *testing.F) {
	f.Add("response-content-type", "application/json")
	f.Add("response-content-disposition", "attachment;filename=test.txt")
	f.Add("response-content-language", "en-US")
	f.Add("response-expires", "Thu,01Dec1994-16:00:00-GMT")
	f.Add("response-cache-control", "no-cache")
	f.Add("response-content-encoding", "gzip")
	f.Add("unknown-param", "value")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, param, value string) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "/bucket/key", nil)
		if err != nil {
			return
		}
		q := req.URL.Query()
		if param != "" {
			q.Set(param, value)
		}
		req.URL.RawQuery = q.Encode()
		applyResponseOverrides(recorder, req)
	})
}

func FuzzIsPresignedURL(f *testing.F) {
	f.Add("X-Amz-Signature", "abc123", "", "")
	f.Add("", "", "AWSAccessKeyId", "AKID")
	f.Add("", "", "", "")
	f.Add("x-amz-signature", "sig", "", "")

	f.Fuzz(func(t *testing.T, key1, val1, key2, val2 string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		q := req.URL.Query()
		if key1 != "" {
			q.Set(key1, val1)
		}
		if key2 != "" {
			q.Set(key2, val2)
		}
		req.URL.RawQuery = q.Encode()
		_ = isPresignedURL(req)
	})
}

func FuzzIsAnonymousRequest(f *testing.F) {
	f.Add("", "", "")
	f.Add("AWS4-HMAC-SHA256 ...", "", "")
	f.Add("", "X-Amz-Credential", "AKID/20230101/us-east-1/s3/aws4_request")
	f.Add("", "AWSAccessKeyId", "AKID")

	f.Fuzz(func(t *testing.T, authHeader, qKey, qVal string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		if qKey != "" {
			q := req.URL.Query()
			q.Set(qKey, qVal)
			req.URL.RawQuery = q.Encode()
		}
		_ = isAnonymousRequest(req)
	})
}
