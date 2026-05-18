package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzLoggingFilterSignature(f *testing.F) {
	f.Add("prefix", "logs/")
	f.Add("suffix", ".log")
	f.Add("", "")
	f.Add("PREFIX", "data/")

	f.Fuzz(func(t *testing.T, ruleName, ruleValue string) {
		filter := &backend.LoggingFilter{
			Key: &backend.LoggingKeyFilter{
				FilterRules: []backend.FilterRule{
					{Name: ruleName, Value: ruleValue},
				},
			},
		}
		_ = loggingFilterSignature(filter)
	})
}

func FuzzLoggingFilterSignatureNil(f *testing.F) {
	f.Add(true)
	f.Add(false)

	f.Fuzz(func(t *testing.T, nilFilter bool) {
		if nilFilter {
			_ = loggingFilterSignature(nil)
		} else {
			_ = loggingFilterSignature(&backend.LoggingFilter{})
		}
	})
}

func FuzzMatchesLoggingFilter(f *testing.F) {
	f.Add("logs/2024/test.log", "prefix", "logs/")
	f.Add("data/file.csv", "suffix", ".csv")
	f.Add("-", "prefix", "anything")
	f.Add("", "", "")
	f.Add("key", "prefix", "ke")

	f.Fuzz(func(t *testing.T, key, ruleName, ruleValue string) {
		filter := &backend.LoggingFilter{
			Key: &backend.LoggingKeyFilter{
				FilterRules: []backend.FilterRule{
					{Name: ruleName, Value: ruleValue},
				},
			},
		}
		_ = matchesLoggingFilter(key, filter)
	})
}

func FuzzShouldLogJournalOperation(f *testing.F) {
	f.Add("REST.PUT.ACL")
	f.Add("REST.PUT.OBJECT")
	f.Add("REST.GET.OBJECT")
	f.Add("REST.DELETE.OBJECT_TAGGING")
	f.Add("REST.PUT.LEGAL_HOLD")
	f.Add("REST.PUT.RETENTION")
	f.Add("")
	f.Add("REST.HEAD.BUCKET")

	f.Fuzz(func(t *testing.T, op string) {
		_ = shouldLogJournalOperation(op)
	})
}

func FuzzMapRequestToLoggingOperation(f *testing.F) {
	f.Add("GET", "/bucket/key", "key", "")
	f.Add("PUT", "/bucket/key", "key", "uploadId=abc")
	f.Add("POST", "/bucket/key", "key", "uploads=")
	f.Add("DELETE", "/bucket/key", "key", "")
	f.Add("GET", "/bucket", "", "")
	f.Add("PUT", "/bucket", "", "logging=")
	f.Add("POST", "/bucket", "", "delete=")
	f.Add("HEAD", "/bucket/key", "key", "")
	f.Add("PUT", "/bucket/key", "key", "acl=")
	f.Add("PUT", "/bucket/key", "key", "tagging=")
	f.Add("POST", "/bucket/key", "key", "restore=")

	f.Fuzz(func(t *testing.T, method, path, key, query string) {
		if !isValidHTTPMethod(method) {
			return
		}
		if !strings.HasPrefix(path, "/") {
			return
		}
		target := path
		if query != "" {
			target += "?" + query
		}
		req, err := http.NewRequest(method, target, nil)
		if err != nil {
			return
		}
		_ = mapRequestToLoggingOperation(req, key)
	})
}

func FuzzLoggingAuthType(f *testing.F) {
	f.Add("", "", "")
	f.Add("AWS4-HMAC-SHA256 ...", "", "")
	f.Add("", "AKID", "sig123")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, authHeader, awsAccessKeyID, signature string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		q := req.URL.Query()
		if awsAccessKeyID != "" {
			q.Set("AWSAccessKeyId", awsAccessKeyID)
		}
		if signature != "" {
			q.Set("Signature", signature)
		}
		req.URL.RawQuery = q.Encode()
		_ = loggingAuthType(req)
	})
}

func FuzzLoggingActionFromRequest(f *testing.F) {
	f.Add("GET", "key")
	f.Add("PUT", "key")
	f.Add("DELETE", "key")
	f.Add("HEAD", "key")
	f.Add("GET", "")
	f.Add("PUT", "")
	f.Add("POST", "")

	f.Fuzz(func(t *testing.T, method, key string) {
		if !isValidHTTPMethod(method) {
			return
		}
		req, err := http.NewRequest(method, "/bucket/key", nil)
		if err != nil {
			return
		}
		_ = loggingActionFromRequest(req, key)
	})
}

func isValidHTTPMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return true
	}
	return len(m) > 0 && len(m) < 10 && !strings.ContainsAny(m, " \t\r\n")
}
