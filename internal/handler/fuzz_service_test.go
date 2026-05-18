package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func FuzzIamAction(f *testing.F) {
	f.Add("GET", "CreateUser", "")
	f.Add("POST", "", "GetUser")
	f.Add("GET", "", "")
	f.Add("POST", "", "ListAccessKeys")
	f.Add("GET", "  DeleteUser  ", "")

	f.Fuzz(func(t *testing.T, method, queryAction, formAction string) {
		if method != http.MethodGet && method != http.MethodPost {
			return
		}
		target := "/?"
		if queryAction != "" {
			target += "Action=" + url.QueryEscape(queryAction)
		}
		var body *strings.Reader
		if method == http.MethodPost && formAction != "" {
			body = strings.NewReader("Action=" + url.QueryEscape(formAction))
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(method, target, body)
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		_ = iamAction(req)
	})
}

func FuzzIamFormValue(f *testing.F) {
	f.Add("UserName", "testuser", "GET")
	f.Add("Path", "/engineering/", "POST")
	f.Add("", "", "GET")
	f.Add("AccessKeyId", "AKID123", "POST")

	f.Fuzz(func(t *testing.T, key, value, method string) {
		if method != http.MethodGet && method != http.MethodPost {
			return
		}
		var req *http.Request
		if method == http.MethodPost {
			body := strings.NewReader(url.Values{key: {value}}.Encode())
			req = httptest.NewRequest(http.MethodPost, "/", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req = httptest.NewRequest(http.MethodGet, "/?"+url.Values{key: {value}}.Encode(), nil)
		}
		_ = iamFormValue(req, key)
	})
}
