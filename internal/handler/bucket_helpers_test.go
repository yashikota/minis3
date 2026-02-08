package handler

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsAnonymousRequest(t *testing.T) {
	tests := []struct {
		name   string
		build  func(*http.Request)
		anonOK bool
	}{
		{
			name: "authorization header",
			build: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS access:sig")
			},
			anonOK: false,
		},
		{
			name: "sigv4 query",
			build: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("X-Amz-Signature", "abc")
				r.URL.RawQuery = q.Encode()
			},
			anonOK: false,
		},
		{
			name: "sigv2 query",
			build: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("Signature", "abc")
				r.URL.RawQuery = q.Encode()
			},
			anonOK: false,
		},
		{
			name: "legacy access key query",
			build: func(r *http.Request) {
				q := r.URL.Query()
				q.Set("AWSAccessKeyId", "access")
				r.URL.RawQuery = q.Encode()
			},
			anonOK: false,
		},
		{
			name: "fully anonymous",
			build: func(r *http.Request) {
			},
			anonOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/bucket/key", nil)
			tt.build(r)
			got := isAnonymousRequest(r)
			if got != tt.anonOK {
				t.Fatalf("isAnonymousRequest() = %v, want %v", got, tt.anonOK)
			}
		})
	}
}

func TestMultipartFieldHelpers(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("Policy", "policy-value"); err != nil {
		t.Fatalf("WriteField Policy failed: %v", err)
	}
	if err := writer.WriteField("X-Amz-Date", "20260207T000000Z"); err != nil {
		t.Fatalf("WriteField X-Amz-Date failed: %v", err)
	}

	sigField, err := writer.CreateFormFile("X-Amz-Signature", "sig.txt")
	if err != nil {
		t.Fatalf("CreateFormFile signature failed: %v", err)
	}
	if _, err := sigField.Write([]byte("sig-from-file")); err != nil {
		t.Fatalf("write signature file failed: %v", err)
	}

	fileField, err := writer.CreateFormFile("file", "payload.txt")
	if err != nil {
		t.Fatalf("CreateFormFile file failed: %v", err)
	}
	if _, err := fileField.Write([]byte("file-content")); err != nil {
		t.Fatalf("write file failed: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("multipart close failed: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "http://example.test/upload", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("ParseMultipartForm failed: %v", err)
	}

	fields := parseMultipartFormFields(r)
	if got := getMultipartFormValue(fields, "POLICY"); got != "policy-value" {
		t.Fatalf("getMultipartFormValue(POLICY) = %q", got)
	}
	if got := getMultipartFormValue(fields, "x-amz-signature"); got != "sig-from-file" {
		t.Fatalf("getMultipartFormValue(x-amz-signature) = %q", got)
	}
	if _, exists := fields["file"]; exists {
		t.Fatalf("file field should be excluded from parsed fields: %+v", fields)
	}

	t.Run("nil multipart form returns empty map", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", nil)
		got := parseMultipartFormFields(req)
		if len(got) != 0 {
			t.Fatalf("expected empty fields for nil multipart form, got %+v", got)
		}
	})

	t.Run("file field skipped when key already exists in values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", nil)
		req.MultipartForm = &multipart.Form{
			Value: map[string][]string{
				"Policy": {"from-value"},
			},
			File: map[string][]*multipart.FileHeader{
				"Policy": {{Filename: "policy.txt"}},
			},
		}
		got := parseMultipartFormFields(req)
		if got["policy"] != "from-value" {
			t.Fatalf("expected value-form field to win, got %+v", got)
		}
	})

	t.Run("file open error is ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/upload", nil)
		req.MultipartForm = &multipart.Form{
			File: map[string][]*multipart.FileHeader{
				"X-Amz-Signature": {{Filename: "sig.txt"}},
			},
		}
		got := parseMultipartFormFields(req)
		if _, ok := got["x-amz-signature"]; ok {
			t.Fatalf("expected x-amz-signature to be skipped on open error, got %+v", got)
		}
	})
}

func TestParsePolicyInt64(t *testing.T) {
	tests := []struct {
		name   string
		input  any
		want   int64
		wantOK bool
	}{
		{name: "float64 integer", input: float64(123), want: 123, wantOK: true},
		{name: "float64 fraction", input: float64(1.5), want: 0, wantOK: false},
		{name: "float64 negative", input: float64(-1), want: 0, wantOK: false},
		{name: "int64", input: int64(42), want: 42, wantOK: true},
		{name: "int64 negative", input: int64(-42), want: 0, wantOK: false},
		{name: "int", input: int(7), want: 7, wantOK: true},
		{name: "int negative", input: int(-7), want: 0, wantOK: false},
		{name: "unsupported type", input: "100", want: 0, wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parsePolicyInt64(tt.input)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf(
					"parsePolicyInt64(%v) = (%d, %v), want (%d, %v)",
					tt.input,
					got,
					ok,
					tt.want,
					tt.wantOK,
				)
			}
		})
	}
}

func TestS3URLEncode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "simple/path.txt", want: "simple/path.txt"},
		{input: "a b/日本?.txt", want: "a%20b/%E6%97%A5%E6%9C%AC%3F.txt"},
		{input: "-._~/AZaz09", want: "-._~/AZaz09"},
	}

	for _, tt := range tests {
		if got := s3URLEncode(tt.input); got != tt.want {
			t.Fatalf("s3URLEncode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseOptionalObjectAttributes(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.test/bucket", nil)

	attrs := parseOptionalObjectAttributes(r)
	if len(attrs) != 0 {
		t.Fatalf("expected empty attributes, got %+v", attrs)
	}

	r.Header.Set("x-amz-optional-object-attributes", "ETag, Checksum , ETag")
	attrs = parseOptionalObjectAttributes(r)
	if len(attrs) != 2 || !attrs["ETag"] || !attrs["Checksum"] {
		t.Fatalf("unexpected parsed attributes: %+v", attrs)
	}
}

func TestResolvePostObjectFormKey(t *testing.T) {
	tests := []struct {
		name      string
		rawKey    string
		fileName  string
		wantKey   string
		wantValid bool
	}{
		{
			name:      "missing key",
			rawKey:    "",
			fileName:  "upload.txt",
			wantKey:   "",
			wantValid: false,
		},
		{
			name:      "plain key",
			rawKey:    "path/object.txt",
			fileName:  "upload.txt",
			wantKey:   "path/object.txt",
			wantValid: true,
		},
		{
			name:      "filename substitution",
			rawKey:    "uploads/${filename}",
			fileName:  "upload.txt",
			wantKey:   "uploads/upload.txt",
			wantValid: true,
		},
		{
			name:      "empty after substitution",
			rawKey:    "${filename}",
			fileName:  "",
			wantKey:   "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotValid := resolvePostObjectFormKey(tt.rawKey, tt.fileName)
			if gotValid != tt.wantValid || gotKey != tt.wantKey {
				t.Fatalf(
					"resolvePostObjectFormKey(%q, %q) = (%q, %v), want (%q, %v)",
					tt.rawKey,
					tt.fileName,
					gotKey,
					gotValid,
					tt.wantKey,
					tt.wantValid,
				)
			}
		})
	}
}
