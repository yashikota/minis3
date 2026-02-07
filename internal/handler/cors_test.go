package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleRequestCORSPreflightRequestedHeaders(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "cors-bucket")

	t.Run("rejects preflight when requested header is not allowed", func(t *testing.T) {
		err := b.PutBucketCORS("cors-bucket", &backend.CORSConfiguration{
			CORSRules: []backend.CORSRule{
				{
					AllowedMethods: []string{"GET"},
					AllowedOrigins: []string{"*"},
					ExposeHeaders:  []string{"x-amz-meta-header1"},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketCORS failed: %v", err)
		}

		req := newRequest(
			http.MethodOptions,
			"http://example.test/cors-bucket/bar",
			"",
			map[string]string{
				"Origin":                         "example.origin",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "x-amz-meta-header2",
			},
		)
		w := doRequest(h, req)

		requireStatus(t, w, http.StatusForbidden)
		if got := w.Header().Get("access-control-allow-origin"); got != "" {
			t.Fatalf("access-control-allow-origin = %q, want empty", got)
		}
		if got := w.Header().Get("access-control-allow-methods"); got != "" {
			t.Fatalf("access-control-allow-methods = %q, want empty", got)
		}
	})

	t.Run("allows preflight when all requested headers are allowed", func(t *testing.T) {
		err := b.PutBucketCORS("cors-bucket", &backend.CORSConfiguration{
			CORSRules: []backend.CORSRule{
				{
					AllowedMethods: []string{"GET"},
					AllowedOrigins: []string{"*"},
					AllowedHeaders: []string{"x-amz-meta-*", "content-type"},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketCORS failed: %v", err)
		}

		req := newRequest(
			http.MethodOptions,
			"http://example.test/cors-bucket/bar",
			"",
			map[string]string{
				"Origin":                         "example.origin",
				"Access-Control-Request-Method":  "GET",
				"Access-Control-Request-Headers": "x-amz-meta-header2, Content-Type",
			},
		)
		w := doRequest(h, req)

		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("access-control-allow-origin"); got != "*" {
			t.Fatalf("access-control-allow-origin = %q, want *", got)
		}
		if got := w.Header().Get("access-control-allow-methods"); got != "GET" {
			t.Fatalf("access-control-allow-methods = %q, want GET", got)
		}
	})

	t.Run(
		"allows preflight without requested headers even when AllowedHeaders is empty",
		func(t *testing.T) {
			err := b.PutBucketCORS("cors-bucket", &backend.CORSConfiguration{
				CORSRules: []backend.CORSRule{
					{
						AllowedMethods: []string{"GET"},
						AllowedOrigins: []string{"*"},
					},
				},
			})
			if err != nil {
				t.Fatalf("PutBucketCORS failed: %v", err)
			}

			req := newRequest(
				http.MethodOptions,
				"http://example.test/cors-bucket/bar",
				"",
				map[string]string{
					"Origin":                        "example.origin",
					"Access-Control-Request-Method": "GET",
				},
			)
			w := doRequest(h, req)

			requireStatus(t, w, http.StatusOK)
			if got := w.Header().Get("access-control-allow-origin"); got != "*" {
				t.Fatalf("access-control-allow-origin = %q, want *", got)
			}
		},
	)
}

func TestCORSRequestHeadersAllowed(t *testing.T) {
	tests := []struct {
		name           string
		requestHeaders string
		allowedHeaders []string
		want           bool
	}{
		{
			name:           "no requested headers is always allowed",
			requestHeaders: "",
			allowedHeaders: nil,
			want:           true,
		},
		{
			name:           "requested header denied when no allowed headers",
			requestHeaders: "x-amz-meta-foo",
			allowedHeaders: nil,
			want:           false,
		},
		{
			name:           "wildcard allows all headers",
			requestHeaders: "x-amz-meta-foo,content-type",
			allowedHeaders: []string{"*"},
			want:           true,
		},
		{
			name:           "pattern matching is case-insensitive",
			requestHeaders: "X-Amz-Meta-Bar",
			allowedHeaders: []string{"x-amz-meta-*"},
			want:           true,
		},
		{
			name:           "all requested headers must match",
			requestHeaders: "x-amz-meta-ok,x-amz-meta-ng",
			allowedHeaders: []string{"x-amz-meta-ok"},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := corsRequestHeadersAllowed(tt.requestHeaders, tt.allowedHeaders)
			if got != tt.want {
				t.Fatalf(
					"corsRequestHeadersAllowed(%q, %v) = %v, want %v",
					tt.requestHeaders,
					tt.allowedHeaders,
					got,
					tt.want,
				)
			}
		})
	}
}
