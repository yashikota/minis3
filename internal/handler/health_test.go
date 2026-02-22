package handler

import (
	"net/http"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)

	t.Run("get", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/health", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", got)
		}
		if got := w.Body.String(); got != "ok\n" {
			t.Fatalf("body = %q, want %q", got, "ok\n")
		}
	})

	t.Run("head", func(t *testing.T) {
		req := newRequest(http.MethodHead, "http://example.test/health", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", got)
		}
		if got := w.Body.String(); got != "" {
			t.Fatalf("body = %q, want empty", got)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := newRequest(http.MethodPost, "http://example.test/health", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusMethodNotAllowed)
		requireS3ErrorCode(t, w, "MethodNotAllowed")
	})
}
