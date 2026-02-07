package handler

import (
	"fmt"
	"net/http"
	"testing"
)

func TestHandleService(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "svc-a")
	mustCreateBucket(t, b, "svc-b")

	t.Run("method not allowed", func(t *testing.T) {
		req := newRequest(http.MethodPost, "http://example.test/", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusMethodNotAllowed)
		requireS3ErrorCode(t, w, "MethodNotAllowed")
	})

	t.Run("invalid max-buckets", func(t *testing.T) {
		for _, query := range []string{"abc", "-1", "10001"} {
			req := newRequest(
				http.MethodGet,
				"http://example.test/?max-buckets="+query,
				"",
				nil,
			)
			w := doRequest(h, req)
			requireStatus(t, w, http.StatusBadRequest)
			requireS3ErrorCode(t, w, "InvalidArgument")
		}
	})

	t.Run("list buckets with usage", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/?usage", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("Content-Type"); got != "application/xml" {
			t.Fatalf("Content-Type = %q, want application/xml", got)
		}
		if body := w.Body.String(); body == "" || body[0] != '<' {
			t.Fatalf("unexpected body: %q", body)
		}
	})

	t.Run("list buckets pagination params", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			fmt.Sprintf(
				"http://example.test/?prefix=svc&continuation-token=%s&max-buckets=1",
				"svc-a",
			),
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})
}
