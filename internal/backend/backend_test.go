package backend

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteError(t *testing.T) {
	t.Run("writes xml error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		w.Header().Set("x-amz-request-id", "req-123")
		w.Header().Set("x-amz-id-2", "host-123")

		WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")

		if w.Code != http.StatusForbidden {
			t.Fatalf("unexpected status: got %d want %d", w.Code, http.StatusForbidden)
		}
		body := w.Body.String()
		if !strings.Contains(body, "<Error>") {
			t.Fatalf("expected XML error body, got %q", body)
		}
		if !strings.Contains(body, "<Code>AccessDenied</Code>") {
			t.Fatalf("expected code in response body, got %q", body)
		}
		if !strings.Contains(body, "<Message>Access Denied</Message>") {
			t.Fatalf("expected message in response body, got %q", body)
		}
		if !strings.Contains(body, "<RequestId>req-123</RequestId>") {
			t.Fatalf("expected request id in response body, got %q", body)
		}
		if !strings.Contains(body, "<HostId>host-123</HostId>") {
			t.Fatalf("expected host id in response body, got %q", body)
		}
	})

	t.Run("marshal failure logs and returns without body", func(t *testing.T) {
		origMarshal := xmlMarshal
		origFatalf := logFatalf
		t.Cleanup(func() {
			xmlMarshal = origMarshal
			logFatalf = origFatalf
		})

		fatalCalled := false
		xmlMarshal = func(any) ([]byte, error) {
			return nil, errors.New("boom")
		}
		logFatalf = func(string, ...any) {
			fatalCalled = true
		}

		w := httptest.NewRecorder()
		WriteError(w, http.StatusInternalServerError, "InternalError", "internal")

		if !fatalCalled {
			t.Fatal("expected logFatalf to be called")
		}
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("unexpected status: got %d want %d", w.Code, http.StatusInternalServerError)
		}
		if w.Body.Len() != 0 {
			t.Fatalf("expected empty body on marshal failure, got %q", w.Body.String())
		}
	})
}
