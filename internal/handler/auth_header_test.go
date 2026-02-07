package handler

import (
	"net/http/httptest"
	"testing"
)

func requireAuthErrCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %q, got nil", want)
	}
	pe, ok := err.(*presignedError)
	if !ok {
		t.Fatalf("expected presignedError, got %T (%v)", err, err)
	}
	if pe.code != want {
		t.Fatalf("code = %q, want %q", pe.code, want)
	}
}

func TestVerifyPresignedURLV2InvalidExpires(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"http://example.test/bucket/key?Signature=abc&Expires=not-a-number",
		nil,
	)
	requireAuthErrCode(t, verifyPresignedURL(req), "InvalidArgument")
}

func TestDefaultCredentialsAndHashHelpers(t *testing.T) {
	creds := DefaultCredentials()
	if creds["minis3-access-key"] == "" {
		t.Fatal("minis3-access-key credential should be defined")
	}
	if creds["tenant-access-key"] == "" {
		t.Fatal("tenant-access-key credential should be defined")
	}

	if got := sha256Hash("abc"); got !=
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected sha256 hash: %q", got)
	}

	if got := hmacSHA256Hex([]byte("key"), "message"); got ==
		"" {
		t.Fatal("hmacSHA256Hex should return non-empty value")
	}
}
