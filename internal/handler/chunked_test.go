package handler

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("boom")
}

func TestDecodeAWSChunkedBody(t *testing.T) {
	t.Run("decode success", func(t *testing.T) {
		body := "4;chunk-signature=abc\r\ntest\r\n5;chunk-signature=def\r\n-body\r\n0;chunk-signature=end\r\n\r\n"
		got, err := decodeAWSChunkedBody(strings.NewReader(body))
		if err != nil {
			t.Fatalf("decodeAWSChunkedBody returned error: %v", err)
		}
		if string(got) != "test-body" {
			t.Fatalf("decoded body = %q, want %q", string(got), "test-body")
		}
	})

	t.Run("invalid chunk size", func(t *testing.T) {
		_, err := decodeAWSChunkedBody(strings.NewReader("ZZZ\r\n"))
		if err == nil {
			t.Fatal("expected parse error for invalid chunk size")
		}
	})

	t.Run("unexpected eof", func(t *testing.T) {
		_, err := decodeAWSChunkedBody(strings.NewReader("5\r\nab"))
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF-related error, got %v", err)
		}
	})

	t.Run("reader error", func(t *testing.T) {
		_, err := decodeAWSChunkedBody(errReader{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestChunkedHelpers(t *testing.T) {
	t.Run("readLine without trailing newline", func(t *testing.T) {
		cr := &chunkedReader{r: strings.NewReader("abc")}
		line, err := cr.readLine()
		if err != nil {
			t.Fatalf("readLine error: %v", err)
		}
		if line != "abc" {
			t.Fatalf("line = %q, want %q", line, "abc")
		}
	})

	t.Run("readChunk zero chunk", func(t *testing.T) {
		cr := &chunkedReader{r: strings.NewReader("0\r\n\r\n")}
		chunk, err := cr.readChunk()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want EOF", err)
		}
		if len(chunk) != 0 {
			t.Fatalf("chunk len = %d, want 0", len(chunk))
		}
	})
}
