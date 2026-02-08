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

	t.Run("decode zero chunk without trailing headers", func(t *testing.T) {
		got, err := decodeAWSChunkedBody(strings.NewReader("0\r\n"))
		if err != nil {
			t.Fatalf("decodeAWSChunkedBody returned error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("decoded body len = %d, want 0", len(got))
		}
	})

	t.Run("readChunk empty header line returns EOF", func(t *testing.T) {
		cr := &chunkedReader{r: strings.NewReader("\r\n")}
		chunk, err := cr.readChunk()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want EOF", err)
		}
		if len(chunk) != 0 {
			t.Fatalf("chunk len = %d, want 0", len(chunk))
		}
	})

	t.Run("readLine continues on zero-byte read", func(t *testing.T) {
		cr := &chunkedReader{r: &zeroThenDataReader{
			parts: []readResult{
				{n: 0, err: nil},
				{b: []byte("a")},
				{b: []byte("b")},
				{b: []byte("\r")},
				{b: []byte("\n")},
			},
		}}
		line, err := cr.readLine()
		if err != nil {
			t.Fatalf("readLine error: %v", err)
		}
		if line != "ab" {
			t.Fatalf("line = %q, want %q", line, "ab")
		}
	})
}

type readResult struct {
	b   []byte
	n   int
	err error
}

type zeroThenDataReader struct {
	idx   int
	parts []readResult
}

func (r *zeroThenDataReader) Read(p []byte) (int, error) {
	if r.idx >= len(r.parts) {
		return 0, io.EOF
	}
	part := r.parts[r.idx]
	r.idx++
	if part.n == 0 && part.err == nil && len(part.b) == 0 {
		return 0, nil
	}
	if len(part.b) > 0 {
		copy(p, part.b)
		return len(part.b), part.err
	}
	if part.n > 0 {
		return part.n, part.err
	}
	return 0, part.err
}
