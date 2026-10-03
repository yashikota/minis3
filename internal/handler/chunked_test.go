package handler

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

	t.Run("chunk size exceeds maximum", func(t *testing.T) {
		_, err := decodeAWSChunkedBody(strings.NewReader("4000001;chunk-signature=abc\r\n"))
		if err == nil {
			t.Fatal("expected error for chunk size exceeding maximum")
		}
		if !strings.Contains(err.Error(), "exceeds maximum") {
			t.Fatalf("expected exceeds-maximum error, got %v", err)
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

	t.Run("decode with trailers success", func(t *testing.T) {
		body := "5\r\nhello\r\n0\r\nx-amz-checksum-crc32: abc\r\n\r\n"
		got, err := decodeAWSChunkedBody(strings.NewReader(body))
		if err != nil {
			t.Fatalf("decodeAWSChunkedBody returned error: %v", err)
		}
		if string(got) != "hello" {
			t.Fatalf("decoded body = %q, want %q", string(got), "hello")
		}
	})

	t.Run("trailer read error propagates", func(t *testing.T) {
		r := &trailerErrReader{
			data: []byte("5\r\nhello\r\n0\r\n"),
			err:  errors.New("boom"),
		}
		_, err := decodeAWSChunkedBody(r)
		if err == nil {
			t.Fatal("expected trailer read error to propagate, got nil")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected boom error, got %v", err)
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

	t.Run("readChunk truncated trailer signals EOF", func(t *testing.T) {
		// "5\r\nhello\r\n0\r\n" then EOF: first chunk is data,
		// second chunk header is zero-size with missing final CRLF.
		// Must not be silently swallowed as (nil, nil).
		cr := &chunkedReader{r: strings.NewReader("5\r\nhello\r\n0\r\n")}
		chunk, err := cr.readChunk()
		if err != nil {
			t.Fatalf("first readChunk error: %v", err)
		}
		if string(chunk) != "hello" {
			t.Fatalf("chunk = %q, want %q", string(chunk), "hello")
		}
		chunk, err = cr.readChunk()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("truncated trailer err = %v, want EOF (must not be nil)", err)
		}
		if len(chunk) != 0 {
			t.Fatalf("chunk len = %d, want 0", len(chunk))
		}
	})

	t.Run("readChunk trailer error propagates", func(t *testing.T) {
		cr := &chunkedReader{r: &trailerErrReader{
			data: []byte("0\r\n"),
			err:  errors.New("boom"),
		}}
		_, err := cr.readChunk()
		if err == nil {
			t.Fatal("expected trailer error, got nil")
		}
		if !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected boom error, got %v", err)
		}
	})
}

type readResult struct {
	b   []byte
	n   int
	err error
}

// trailerErrReader serves data one byte at a time, then fails with err.
// Used to simulate a connection break during trailer read after size==0.
type trailerErrReader struct {
	data []byte
	off  int
	err  error
}

func (r *trailerErrReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		if r.err != nil {
			return 0, r.err
		}
		return 0, io.EOF
	}
	p[0] = r.data[r.off]
	r.off++
	return 1, nil
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

func TestValidateContentMD5(t *testing.T) {
	body := []byte("bar")
	sum := md5.Sum(body)
	valid := base64.StdEncoding.EncodeToString(sum[:])

	if code, _ := validateContentMD5(valid, body); code != "" {
		t.Fatalf("valid header code = %q, want empty", code)
	}
	for name, value := range map[string]string{
		"empty":          "",
		"short base64":   "YWJyYWNhZGFicmE=",
		"not base64":     "@@not-base64@@",
		"wrong length":   base64.StdEncoding.EncodeToString([]byte("short")),
		"padded garbage": "!!!!",
	} {
		if code, _ := validateContentMD5(value, body); code != "InvalidDigest" {
			t.Fatalf("%s: code = %q, want InvalidDigest", name, code)
		}
	}
	wrongSum := md5.Sum([]byte("other"))
	wrong := base64.StdEncoding.EncodeToString(wrongSum[:])
	if code, _ := validateContentMD5(wrong, body); code != "BadDigest" {
		t.Fatalf("mismatch code = %q, want BadDigest", code)
	}
}

func TestPutObjectContentMD5Validation(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "md5-bucket")

	putWithMD5 := func(t *testing.T, key, md5Value string) *httptest.ResponseRecorder {
		t.Helper()
		headers := map[string]string{}
		if md5Value != "" {
			headers["Content-MD5"] = md5Value
		}
		return doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/md5-bucket/"+key, "bar", headers),
		)
	}

	t.Run("garbage md5 rejected", func(t *testing.T) {
		w := putWithMD5(t, "k1", "@@not-base64@@")
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidDigest")
	})

	t.Run("short md5 rejected", func(t *testing.T) {
		w := putWithMD5(t, "k2", "YWJyYWNhZGFicmE=")
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidDigest")
	})

	t.Run("empty md5 rejected", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPut,
			"http://example.test/md5-bucket/k-empty",
			strings.NewReader("bar"),
		)
		req.Header["Content-Md5"] = []string{""}
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidDigest")
	})

	t.Run("mismatched md5 rejected", func(t *testing.T) {
		wrongSum := md5.Sum([]byte("other"))
		wrong := base64.StdEncoding.EncodeToString(wrongSum[:])
		w := putWithMD5(t, "k3", wrong)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "BadDigest")
	})

	t.Run("matching md5 accepted", func(t *testing.T) {
		sum := md5.Sum([]byte("bar"))
		w := putWithMD5(t, "k4", base64.StdEncoding.EncodeToString(sum[:]))
		requireStatus(t, w, http.StatusOK)
	})
}
