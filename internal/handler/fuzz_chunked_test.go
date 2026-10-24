package handler

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func FuzzDecodeAWSChunkedBody(f *testing.F) {
	f.Add("4;chunk-signature=abc\r\ntest\r\n0;chunk-signature=end\r\n\r\n")
	f.Add("0\r\n\r\n")
	f.Add("")
	f.Add("FFFFFFFF\r\n")
	f.Add("1\r\nX\r\n0\r\n\r\n")
	f.Add("a\r\n0123456789\r\n0\r\n\r\n")
	f.Add(
		"5;chunk-signature=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\nhello\r\n0;chunk-signature=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n\r\n",
	)
	f.Add("3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")
	f.Add("0;chunk-signature=sig\r\nx-amz-checksum:abc\r\n\r\n")
	f.Add("\r\n")
	f.Add("\n\n\n")
	f.Add("xyz\r\n")
	f.Add("-1\r\n")

	f.Fuzz(func(t *testing.T, data string) {
		_, _ = decodeAWSChunkedBody(strings.NewReader(data))
	})
}

// FuzzAWSChunkedRoundTrip encodes data as aws-chunked with chunks of
// chunkSize bytes (with and without chunk signatures and a trailer) and
// checks that decoding gives data back.
func FuzzAWSChunkedRoundTrip(f *testing.F) {
	f.Add([]byte("hello world"), uint16(4), true, false)
	f.Add([]byte{}, uint16(1), false, true)
	f.Add([]byte("\r\n0\r\n\r\n"), uint16(2), true, true)
	f.Add(bytes.Repeat([]byte("x"), 300), uint16(256), false, false)

	f.Fuzz(func(t *testing.T, data []byte, chunkSize uint16, signed, trailer bool) {
		if chunkSize == 0 {
			chunkSize = 1
		}
		var body bytes.Buffer
		header := func(n int) {
			fmt.Fprintf(&body, "%x", n)
			if signed {
				body.WriteString(";chunk-signature=" + strings.Repeat("0", 64))
			}
			body.WriteString("\r\n")
		}
		for rest := data; len(rest) > 0; {
			n := min(int(chunkSize), len(rest))
			header(n)
			body.Write(rest[:n])
			body.WriteString("\r\n")
			rest = rest[n:]
		}
		header(0)
		if trailer {
			body.WriteString("x-amz-checksum-crc32:AAAAAA==\r\n")
		}
		body.WriteString("\r\n")

		got, err := decodeAWSChunkedBody(bytes.NewReader(body.Bytes()))
		if err != nil {
			t.Fatalf("decodeAWSChunkedBody: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("decoded %q, want %q", got, data)
		}
	})
}
