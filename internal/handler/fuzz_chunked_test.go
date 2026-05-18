package handler

import (
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
