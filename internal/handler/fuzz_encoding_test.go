package handler

import "testing"

func FuzzAwsQueryEscape(f *testing.F) {
	f.Add("/bucket/key with spaces")
	f.Add("")
	f.Add("hello+world")
	f.Add("special!@#$%^&*()")
	f.Add("日本語テスト")
	f.Add("a/b/c/d/e")
	f.Add("~unreserved-chars._")
	f.Add("reserved:/?#[]@!$&'()*+,;=")
	f.Add("\x00\x01\x7f\x80\xff")
	f.Add("AZaz09-_.~")
	f.Add("key=value&foo=bar")
	f.Add("path/to/object with spaces/file (1).txt")

	f.Fuzz(func(t *testing.T, s string) {
		_ = awsQueryEscape(s)
	})
}

func FuzzS3URLEncode(f *testing.F) {
	f.Add("/bucket/key")
	f.Add("")
	f.Add("hello world")
	f.Add("special!@#$%^&*()")
	f.Add("日本語")
	f.Add("/a/b/c?query=val")
	f.Add("/bucket/key with spaces/file.txt")
	f.Add("/bucket/特殊文字/キー")
	f.Add("/bucket/key+plus")
	f.Add("/bucket/dir1/dir2/dir3/deep/key")
	f.Add("/bucket/key%already-encoded")

	f.Fuzz(func(t *testing.T, s string) {
		_ = s3URLEncode(s)
	})
}

func FuzzEncodeHeaderMetadataValue(f *testing.F) {
	f.Add("simple-value")
	f.Add("")
	f.Add("value with spaces")
	f.Add("日本語メタデータ")
	f.Add("\x00\x01\x02\xff")
	f.Add("ASCII only 0123456789")
	f.Add("special=chars;here")
	f.Add("multi\nline\nvalue")
	f.Add("\ttab\tseparated")
	f.Add("emoji: 🎉🚀")

	f.Fuzz(func(t *testing.T, v string) {
		_ = encodeHeaderMetadataValue(v)
	})
}

func FuzzStripAWSChunkedContentEncoding(f *testing.F) {
	f.Add("aws-chunked")
	f.Add("gzip, aws-chunked")
	f.Add("")
	f.Add("gzip")
	f.Add("aws-chunked, gzip, deflate")
	f.Add(",,,")
	f.Add("identity")
	f.Add("br, gzip, aws-chunked")
	f.Add("AWS-CHUNKED")
	f.Add(" aws-chunked ")

	f.Fuzz(func(t *testing.T, contentEncoding string) {
		_ = stripAWSChunkedContentEncoding(contentEncoding)
	})
}
