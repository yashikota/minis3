package handler

import "testing"

func FuzzParseRangeHeader(f *testing.F) {
	f.Add("bytes=0-10", int64(100))
	f.Add("bytes=-5", int64(100))
	f.Add("bytes=5-", int64(100))
	f.Add("", int64(0))
	f.Add("items=0-1", int64(10))
	f.Add("bytes=0-0", int64(1))
	f.Add("bytes=0-99", int64(100))
	f.Add("bytes=99-99", int64(100))
	f.Add("bytes=50-25", int64(100))
	f.Add("bytes=-0", int64(100))
	f.Add("bytes=0-", int64(0))
	f.Add("bytes=9999999999-", int64(100))
	f.Add("bytes=-9999999999", int64(100))
	f.Add("bytes=0-9223372036854775807", int64(100))
	f.Add("BYTES=0-10", int64(100))

	f.Fuzz(func(t *testing.T, header string, size int64) {
		if size < 0 {
			return
		}
		_, _, _ = parseRangeHeader(header, size)
	})
}

func FuzzDecodeURI(f *testing.F) {
	f.Add("/bucket/key")
	f.Add("/bucket/key%20name")
	f.Add("%")
	f.Add("%ZZ")
	f.Add("")
	f.Add("%00")
	f.Add("%ff")
	f.Add("%2F%2F%2F")
	f.Add("/%E6%97%A5%E6%9C%AC%E8%AA%9E")
	f.Add("/bucket/dir1/dir2/key.txt")
	f.Add("%25%25%25")
	f.Add("/bucket/key%2Bplus")
	f.Add("/%20%20%20")
	f.Add("/a%2fb%2fc")
	f.Add("%1%2%3")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeURI(s)
	})
}

func FuzzDecodeAndParseCopySource(f *testing.F) {
	f.Add("/bucket/key")
	f.Add("/bucket/key?versionId=abc")
	f.Add("")
	f.Add("//")
	f.Add("/bucket/dir/subdir/key.txt?versionId=ver123")
	f.Add("bucket/key")
	f.Add("/bucket/key%20with%20spaces")
	f.Add("/bucket/key?versionId=null")
	f.Add("/bucket/key?versionId=")
	f.Add("/bucket/key?other=param&versionId=v1")
	f.Add("/%E6%97%A5%E6%9C%AC%E8%AA%9E/%E3%82%AD%E3%83%BC")
	f.Add("/bucket/key?versionId=ver&extra=val")
	f.Add("/")
	f.Add("/bucket/")

	f.Fuzz(func(t *testing.T, src string) {
		_, _ = decodeAndParseCopySource(src)
	})
}

func FuzzParseTaggingHeader(f *testing.F) {
	f.Add("key1=value1&key2=value2")
	f.Add("")
	f.Add("===")
	f.Add("a=b")
	f.Add("key=")
	f.Add("=value")
	f.Add("k1=v1&k2=v2&k3=v3&k4=v4&k5=v5&k6=v6&k7=v7&k8=v8&k9=v9&k10=v10")
	f.Add("%E6%97%A5=%E6%9C%AC")
	f.Add("key+name=value+name")
	f.Add("&&&&")
	f.Add("key=val1&key=val2")

	f.Fuzz(func(t *testing.T, header string) {
		_ = parseTaggingHeader(header)
	})
}

func FuzzParseExpires(f *testing.F) {
	f.Add("Mon, 02 Jan 2006 15:04:05 GMT")
	f.Add("2006-01-02T15:04:05Z")
	f.Add("")
	f.Add("not-a-date")
	f.Add("Thu, 01 Jan 1970 00:00:00 GMT")
	f.Add("Fri, 31 Dec 9999 23:59:59 GMT")
	f.Add("2024-06-15T10:30:00+09:00")
	f.Add("2024-06-15T10:30:00.000Z")
	f.Add("0")
	f.Add("-1")
	f.Add("9999999999")

	f.Fuzz(func(t *testing.T, value string) {
		_ = parseExpires(value)
	})
}
