package backend

import (
	"strings"
	"testing"
)

func FuzzValidateBucketName(f *testing.F) {
	f.Add("my-bucket")
	f.Add("bucket.name.123")
	f.Add("")
	f.Add("ab")
	f.Add("abc")
	f.Add("192.168.1.1")
	f.Add("10.0.0.1")
	f.Add("xn--bucket")
	f.Add("xn--nxasmq6b")
	f.Add("bucket-s3alias")
	f.Add("bucket--ol-s3")
	f.Add("my..bucket")
	f.Add("-start")
	f.Add("end-")
	f.Add("end.")
	f.Add(".start")
	f.Add(strings.Repeat("a", 64))
	f.Add(strings.Repeat("a", 63))
	f.Add(strings.Repeat("a", 3))
	f.Add("a")
	f.Add("UPPERCASE")
	f.Add("MiXeD-CaSe")
	f.Add("bucket_underscore")
	f.Add("bucket name")
	f.Add("bucket\ttab")
	f.Add("bucket\nnewline")
	f.Add("bucket/slash")
	f.Add("bucket\\backslash")
	f.Add("日本語バケット")
	f.Add("sthree-bucket")
	f.Add("sthree-configurator")
	f.Add("amzn-s3-demo-bucket")
	f.Add("a.b.c.d")
	f.Add("0.0.0.0")
	f.Add("255.255.255.255")
	f.Add("1.2.3.4.5")
	f.Add("bucket--name")
	f.Add("a-b-c-d-e-f-g")

	f.Fuzz(func(t *testing.T, name string) {
		_ = ValidateBucketName(name)
	})
}
