package backend

import (
	"errors"
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
		err := ValidateBucketName(name)
		if want := referenceBucketNameValid(name); (err == nil) != want {
			t.Fatalf("ValidateBucketName(%q) = %v, reference says valid=%v", name, err, want)
		}
		if err != nil && !errors.Is(err, ErrInvalidBucketName) {
			t.Fatalf("ValidateBucketName(%q) = %v, want ErrInvalidBucketName", name, err)
		}
	})
}

// referenceBucketNameValid restates the S3 bucket naming rules
// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html)
// independently of ValidateBucketName, for "tenant:name" names too.
func referenceBucketNameValid(name string) bool {
	if _, after, ok := strings.Cut(name, ":"); ok {
		name = after
	}
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	isAlnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := isAlnum(c)
		if !alnum && c != '-' && c != '.' {
			return false
		}
		if (i == 0 || i == len(name)-1) && !alnum {
			return false
		}
		if i > 0 && c == '.' && !isAlnum(name[i-1]) {
			return false // ".." or "-."
		}
		if i > 0 && c == '-' && name[i-1] == '.' {
			return false // ".-"
		}
	}
	if strings.Count(name, ".") == 3 && isDottedDigits(name) {
		return false
	}
	for _, p := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	for _, s := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// isDottedDigits reports four dot-separated groups of one to three digits,
// which S3 rejects as IP-address-like even when a group exceeds 255.
func isDottedDigits(name string) bool {
	for _, group := range strings.Split(name, ".") {
		if len(group) == 0 || len(group) > 3 {
			return false
		}
		for i := 0; i < len(group); i++ {
			if group[i] < '0' || group[i] > '9' {
				return false
			}
		}
	}
	return true
}
