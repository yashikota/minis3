package handler

import "testing"

func FuzzGetSignatureKey(f *testing.F) {
	f.Add("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	f.Add("secret", "20230101", "eu-west-1", "sts")
	f.Add("", "", "", "")
	f.Add("key", "date", "region", "service")

	f.Fuzz(func(t *testing.T, secretKey, dateStamp, region, service string) {
		_ = getSignatureKey(secretKey, dateStamp, region, service)
	})
}

func FuzzHmacSHA256(f *testing.F) {
	f.Add([]byte("key"), "data")
	f.Add([]byte{}, "")
	f.Add([]byte("AWS4secret"), "20230101")
	f.Add([]byte{0, 1, 2, 3}, "test")

	f.Fuzz(func(t *testing.T, key []byte, data string) {
		_ = hmacSHA256(key, data)
	})
}

func FuzzHmacSHA256Hex(f *testing.F) {
	f.Add([]byte("key"), "data")
	f.Add([]byte{}, "")
	f.Add([]byte("secret"), "message")

	f.Fuzz(func(t *testing.T, key []byte, data string) {
		_ = hmacSHA256Hex(key, data)
	})
}

func FuzzSha256Hash(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("UNSIGNED-PAYLOAD")
	f.Add("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	f.Fuzz(func(t *testing.T, data string) {
		_ = sha256Hash(data)
	})
}

func FuzzVerifyPostPolicySignature(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE", "abc123signature", "eyJjb25kaXRpb25zIjpbXX0=")
	f.Add("", "", "")
	f.Add("key", "sig", "policy")
	f.Add("AKID", "invalid", "notbase64")

	f.Fuzz(func(t *testing.T, accessKey, signature, policy string) {
		_ = verifyPostPolicySignature(accessKey, signature, policy)
	})
}

func FuzzParsePolicyInt64(f *testing.F) {
	f.Add(float64(1024))
	f.Add(float64(-1))
	f.Add(float64(0))
	f.Add(float64(1.5))
	f.Add(float64(9007199254740992))

	f.Fuzz(func(t *testing.T, val float64) {
		_, _ = parsePolicyInt64(val)
	})
}
