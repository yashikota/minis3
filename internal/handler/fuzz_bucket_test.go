package handler

import "testing"

func FuzzValidateMFAHeader(f *testing.F) {
	f.Add("arn:aws:iam::123456789012:mfa/user 123456")
	f.Add("")
	f.Add("invalid")
	f.Add("serial-number code")
	f.Add("  ")
	f.Add("arn:aws:iam::000000000000:mfa/root-account-mfa-device 000000")
	f.Add("arn:aws:iam::123456789012:mfa/user 12345")
	f.Add("arn:aws:iam::123456789012:mfa/user 1234567")
	f.Add("serial 123456 extra")
	f.Add("serial")

	f.Fuzz(func(t *testing.T, header string) {
		_ = validateMFAHeader(header)
	})
}

func FuzzNormalizePostPolicyFieldName(f *testing.F) {
	f.Add("Content-Type")
	f.Add("x-amz-meta-custom")
	f.Add("")
	f.Add("$key")
	f.Add("KEY")
	f.Add("content-type")
	f.Add("X-Amz-Algorithm")
	f.Add("X-Amz-Credential")
	f.Add("X-Amz-Date")
	f.Add("X-Amz-Signature")
	f.Add("$Content-Type")
	f.Add("x-amz-server-side-encryption")
	f.Add("Cache-Control")
	f.Add("Content-Disposition")

	f.Fuzz(func(t *testing.T, fieldName string) {
		_ = normalizePostPolicyFieldName(fieldName)
	})
}
