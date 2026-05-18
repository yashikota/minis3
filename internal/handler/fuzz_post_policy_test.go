package handler

import "testing"

func FuzzResolvePostObjectFormKey(f *testing.F) {
	f.Add("uploads/${filename}", "photo.jpg")
	f.Add("${filename}", "document.pdf")
	f.Add("fixed-key", "ignored.txt")
	f.Add("", "file.txt")
	f.Add("prefix/${filename}/suffix", "name.txt")
	f.Add("${filename}${filename}", "a.txt")
	f.Add("key", "")

	f.Fuzz(func(t *testing.T, rawKey, fileName string) {
		_, _ = resolvePostObjectFormKey(rawKey, fileName)
	})
}

func FuzzNormalizePostPolicyFieldNameExtended(f *testing.F) {
	f.Add("$Content-Type")
	f.Add("$key")
	f.Add("$bucket")
	f.Add("content-type")
	f.Add("X-Amz-Meta-Custom")
	f.Add("$X-Amz-Algorithm")
	f.Add("  $spaced  ")
	f.Add("")
	f.Add("$")
	f.Add("$$double")

	f.Fuzz(func(t *testing.T, fieldName string) {
		_ = normalizePostPolicyFieldName(fieldName)
	})
}

func FuzzPostPolicyFieldConditionExempt(f *testing.F) {
	f.Add("file")
	f.Add("policy")
	f.Add("x-amz-signature")
	f.Add("signature")
	f.Add("awsaccesskeyid")
	f.Add("")
	f.Add("x-ignore-custom")
	f.Add("x-amz-checksum-crc32")
	f.Add("content-type")
	f.Add("key")
	f.Add("x-amz-meta-tag")

	f.Fuzz(func(t *testing.T, fieldName string) {
		_ = postPolicyFieldConditionExempt(fieldName)
	})
}

func FuzzStartsWithPostPolicyValue(f *testing.F) {
	f.Add("key", "uploads/photo.jpg", "uploads/")
	f.Add("content-type", "image/jpeg,image/png", "image/")
	f.Add("key", "exact", "exact")
	f.Add("key", "short", "longer-prefix")
	f.Add("content-type", "text/plain", "text/")
	f.Add("key", "", "")
	f.Add("key", "value", "")

	f.Fuzz(func(t *testing.T, fieldName, actual, expected string) {
		_ = startsWithPostPolicyValue(fieldName, actual, expected)
	})
}

func FuzzResolvePostPolicyFieldValue(f *testing.F) {
	f.Add("$bucket", "my-bucket", "uploads/key.txt", "image/png")
	f.Add("$key", "bucket", "dir/file.txt", "text/plain")
	f.Add("$Content-Type", "bucket", "key", "application/json")
	f.Add("x-amz-meta-tag", "bucket", "key", "")
	f.Add("", "bucket", "key", "")

	f.Fuzz(func(t *testing.T, fieldName, bucketName, key, contentType string) {
		formFields := map[string]string{
			"x-amz-meta-tag": "value",
			"x-amz-date":     "20230101T000000Z",
		}
		_ = resolvePostPolicyFieldValue(fieldName, bucketName, key, contentType, formFields)
	})
}
