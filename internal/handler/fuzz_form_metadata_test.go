package handler

import "testing"

func FuzzExtractPostFormMetadata(f *testing.F) {
	f.Add("x-amz-meta-key1", "value1", "x-amz-meta-key2", "value2")
	f.Add("x-amz-meta-", "empty-key", "content-type", "ignored")
	f.Add("X-Amz-Meta-CamelCase", "val", "x-amz-meta-lower", "val2")
	f.Add("", "", "", "")
	f.Add("x-amz-meta-日本語", "テスト", "x-amz-meta-emoji", "🎉")
	f.Add("not-meta", "skip", "x-amz-meta-real", "keep")

	f.Fuzz(func(t *testing.T, key1, val1, key2, val2 string) {
		formFields := make(map[string]string)
		if key1 != "" {
			formFields[key1] = val1
		}
		if key2 != "" {
			formFields[key2] = val2
		}
		_ = extractPostFormMetadata(formFields)
	})
}
