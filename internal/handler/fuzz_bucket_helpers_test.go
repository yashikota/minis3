package handler

import (
	"encoding/json"
	"testing"
)

func FuzzTenantFromAccessKey(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("")
	f.Add("testuser")
	f.Add("tenant$user")

	f.Fuzz(func(t *testing.T, accessKey string) {
		_ = tenantFromAccessKey(accessKey)
	})
}

func FuzzNormalizeBucketNameForRequestAccessKey(f *testing.F) {
	f.Add("my-bucket", "AKIAIOSFODNN7EXAMPLE")
	f.Add(":global-bucket", "AKID")
	f.Add("tenant:bucket", "AKID")
	f.Add("", "")
	f.Add("bucket", "")

	f.Fuzz(func(t *testing.T, bucketName, accessKey string) {
		_ = normalizeBucketNameForRequestAccessKey(bucketName, accessKey)
	})
}

func FuzzDisplayBucketName(f *testing.F) {
	f.Add("my-bucket")
	f.Add("tenant:bucket")
	f.Add(":bucket")
	f.Add("")
	f.Add("no-colon")
	f.Add("multiple:colons:here")

	f.Fuzz(func(t *testing.T, name string) {
		_ = displayBucketName(name)
	})
}

func FuzzDefaultLogField(f *testing.F) {
	f.Add("value", "-")
	f.Add("", "-")
	f.Add("  ", "-")
	f.Add("actual-value", "fallback")

	f.Fuzz(func(t *testing.T, value, fallback string) {
		_ = defaultLogField(value, fallback)
	})
}

func FuzzSplitQualifiedBucketName(f *testing.F) {
	f.Add("tenant:bucket")
	f.Add("simple-bucket")
	f.Add(":bucket")
	f.Add("")
	f.Add("a:b:c")

	f.Fuzz(func(t *testing.T, name string) {
		_, _ = splitQualifiedBucketName(name)
	})
}

func FuzzQualifiedBucketARN(f *testing.F) {
	f.Add("my-bucket", "")
	f.Add("my-bucket", "prefix/*")
	f.Add("tenant:bucket", "")
	f.Add("tenant:bucket", "key")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, name, suffix string) {
		_ = qualifiedBucketARN(name, suffix)
	})
}

func FuzzQualifiedBucketObjectARN(f *testing.F) {
	f.Add("my-bucket", "photos/")
	f.Add("tenant:bucket", "*")
	f.Add("", "")
	f.Add("bucket", "key/path")

	f.Fuzz(func(t *testing.T, name, prefix string) {
		_ = qualifiedBucketObjectARN(name, prefix)
	})
}

func FuzzSourceAccountIDForLogging(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("")
	f.Add("testuser")

	f.Fuzz(func(t *testing.T, accessKey string) {
		_ = sourceAccountIDForLogging(accessKey)
	})
}

func FuzzPolicyValueToStrings(f *testing.F) {
	f.Add([]byte(`"s3:GetObject"`))
	f.Add([]byte(`["s3:GetObject","s3:PutObject"]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
		_ = policyValueToStrings(v)
	})
}

func FuzzMapValueByFold(f *testing.F) {
	f.Add("StringEquals", "stringequals")
	f.Add("StringLike", "STRINGLIKE")
	f.Add("", "")
	f.Add("key", "KEY")

	f.Fuzz(func(t *testing.T, mapKey, searchKey string) {
		m := map[string]any{mapKey: "value"}
		_, _ = mapValueByFold(m, searchKey)
	})
}

func FuzzPrincipalHasLoggingService(f *testing.F) {
	f.Add([]byte(`"*"`))
	f.Add([]byte(`{"Service":"logging.s3.amazonaws.com"}`))
	f.Add([]byte(`{"Service":["logging.s3.amazonaws.com","other"]}`))
	f.Add([]byte(`{"AWS":"*"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var principal any
		if err := json.Unmarshal(data, &principal); err != nil {
			return
		}
		_ = principalHasLoggingService(principal)
	})
}

func FuzzIsAWSChunkedEncoding(f *testing.F) {
	f.Add("aws-chunked")
	f.Add("gzip, aws-chunked")
	f.Add("gzip")
	f.Add("")
	f.Add("AWS-CHUNKED")
	f.Add("identity")

	f.Fuzz(func(t *testing.T, contentEncoding string) {
		_ = isAWSChunkedEncoding(contentEncoding)
	})
}

func FuzzContainsUnreadableURIKeyRune(f *testing.F) {
	f.Add("normal-key")
	f.Add("key with spaces")
	f.Add("key\x00null")
	f.Add("key\ttab")
	f.Add("")
	f.Add("日本語キー")
	f.Add("key/with/slashes")

	f.Fuzz(func(t *testing.T, key string) {
		_ = containsUnreadableURIKeyRune(key)
	})
}
