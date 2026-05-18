package handler

import (
	"encoding/json"
	"testing"
)

func FuzzLoggingConditionValues(f *testing.F) {
	f.Add([]byte(`{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}`), "StringEquals", "s3:x-amz-acl")
	f.Add([]byte(`{"StringLike":{"aws:SourceArn":"arn:aws:s3:::*"}}`), "StringLike", "aws:SourceArn")
	f.Add([]byte(`{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::bucket"}}`), "ArnLike", "aws:SourceArn")
	f.Add([]byte(`{}`), "StringEquals", "s3:x-amz-acl")
	f.Add([]byte(`null`), "", "")
	f.Add([]byte(`{"StringEquals":{"key":["val1","val2"]}}`), "StringEquals", "key")

	f.Fuzz(func(t *testing.T, conditionsData []byte, operator, conditionKey string) {
		var conditions map[string]any
		if err := json.Unmarshal(conditionsData, &conditions); err != nil {
			return
		}
		operators := []string{operator}
		if operator != "" {
			_, _ = loggingConditionValues(conditions, operators, conditionKey)
		}
	})
}

func FuzzWildcardMatchHandler(f *testing.F) {
	f.Add("*", "anything")
	f.Add("prefix*", "prefix-value")
	f.Add("*suffix", "has-suffix")
	f.Add("exact", "exact")
	f.Add("exact", "not-exact")
	f.Add("pre*mid*suf", "pre-middle-suf")
	f.Add("", "")
	f.Add("*", "")
	f.Add("a*b*c", "axbxc")
	f.Add("a*b*c", "abc")
	f.Add("**", "anything")
	f.Add("test*", "test")

	f.Fuzz(func(t *testing.T, pattern, value string) {
		_ = wildcardMatch(pattern, value)
	})
}

func FuzzPrincipalHasLoggingServiceExtended(f *testing.F) {
	f.Add([]byte(`"*"`))
	f.Add([]byte(`{"Service":"logging.s3.amazonaws.com"}`))
	f.Add([]byte(`{"Service":["logging.s3.amazonaws.com","s3.amazonaws.com"]}`))
	f.Add([]byte(`{"AWS":"*"}`))
	f.Add([]byte(`{"Service":"other.service.com"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`123`))
	f.Add([]byte(`"logging.s3.amazonaws.com"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var principal any
		if err := json.Unmarshal(data, &principal); err != nil {
			return
		}
		_ = principalHasLoggingService(principal)
	})
}
