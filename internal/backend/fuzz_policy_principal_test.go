package backend

import (
	"encoding/json"
	"testing"
)

func FuzzMatchesPrincipal(f *testing.F) {
	f.Add("*", "AKIAIOSFODNN7EXAMPLE", "s3:GetObject", "arn:aws:s3:::bucket/key")
	f.Add("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "s3:PutObject", "arn:aws:s3:::bucket")
	f.Add("", "", "", "")
	f.Add("anonymous", "", "s3:GetObject", "arn:aws:s3:::public-bucket/*")
	f.Add("arn:aws:iam::123456789012:root", "AKIAI44QH8DHBEXAMPLE", "s3:DeleteObject", "arn:aws:s3:::bucket/path/to/key")
	f.Add("*", "", "s3:ListBucket", "arn:aws:s3:::*")
	f.Add("AKID123", "AKID456", "s3:GetObject", "arn:aws:s3:::bucket/key")
	f.Add("arn:aws:iam::*:user/*", "AKID", "s3:*", "arn:aws:s3:::bucket")
	f.Add("123456789012", "AKID", "s3:GetBucketPolicy", "arn:aws:s3:::my-bucket")
	f.Add("*", "anonymous", "s3:GetObject", "")

	f.Fuzz(func(t *testing.T, principalStr, accessKey, action, resource string) {
		var principal any
		if principalStr == "*" || principalStr == "" {
			principal = principalStr
		} else {
			principal = principalStr
		}

		ctx := PolicyEvalContext{
			AccessKey: accessKey,
			Action:    action,
			Resource:  resource,
		}
		_ = matchesPrincipal(principal, ctx)
	})
}

func FuzzExtractAWSPrincipals(f *testing.F) {
	f.Add([]byte(`"*"`))
	f.Add([]byte(`"AKIAIOSFODNN7EXAMPLE"`))
	f.Add([]byte(`["AKIAIOSFODNN7EXAMPLE","AKIAI44QH8DHBEXAMPLE"]`))
	f.Add([]byte(`{"AWS":"*"}`))
	f.Add([]byte(`{"AWS":["AKIAIOSFODNN7EXAMPLE"]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`123`))
	f.Add([]byte(`{"Service":"logging.s3.amazonaws.com"}`))
	f.Add([]byte(`{"AWS":"arn:aws:iam::123456789012:root"}`))
	f.Add([]byte(`{"AWS":["arn:aws:iam::123456789012:user/testuser","*"]}`))
	f.Add([]byte(`{"Federated":"cognito-identity.amazonaws.com"}`))
	f.Add([]byte(`["*","arn:aws:iam::111111111111:root"]`))
	f.Add([]byte(`{"AWS":[]}`))
	f.Add([]byte(`[123]`))
	f.Add([]byte(`{"AWS":{"nested":"object"}}`))
	f.Add([]byte(`{"Service":["s3.amazonaws.com","ec2.amazonaws.com"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var principal any
		if err := json.Unmarshal(data, &principal); err != nil {
			return
		}
		_, _ = extractAWSPrincipals(principal)
	})
}

func FuzzIsPublicPrincipal(f *testing.F) {
	f.Add([]byte(`"*"`))
	f.Add([]byte(`"AKIAIOSFODNN7EXAMPLE"`))
	f.Add([]byte(`["*","AKIAIOSFODNN7EXAMPLE"]`))
	f.Add([]byte(`{"AWS":"*"}`))
	f.Add([]byte(`{"AWS":["not-star"]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var principal any
		if err := json.Unmarshal(data, &principal); err != nil {
			return
		}
		_ = isPublicPrincipal(principal)
	})
}

func FuzzMatchesResource(f *testing.F) {
	f.Add("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key")
	f.Add("arn:aws:s3:::*", "arn:aws:s3:::anything")
	f.Add("*", "arn:aws:s3:::bucket/key")
	f.Add("", "")
	f.Add("arn:aws:s3:::bucket/prefix*", "arn:aws:s3:::bucket/prefixed-key")

	f.Fuzz(func(t *testing.T, resource, target string) {
		resources := PolicyStringOrSlice{resource}
		_ = matchesResource(resources, target)
	})
}

func FuzzEvaluateConditions(f *testing.F) {
	f.Add("StringEquals", "s3:prefix", "photos/", "AKIAIOSFODNN7EXAMPLE", "s3:ListBucket", "arn:aws:s3:::bucket")
	f.Add("StringLike", "s3:prefix", "photos/*", "AKID", "s3:GetObject", "arn:aws:s3:::bucket/key")
	f.Add("IpAddress", "aws:SourceIp", "192.168.1.0/24", "", "", "")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, operator, condKey, condValue, accessKey, action, resource string) {
		conditions := map[string]map[string]string{
			operator: {condKey: condValue},
		}
		ctx := PolicyEvalContext{
			AccessKey: accessKey,
			Action:    action,
			Resource:  resource,
		}
		_ = evaluateConditions(conditions, ctx)
	})
}

func FuzzConditionKeySupportedForAction(f *testing.F) {
	f.Add("s3:prefix", "s3:ListBucket")
	f.Add("s3:delimiter", "s3:ListBucket")
	f.Add("s3:max-keys", "s3:ListBucket")
	f.Add("aws:SourceIp", "s3:GetObject")
	f.Add("", "")
	f.Add("s3:prefix", "s3:PutObject")
	f.Add("s3:ExistingObjectTag/env", "s3:GetObject")
	f.Add("s3:RequestObjectTag/team", "s3:PutObject")

	f.Fuzz(func(t *testing.T, condKey, action string) {
		_ = conditionKeySupportedForAction(condKey, action)
	})
}

func FuzzGetConditionKeyValue(f *testing.F) {
	f.Add("s3:prefix", "photos/", "AKID", "s3:ListBucket", "arn:aws:s3:::bucket")
	f.Add("s3:delimiter", "/", "AKID", "s3:ListBucket", "arn:aws:s3:::bucket")
	f.Add("aws:SourceIp", "", "", "", "")
	f.Add("", "", "", "", "")
	f.Add("s3:max-keys", "1000", "", "s3:ListBucket", "")

	f.Fuzz(func(t *testing.T, condKey, prefix, accessKey, action, resource string) {
		ctx := PolicyEvalContext{
			AccessKey: accessKey,
			Action:    action,
			Resource:  resource,
			Headers:   map[string]string{"prefix": prefix},
		}
		_ = getConditionKeyValue(condKey, ctx)
	})
}
