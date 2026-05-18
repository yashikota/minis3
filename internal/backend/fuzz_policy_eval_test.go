package backend

import "testing"

func FuzzEvaluateBucketPolicyAccess(f *testing.F) {
	f.Add(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
		"s3:GetObject",
		"arn:aws:s3:::bucket/key.txt",
		"AKIAIOSFODNN7EXAMPLE",
	)
	f.Add(
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		"s3:PutObject",
		"arn:aws:s3:::bucket/key",
		"",
	)
	f.Add("", "s3:GetObject", "arn:aws:s3:::bucket/key", "")
	f.Add("{}", "s3:GetObject", "arn:aws:s3:::bucket/key", "")
	f.Add("invalid json", "s3:GetObject", "arn:aws:s3:::bucket/key", "")
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root"]},"Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::bucket/*","Condition":{"StringEquals":{"aws:Referer":"http://example.com"}}}]}`,
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
		"AKID",
	)
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:Get*","Resource":"arn:aws:s3:::*"}]}`,
		"s3:GetBucketAcl",
		"arn:aws:s3:::mybucket",
		"",
	)
	f.Add(
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotLike":{"aws:Referer":"http://*.example.com/*"}}}]}`,
		"s3:GetObject",
		"arn:aws:s3:::bucket/index.html",
		"",
	)

	f.Fuzz(func(t *testing.T, policyJSON, action, resource, accessKey string) {
		ctx := PolicyEvalContext{
			Action:    action,
			Resource:  resource,
			AccessKey: accessKey,
			Headers:   map[string]string{"referer": "http://example.com"},
		}
		_ = EvaluateBucketPolicyAccess(policyJSON, ctx)
	})
}

func FuzzIsPolicyPublic(f *testing.F) {
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`)
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*"}]}`)
	f.Add(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:Referer":"x"}}}]}`)
	f.Add("")
	f.Add("{}")
	f.Add("invalid")
	f.Add(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`)

	f.Fuzz(func(t *testing.T, policyJSON string) {
		_ = IsPolicyPublic(policyJSON)
	})
}

func FuzzHasAllowStatementForRequest(f *testing.F) {
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
		"",
	)
	f.Add("", "s3:PutObject", "arn:aws:s3:::bucket/key", "AKID")
	f.Add("invalid", "s3:GetObject", "arn:aws:s3:::bucket/key", "")
	f.Add(
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
		"",
	)

	f.Fuzz(func(t *testing.T, policyJSON, action, resource, accessKey string) {
		ctx := PolicyEvalContext{
			Action:    action,
			Resource:  resource,
			AccessKey: accessKey,
		}
		_ = HasAllowStatementForRequest(policyJSON, ctx)
	})
}

func FuzzMatchesAction(f *testing.F) {
	f.Add("s3:GetObject", "s3:GetObject")
	f.Add("s3:*", "s3:PutObject")
	f.Add("s3:Get*", "s3:GetBucketAcl")
	f.Add("*", "s3:DeleteObject")
	f.Add("s3:PutObject", "s3:GetObject")
	f.Add("", "s3:GetObject")
	f.Add("S3:GETOBJECT", "s3:GetObject")

	f.Fuzz(func(t *testing.T, action, target string) {
		actions := PolicyStringOrSlice{action}
		_ = matchesAction(actions, target)
	})
}

func FuzzMatchResourcePattern(f *testing.F) {
	f.Add("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key.txt")
	f.Add("arn:aws:s3:::bucket/prefix*", "arn:aws:s3:::bucket/prefix/deep/key")
	f.Add("*", "arn:aws:s3:::anything")
	f.Add("arn:aws:s3:::bucket/dir?/file", "arn:aws:s3:::bucket/dir1/file")
	f.Add("arn:aws:s3:::exact", "arn:aws:s3:::exact")
	f.Add("arn:aws:s3:::exact", "arn:aws:s3:::different")
	f.Add("arn:aws:s3:::bucket/[abc]", "arn:aws:s3:::bucket/a")

	f.Fuzz(func(t *testing.T, pattern, target string) {
		_ = matchResourcePattern(pattern, target)
	})
}

func FuzzEvaluateCondition(f *testing.F) {
	f.Add("StringEquals", "aws:Referer", "http://example.com", "s3:GetObject", "http://example.com")
	f.Add("StringNotEquals", "aws:Referer", "http://bad.com", "s3:GetObject", "http://example.com")
	f.Add("StringLike", "aws:Referer", "http://*.example.com/*", "s3:GetObject", "http://www.example.com/page")
	f.Add("StringNotLike", "aws:Referer", "http://bad.*", "s3:GetObject", "http://good.com")
	f.Add("Null", "aws:Referer", "true", "s3:GetObject", "")
	f.Add("Null", "aws:Referer", "false", "s3:GetObject", "value")
	f.Add("StringEqualsIfExists", "aws:Referer", "x", "s3:GetObject", "")
	f.Add("UnknownOperator", "aws:Referer", "x", "s3:GetObject", "x")

	f.Fuzz(func(t *testing.T, operator, condKey, condValue, action, headerValue string) {
		ctx := PolicyEvalContext{
			Action:   action,
			Resource: "arn:aws:s3:::bucket/key",
			Headers:  map[string]string{"referer": headerValue},
		}
		_ = evaluateCondition(operator, condKey, condValue, ctx)
	})
}
