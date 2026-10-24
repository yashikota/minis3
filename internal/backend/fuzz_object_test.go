package backend

import (
	"errors"
	"testing"
)

func FuzzParseDeletePreconditionTime(f *testing.F) {
	f.Add("2024-01-01T00:00:00Z")
	f.Add("Mon, 02 Jan 2006 15:04:05 GMT")
	f.Add("")
	f.Add("not-a-date")
	f.Add("2024-13-32T25:61:61Z")
	f.Add("2024-01-15T10:30:00.123456789Z")
	f.Add("Thu, 01 Jan 1970 00:00:00 GMT")
	f.Add("Sat, 31 Dec 2099 23:59:59 GMT")
	f.Add("2024-06-15T00:00:00+09:00")
	f.Add("2024-06-15T00:00:00-05:00")

	f.Fuzz(func(t *testing.T, value string) {
		_, _ = parseDeletePreconditionTime(value)
	})
}

func FuzzMatchesDeleteETag(f *testing.F) {
	f.Add("*", "\"abc123\"")
	f.Add("\"abc123\"", "\"abc123\"")
	f.Add("\"abc\"", "\"def\"")
	f.Add("", "")
	f.Add("abc", "abc")
	f.Add("W/\"abc\"", "\"abc\"")
	f.Add("\"d41d8cd98f00b204e9800998ecf8427e\"", "\"d41d8cd98f00b204e9800998ecf8427e\"")
	f.Add("\"etag1\", \"etag2\"", "\"etag1\"")
	f.Add("*", "")

	f.Fuzz(func(t *testing.T, condition, objectETag string) {
		_ = matchesDeleteETag(condition, objectETag)
	})
}

func FuzzValidateBucketPolicy(f *testing.F) {
	f.Add(`{"Version":"2012-10-17","Statement":[]}`)
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
	)
	f.Add("")
	f.Add("{}")
	f.Add("not json")
	f.Add(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":["s3:*"],"Resource":["arn:aws:s3:::bucket","arn:aws:s3:::bucket/*"]}]}`,
	)
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*","Condition":{"StringEquals":{"aws:UserAgent":"test"}}}]}`,
	)
	f.Add(`{"Version":"2008-10-17","Statement":[]}`)

	f.Fuzz(func(t *testing.T, policy string) {
		if err := ValidateBucketPolicy(policy, "bucket"); err != nil {
			if !errors.Is(err, ErrMalformedPolicy) {
				t.Fatalf("validation error %v does not match ErrMalformedPolicy", err)
			}
			return
		}
		// Oracle: an accepted policy decodes for evaluation and every
		// statement carries exactly one principal and action element and
		// at most one resource element.
		parsed, ok := parseBucketPolicy(policy)
		if !ok || len(parsed.Statement) == 0 {
			t.Fatalf("accepted policy does not decode: %q", policy)
		}
		for _, stmt := range parsed.Statement {
			if (stmt.Principal == nil) == (stmt.NotPrincipal == nil) ||
				(stmt.Action == nil) == (stmt.NotAction == nil) ||
				(stmt.Resource != nil && stmt.NotResource != nil) {
				t.Fatalf("accepted statement lacks a required element: %+v", stmt)
			}
			if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
				t.Fatalf("accepted statement has effect %q", stmt.Effect)
			}
			for operator := range stmt.Condition {
				if _, ok := parseConditionOperator(operator); !ok {
					t.Fatalf("accepted unknown condition operator %q", operator)
				}
			}
		}
		_ = EvaluateBucketPolicyAccess(policy, PolicyEvalContext{
			Action:   "s3:GetObject",
			Resource: "arn:aws:s3:::bucket/key",
		})
	})
}
