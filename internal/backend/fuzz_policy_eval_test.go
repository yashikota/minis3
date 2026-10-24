package backend

import (
	"slices"
	"strings"
	"testing"
)

// singleStatementPolicies splits a decodable policy into one policy per
// statement.
func singleStatementPolicies(p *BucketPolicy) []BucketPolicy {
	out := make([]BucketPolicy, 0, len(p.Statement))
	for _, stmt := range p.Statement {
		out = append(out, BucketPolicy{Statement: PolicyStatementList{stmt}})
	}
	return out
}

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
		got := EvaluateBucketPolicyAccess(policyJSON, ctx)
		parsed, ok := parseBucketPolicy(policyJSON)
		if !ok {
			if got != PolicyEffectDefault {
				t.Fatalf("undecodable policy evaluated to %v", got)
			}
			return
		}
		// Oracle 1 (S3BucketPolicy.tla OrderIrrelevant): statement order
		// does not matter.
		reversed := BucketPolicy{Statement: slices.Clone(parsed.Statement)}
		slices.Reverse(reversed.Statement)
		if r := reversed.evaluate(ctx); r != got {
			t.Fatalf("reversing the statements changed %v to %v", got, r)
		}
		// Oracle 2 (the declarative semantics): Deny iff some statement on
		// its own denies, else Allow iff some statement on its own allows.
		want := PolicyEffectDefault
		for _, single := range singleStatementPolicies(parsed) {
			switch single.evaluate(ctx) {
			case PolicyEffectDeny:
				want = PolicyEffectDeny
			case PolicyEffectAllow:
				if want == PolicyEffectDefault {
					want = PolicyEffectAllow
				}
			}
		}
		if got != want {
			t.Fatalf("EvaluateBucketPolicyAccess = %v, per-statement semantics = %v", got, want)
		}
		if got == PolicyEffectAllow && !HasAllowStatementForRequest(policyJSON, ctx) {
			t.Fatal("an allowed request must have an applicable Allow statement")
		}
	})
}

func FuzzIsPolicyPublic(f *testing.F) {
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
	)
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*"}]}`,
	)
	f.Add(
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:Referer":"x"}}}]}`,
	)
	f.Add("")
	f.Add("{}")
	f.Add("invalid")
	f.Add(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`)

	f.Fuzz(func(t *testing.T, policyJSON string) {
		public := IsPolicyPublic(policyJSON)
		if !public {
			return
		}
		// Oracle: a public policy has an Allow statement for "*", and that
		// statement alone is public.
		parsed, ok := parseBucketPolicy(policyJSON)
		if !ok {
			t.Fatal("an undecodable policy cannot be public")
		}
		found := false
		for _, single := range singleStatementPolicies(parsed) {
			stmt := single.Statement[0]
			if stmt.Effect == "Allow" && isPublicPrincipal(stmt.Principal) &&
				!conditionsRestrictAccess(stmt.Condition) {
				found = true
			}
		}
		if !found {
			t.Fatalf("IsPolicyPublic(%q) = true without a public Allow statement", policyJSON)
		}
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
		got := HasAllowStatementForRequest(policyJSON, ctx)
		parsed, ok := parseBucketPolicy(policyJSON)
		if !ok {
			if got {
				t.Fatal("an undecodable policy has no Allow statement")
			}
			return
		}
		// Oracle: the same as evaluating the policy's Allow statements with
		// their conditions removed.
		allows := BucketPolicy{}
		for _, stmt := range parsed.Statement {
			if stmt.Effect == "Allow" {
				stmt.Condition = nil
				allows.Statement = append(allows.Statement, stmt)
			}
		}
		if want := allows.evaluate(ctx) == PolicyEffectAllow; got != want {
			t.Fatalf(
				"HasAllowStatementForRequest = %v, unconditional Allow evaluation = %v",
				got,
				want,
			)
		}
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
		got := matchesAction(PolicyStringOrSlice{action}, target)
		// Oracle: action names are case-insensitive on both sides.
		if again := matchesAction(
			PolicyStringOrSlice{strings.ToUpper(action)},
			strings.ToLower(target),
		); again != got {
			t.Fatalf(
				"matchesAction(%q, %q) = %v but %v after changing case",
				action,
				target,
				got,
				again,
			)
		}
		if action == "*" && !got {
			t.Fatal("* matches every action")
		}
		// A list matches iff one of its entries matches.
		if list := matchesAction(
			PolicyStringOrSlice{"s3:NoSuchAction", action},
			target,
		); list != (got || strings.EqualFold(target, "s3:NoSuchAction")) {
			t.Fatalf("list match %v disagrees with single match %v", list, got)
		}
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
		got := matchResourcePattern(pattern, target)
		if got != wildcardMatch(pattern, target) {
			t.Fatal("resource patterns use IAM wildcard matching")
		}
		// Oracle: NotResource is the complement of Resource.
		stmt := PolicyStatement{NotResource: PolicyStringOrSlice{pattern}}
		if target != "" && pattern != "*" && stmt.matchesResource(target) == got {
			t.Fatalf("NotResource %q on %q is not the complement of Resource", pattern, target)
		}
	})
}

func FuzzEvaluateCondition(f *testing.F) {
	f.Add("StringEquals", "aws:Referer", "http://example.com", "s3:GetObject", "http://example.com")
	f.Add("StringNotEquals", "aws:Referer", "http://bad.com", "s3:GetObject", "http://example.com")
	f.Add(
		"StringLike",
		"aws:Referer",
		"http://*.example.com/*",
		"s3:GetObject",
		"http://www.example.com/page",
	)
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
		got := evaluateCondition(operator, condKey, condValue, ctx)
		op, ok := parseConditionOperator(operator)
		if !ok {
			if got {
				t.Fatalf("unknown operator %q matched", operator)
			}
			return
		}
		if !conditionKeySupportedForAction(condKey, action) {
			if got {
				t.Fatal("a key unsupported for the action never matches")
			}
			return
		}
		values, present := lookupConditionKey(condKey, ctx)
		// Oracles from S3PolicyCondition.tla.
		if op.kind != condNull && (!present || len(values) == 0) && op.ifExists && !got {
			t.Fatalf("%s on a missing key must hold", operator)
		}
		if op.kind != condNull && op.set == condSetNone && !op.ifExists && present &&
			len(values) > 0 {
			flipped := op
			flipped.negated = !op.negated
			if flipped.evaluate(values, present, []string{condValue}) == got {
				t.Fatalf("%s and its negation agree on %q", operator, values)
			}
		}
	})
}
