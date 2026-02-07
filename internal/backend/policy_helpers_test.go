package backend

import (
	"encoding/json"
	"testing"
)

func TestPolicyStringOrSliceUnmarshalJSON(t *testing.T) {
	var single PolicyStringOrSlice
	if err := json.Unmarshal([]byte(`"s3:GetObject"`), &single); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(single) != 1 || single[0] != "s3:GetObject" {
		t.Fatalf("unexpected single value: %+v", single)
	}

	var multi PolicyStringOrSlice
	if err := json.Unmarshal([]byte(`["s3:GetObject","s3:PutObject"]`), &multi); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(multi) != 2 {
		t.Fatalf("unexpected multi value: %+v", multi)
	}

	var invalid PolicyStringOrSlice
	if err := json.Unmarshal([]byte(`123`), &invalid); err == nil {
		t.Fatal("expected unmarshal error for numeric value")
	}
}

func TestPolicyMatcherHelpers(t *testing.T) {
	t.Run("matches action branches", func(t *testing.T) {
		if !matchesAction(PolicyStringOrSlice{"*"}, "s3:DeleteObject") {
			t.Fatal("expected wildcard action to match")
		}
		if !matchesAction(PolicyStringOrSlice{"s3:*"}, "s3:GetObject") {
			t.Fatal("expected s3:* action to match")
		}
		if !matchesAction(PolicyStringOrSlice{"s3:Get*"}, "s3:GetObject") {
			t.Fatal("expected prefix wildcard action to match")
		}
		if matchesAction(PolicyStringOrSlice{"s3:PutObject"}, "s3:GetObject") {
			t.Fatal("did not expect action mismatch to match")
		}
	})

	t.Run("matches resource branches", func(t *testing.T) {
		if !matchesResource(nil, "arn:aws:s3:::bucket/key") {
			t.Fatal("empty resources should match")
		}
		if !matchesResource(PolicyStringOrSlice{"arn:aws:s3:::bucket/*"}, "") {
			t.Fatal("empty target should match")
		}
		if !matchesResource(PolicyStringOrSlice{"*"}, "arn:aws:s3:::bucket/key") {
			t.Fatal("* resource should match")
		}
		if !matchesResource(PolicyStringOrSlice{"arn:aws:s3:::bucket/*"}, "arn:aws:s3:::bucket/path/to/key") {
			t.Fatal("expected wildcard resource to match")
		}
		if matchesResource(PolicyStringOrSlice{"arn:aws:s3:::other/*"}, "arn:aws:s3:::bucket/key") {
			t.Fatal("did not expect resource mismatch to match")
		}
	})

	t.Run("match resource pattern branches", func(t *testing.T) {
		if !matchResourcePattern("arn:aws:s3:::bucket/key", "arn:aws:s3:::bucket/key") {
			t.Fatal("expected exact pattern match")
		}
		if !matchResourcePattern("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b") {
			t.Fatal("expected suffix /* pattern to match nested path")
		}
		if !matchResourcePattern("arn:aws:s3:::bucket/??", "arn:aws:s3:::bucket/ab") {
			t.Fatal("expected ? wildcard pattern to match")
		}
		if matchResourcePattern("arn:aws:s3:::bucket/??", "arn:aws:s3:::bucket/abc") {
			t.Fatal("did not expect mismatched pattern to match")
		}
	})

	t.Run("wildcard helper branches", func(t *testing.T) {
		if !matchWildcard("a*", "abcd") {
			t.Fatal("expected wildcard match")
		}
		if !wildcardMatch("a?c", "abc") {
			t.Fatal("expected ? wildcard match")
		}
		if wildcardMatch("a?c", "ac") {
			t.Fatal("expected ? wildcard mismatch with short string")
		}
		if wildcardMatch("abc", "ab") {
			t.Fatal("expected final length mismatch")
		}
	})
}

func TestPolicyConditionHelpers(t *testing.T) {
	ctx := PolicyEvalContext{
		Headers: map[string]string{
			"referer":                      "https://example.test",
			"x-amz-server-side-encryption": "AES256",
		},
		ExistingObjectTags: map[string]string{"Project": "alpha"},
		RequestObjectTags:  map[string]string{"Env": "dev"},
	}

	t.Run("get condition key value branches", func(t *testing.T) {
		if got := getConditionKeyValue("s3:ExistingObjectTag/Project", ctx); got != "alpha" {
			t.Fatalf("unexpected ExistingObjectTag value: %q", got)
		}
		if got := getConditionKeyValue("s3:RequestObjectTag/Env", ctx); got != "dev" {
			t.Fatalf("unexpected RequestObjectTag value: %q", got)
		}
		if got := getConditionKeyValue("aws:Referer", ctx); got != "https://example.test" {
			t.Fatalf("unexpected aws header value: %q", got)
		}
		if got := getConditionKeyValue("s3:x-amz-server-side-encryption", ctx); got != "AES256" {
			t.Fatalf("unexpected s3 header value: %q", got)
		}
		if got := getConditionKeyValue("unknown", ctx); got != "" {
			t.Fatalf("expected empty value for unknown key, got %q", got)
		}
	})

	t.Run("get condition key value nil-map fallbacks", func(t *testing.T) {
		emptyCtx := PolicyEvalContext{}
		if got := getConditionKeyValue("s3:ExistingObjectTag/Project", emptyCtx); got != "" {
			t.Fatalf("expected empty ExistingObjectTag value, got %q", got)
		}
		if got := getConditionKeyValue("s3:RequestObjectTag/Env", emptyCtx); got != "" {
			t.Fatalf("expected empty RequestObjectTag value, got %q", got)
		}
		if got := getConditionKeyValue("aws:Referer", emptyCtx); got != "" {
			t.Fatalf("expected empty aws header value, got %q", got)
		}
		if got := getConditionKeyValue("s3:x-amz-server-side-encryption", emptyCtx); got != "" {
			t.Fatalf("expected empty s3 header value, got %q", got)
		}
	})

	t.Run("evaluate condition operators", func(t *testing.T) {
		if !evaluateCondition("StringEquals", "s3:x-amz-server-side-encryption", "AES256", ctx) {
			t.Fatal("expected StringEquals match")
		}
		if !evaluateCondition("StringNotEquals", "s3:x-amz-server-side-encryption", "aws:kms", ctx) {
			t.Fatal("expected StringNotEquals match")
		}
		if !evaluateCondition("StringLike", "aws:Referer", "https://*.test", ctx) {
			t.Fatal("expected StringLike match")
		}
		if !evaluateCondition("StringNotLike", "aws:Referer", "http://*", ctx) {
			t.Fatal("expected StringNotLike match")
		}
		if !evaluateCondition("Null", "s3:missing", "true", ctx) {
			t.Fatal("expected Null=true for missing value")
		}
		if !evaluateCondition("Null", "s3:x-amz-server-side-encryption", "false", ctx) {
			t.Fatal("expected Null=false for existing value")
		}
		if evaluateCondition("UnknownOperator", "s3:x-amz-server-side-encryption", "AES256", ctx) {
			t.Fatal("expected unknown operator to return false")
		}
	})

	t.Run("if exists condition", func(t *testing.T) {
		if !evaluateCondition("StringEqualsIfExists", "s3:missing", "value", ctx) {
			t.Fatal("expected IfExists on missing key to pass")
		}
	})

	t.Run("evaluate conditions map", func(t *testing.T) {
		if !evaluateConditions(nil, ctx) {
			t.Fatal("expected empty conditions to pass")
		}
		if evaluateConditions(map[string]map[string]string{
			"StringEquals": {
				"s3:x-amz-server-side-encryption": "AES256",
			},
			"StringLike": {
				"aws:Referer": "http://*",
			},
		}, ctx) {
			t.Fatal("expected AND conditions to fail when one fails")
		}
	})
}

func TestPolicyResourceMismatchAndWildcardMisses(t *testing.T) {
	policy := mustPolicyJSON(t, map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{
				"Effect":   "Deny",
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::other-bucket/*",
			},
			map[string]any{
				"Effect":   "Allow",
				"Action":   "s3:GetObject",
				"Resource": "arn:aws:s3:::other-bucket/*",
			},
		},
	})
	effect := EvaluateBucketPolicyAccess(policy, PolicyEvalContext{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::bucket/key",
	})
	if effect != PolicyEffectDefault {
		t.Fatalf("expected PolicyEffectDefault for resource mismatch, got %v", effect)
	}

	if wildcardMatch("a*d", "abce") {
		t.Fatal("expected wildcard '*' branch to fail when suffix does not match")
	}
	if wildcardMatch("?", "") {
		t.Fatal("expected '?' branch to fail on empty string")
	}
}
