package backend

import (
	"encoding/json"
	"slices"
	"testing"
)

func FuzzMatchesPrincipal(f *testing.F) {
	f.Add([]byte(`"*"`), "AKIAIOSFODNN7EXAMPLE", false)
	f.Add([]byte(`{"AWS":"*"}`), "", true)
	f.Add([]byte(`{"AWS":"minis3-alt-access-key"}`), "minis3-alt-access-key", false)
	f.Add([]byte(`{"AWS":"arn:aws:iam::123456789012:root"}`), "root-access-key", false)
	f.Add([]byte(`{"AWS":["123456789012","*"]}`), "", true)
	f.Add([]byte(`{"CanonicalUser":"*"}`), "minis3-access-key", false)
	f.Add([]byte(`{"Service":"logging.s3.amazonaws.com"}`), "minis3-access-key", false)
	f.Add([]byte(`{"AWS":[1]}`), "x", false)
	f.Add([]byte(`null`), "", true)

	f.Fuzz(func(t *testing.T, data []byte, accessKey string, anonymous bool) {
		var principal any
		if err := json.Unmarshal(data, &principal); err != nil || principal == nil {
			return
		}
		ctx := PolicyEvalContext{AccessKey: accessKey, IsAnonymous: anonymous || accessKey == ""}
		got := matchesPrincipal(principal, ctx)
		values := principalValues(principal)
		if values == nil {
			if got {
				// A malformed element can only match through a well-formed
				// entry visited before the malformed one.
				m, isMap := principal.(map[string]any)
				if !isMap || len(m) < 2 {
					t.Fatalf("malformed principal %s matched", data)
				}
			}
			return
		}
		// Oracle 1: "*" matches everyone; an anonymous caller matches
		// nothing else.
		star := slices.Contains(values["AWS"], "*") || slices.Contains(values["CanonicalUser"], "*")
		if star && !got {
			t.Fatalf("%s contains * but did not match", data)
		}
		if ctx.IsAnonymous && got != star {
			t.Fatalf("anonymous caller matched %s = %v, want %v", data, got, star)
		}
		if isPublicPrincipal(principal) != star {
			t.Fatalf("isPublicPrincipal(%s) disagrees with the * oracle", data)
		}
		// Oracle 2: NotPrincipal is the complement of Principal.
		stmt := PolicyStatement{NotPrincipal: principal}
		if stmt.matchesPrincipal(ctx) == got {
			t.Fatalf("NotPrincipal %s is not the complement of Principal", data)
		}
	})
}

func FuzzEvaluateConditions(f *testing.F) {
	f.Add(
		"StringEquals",
		"s3:prefix",
		"photos/",
		"NumericLessThan",
		"s3:max-keys",
		"100",
		"photos/",
		"5",
	)
	f.Add("StringLike", "s3:prefix", "photos/*", "Null", "aws:Referer", "true", "photos/x", "1")
	f.Add(
		"IpAddress",
		"aws:SourceIp",
		"192.168.1.0/24",
		"Bool",
		"aws:SecureTransport",
		"false",
		"",
		"",
	)
	f.Add("", "", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, op1, key1, val1, op2, key2, val2, prefix, maxKeys string) {
		ctx := PolicyEvalContext{
			Action:   "s3:ListBucket",
			Resource: "arn:aws:s3:::bucket",
			ConditionKeys: map[string][]string{
				"s3:prefix":           {prefix},
				"s3:max-keys":         {maxKeys},
				"aws:sourceip":        {"192.168.1.7"},
				"aws:securetransport": {"false"},
			},
		}
		first := map[string]map[string]PolicyStringOrSlice{op1: {key1: {val1}}}
		second := map[string]map[string]PolicyStringOrSlice{op2: {key2: {val2}}}
		both := map[string]map[string]PolicyStringOrSlice{op1: {key1: {val1}}}
		if op1 == op2 {
			if key1 == key2 {
				return
			}
			both[op1][key2] = PolicyStringOrSlice{val2}
		} else {
			both[op2] = map[string]PolicyStringOrSlice{key2: {val2}}
		}
		// Oracle: a condition block is the conjunction of its conditions.
		got := evaluateConditions(both, ctx)
		want := evaluateConditions(first, ctx) && evaluateConditions(second, ctx)
		if got != want {
			t.Fatalf("evaluateConditions(%v) = %v, conjunction = %v", both, got, want)
		}
		if !evaluateConditions(nil, ctx) {
			t.Fatal("an empty condition block holds")
		}
	})
}

func FuzzGetConditionKeyValue(f *testing.F) {
	f.Add("s3:prefix", "photos/", "AKID")
	f.Add("aws:Referer", "", "")
	f.Add("s3:ExistingObjectTag/env", "dev", "")
	f.Add("s3:RequestObjectTagKeys", "", "x")
	f.Add("aws:PrincipalType", "", "")

	f.Fuzz(func(t *testing.T, condKey, value, accessKey string) {
		ctx := PolicyEvalContext{
			AccessKey:          accessKey,
			IsAnonymous:        accessKey == "",
			Action:             "s3:GetObject",
			Headers:            map[string]string{"referer": value, "x-amz-acl": value},
			ConditionKeys:      map[string][]string{"s3:prefix": {value}},
			ExistingObjectTags: map[string]string{"env": value},
		}
		got := getConditionKeyValue(condKey, ctx)
		values, present := lookupConditionKey(condKey, ctx)
		// Oracle: the first value of the lookup, "" when absent.
		want := ""
		if present && len(values) > 0 {
			want = values[0]
		}
		if got != want {
			t.Fatalf(
				"getConditionKeyValue(%q) = %q, lookup = %q (present %v)",
				condKey,
				got,
				values,
				present,
			)
		}
	})
}
