package backend

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateBucketPolicy(t *testing.T) {
	const ok = ""
	stmt := func(body string) string {
		return `{"Version":"2012-10-17","Statement":[{` + body + `}]}`
	}
	base := `"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"`
	tests := []struct {
		name    string
		policy  string
		wantErr string // substring of the error message; "" means valid
	}{
		{"minimal", stmt(base), ok},
		{"statement object", `{"Statement":{` + base + `}}`, ok},
		{"version 2008", `{"Version":"2008-10-17","Statement":[{` + base + `}]}`, ok},
		{"no version", `{"Statement":[{` + base + `}]}`, ok},
		{"id", `{"Id":"x","Statement":[{` + base + `}]}`, ok},
		{"sid", stmt(`"Sid":"a",` + base), ok},
		{"repeated sid", `{"Statement":[{"Sid":"a",` + base + `},{"Sid":"a",` + base + `}]}`, ok},
		{
			"principal aws list",
			stmt(
				`"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:root","123456789012"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"`,
			),
			ok,
		},
		{
			"principal canonical",
			stmt(
				`"Effect":"Allow","Principal":{"CanonicalUser":"abc"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"`,
			),
			ok,
		},
		{
			"principal service",
			stmt(
				`"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::bkt/*"`,
			),
			ok,
		},
		{
			"deny notprincipal",
			stmt(
				`"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:*","Resource":"arn:aws:s3:::bkt/*"`,
			),
			ok,
		},
		{
			"notaction",
			stmt(
				`"Effect":"Deny","Principal":"*","NotAction":["s3:GetObject","s3:List*"],"Resource":"arn:aws:s3:::bkt/*"`,
			),
			ok,
		},
		{
			"notresource",
			stmt(
				`"Effect":"Deny","Principal":"*","Action":"s3:*","NotResource":"arn:aws:s3:::bkt/public/*"`,
			),
			ok,
		},
		{
			"resource star",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"`),
			ok,
		},
		{
			"resource bucket wildcard",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bk*/x"`,
			),
			ok,
		},
		{
			"resource tenant arn",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3::tenant:bkt/*"`,
			),
			ok,
		},
		{
			"no resource (RGW compatible)",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:PutBucketLogging"`),
			ok,
		},
		{"action star", stmt(`"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"`), ok},
		{
			"action case insensitive",
			stmt(`"Effect":"Allow","Principal":"*","Action":"S3:getobject","Resource":"*"`),
			ok,
		},
		{
			"action question mark",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:GetObjec?","Resource":"*"`),
			ok,
		},
		{
			"numeric condition",
			stmt(base + `,"Condition":{"NumericLessThanEquals":{"s3:max-keys":"10"}}`),
			ok,
		},
		{
			"numeric json number",
			stmt(base + `,"Condition":{"NumericGreaterThan":{"s3:max-keys":5}}`),
			ok,
		},
		{
			"date condition",
			stmt(base + `,"Condition":{"DateLessThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}`),
			ok,
		},
		{
			"date epoch",
			stmt(base + `,"Condition":{"DateGreaterThan":{"aws:EpochTime":"1700000000"}}`),
			ok,
		},
		{"bool condition", stmt(base + `,"Condition":{"Bool":{"aws:SecureTransport":false}}`), ok},
		{
			"ip condition",
			stmt(
				base + `,"Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","2001:db8::/32","192.0.2.1"]}}`,
			),
			ok,
		},
		{
			"not ip condition",
			stmt(base + `,"Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`),
			ok,
		},
		{
			"null condition",
			stmt(base + `,"Condition":{"Null":{"s3:x-amz-server-side-encryption":"true"}}`),
			ok,
		},
		{
			"set qualifier",
			stmt(
				base + `,"Condition":{"ForAllValues:StringEquals":{"s3:RequestObjectTagKeys":["a","b"]}}`,
			),
			ok,
		},
		{
			"ifexists",
			stmt(base + `,"Condition":{"StringEqualsIfExists":{"s3:x-amz-acl":"private"}}`),
			ok,
		},
		{
			"arn condition",
			stmt(base + `,"Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::src*"}}`),
			ok,
		},

		{"invalid json", `{`, "invalid Json"},
		{"trailing data", stmt(base) + `{}`, "invalid Json"},
		{"not an object", `[]`, "invalid Json"},
		{"too large", `{"Id":"` + strings.Repeat("x", MaxBucketPolicySize) + `"}`, "less than"},
		{"unknown top field", `{"Statement":[{` + base + `}],"Foo":1}`, "Unknown field Foo"},
		{"bad version", `{"Version":"2010-01-01","Statement":[{` + base + `}]}`, "version"},
		{"numeric version", `{"Version":2012,"Statement":[{` + base + `}]}`, "version"},
		{"id not string", `{"Id":1,"Statement":[{` + base + `}]}`, "Id must be a string"},
		{"no statement", `{"Version":"2012-10-17"}`, "Missing required field Statement"},
		{"empty statement", `{"Statement":[]}`, "Missing required field Statement"},
		{"statement string", `{"Statement":"x"}`, "Statement must be"},
		{"statement item not object", `{"Statement":[1]}`, "Statement must be"},
		{"unknown statement field", stmt(base + `,"Foo":1`), "Unknown field Foo"},
		{"sid not string", stmt(`"Sid":1,` + base), "Sid must be a string"},
		{
			"no effect",
			stmt(`"Principal":"*","Action":"s3:GetObject","Resource":"*"`),
			"Missing required field Effect",
		},
		{
			"bad effect",
			stmt(`"Effect":"allow","Principal":"*","Action":"s3:GetObject","Resource":"*"`),
			"Invalid effect",
		},
		{
			"no principal",
			stmt(`"Effect":"Allow","Action":"s3:GetObject","Resource":"*"`),
			"Missing required field Principal",
		},
		{
			"both principals",
			stmt(
				`"Effect":"Deny","Principal":"*","NotPrincipal":"*","Action":"s3:GetObject","Resource":"*"`,
			),
			"both Principal and NotPrincipal",
		},
		{
			"allow notprincipal",
			stmt(
				`"Effect":"Allow","NotPrincipal":{"AWS":"x"},"Action":"s3:GetObject","Resource":"*"`,
			),
			"NotPrincipal",
		},
		{
			"bare principal not star",
			stmt(`"Effect":"Allow","Principal":"someone","Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"principal unknown type",
			stmt(`"Effect":"Allow","Principal":{"Foo":"x"},"Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"principal empty object",
			stmt(`"Effect":"Allow","Principal":{},"Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"principal empty list",
			stmt(`"Effect":"Allow","Principal":{"AWS":[]},"Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"principal number",
			stmt(`"Effect":"Allow","Principal":{"AWS":1},"Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"principal empty string",
			stmt(`"Effect":"Allow","Principal":{"AWS":""},"Action":"s3:GetObject","Resource":"*"`),
			"Invalid principal",
		},
		{
			"no action",
			stmt(`"Effect":"Allow","Principal":"*","Resource":"*"`),
			"Missing required field Action",
		},
		{
			"both actions",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"`,
			),
			"both Action and NotAction",
		},
		{
			"unknown s3 action",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:GetObjects","Resource":"*"`),
			"invalid action",
		},
		{
			"other service action",
			stmt(`"Effect":"Allow","Principal":"*","Action":"iam:GetUser","Resource":"*"`),
			"invalid action",
		},
		{
			"action without service",
			stmt(`"Effect":"Allow","Principal":"*","Action":"GetObject","Resource":"*"`),
			"invalid action",
		},
		{
			"action list with number",
			stmt(`"Effect":"Allow","Principal":"*","Action":["s3:GetObject",1],"Resource":"*"`),
			"invalid action",
		},
		{
			"empty action list",
			stmt(`"Effect":"Allow","Principal":"*","Action":[],"Resource":"*"`),
			"invalid action",
		},
		{
			"both resources",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","NotResource":"*"`,
			),
			"both Resource and NotResource",
		},
		{
			"resource not arn",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"bkt/*"`),
			"invalid resource",
		},
		{
			"resource other service",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:iam:::bkt"`,
			),
			"invalid resource",
		},
		{
			"resource other bucket",
			stmt(
				`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"`,
			),
			"invalid resource",
		},
		{
			"resource empty list",
			stmt(`"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":[]`),
			"invalid resource",
		},
		{"condition not object", stmt(base + `,"Condition":"x"`), "Condition must be an object"},
		{
			"unknown operator",
			stmt(base + `,"Condition":{"StringMaybe":{"aws:Referer":"x"}}`),
			"Invalid Condition type",
		},
		{
			"null ifexists",
			stmt(base + `,"Condition":{"NullIfExists":{"aws:Referer":"true"}}`),
			"Invalid Condition type",
		},
		{
			"operator body not object",
			stmt(base + `,"Condition":{"StringEquals":"x"}`),
			"Invalid Condition block",
		},
		{
			"operator body empty",
			stmt(base + `,"Condition":{"StringEquals":{}}`),
			"Invalid Condition block",
		},
		{
			"bad condition key",
			stmt(base + `,"Condition":{"StringEquals":{"referer":"x"}}`),
			"invalid condition key",
		},
		{
			"condition value object",
			stmt(base + `,"Condition":{"StringEquals":{"aws:Referer":{"a":1}}}`),
			"Invalid Condition value",
		},
		{
			"condition value empty list",
			stmt(base + `,"Condition":{"StringEquals":{"aws:Referer":[]}}`),
			"Invalid Condition value",
		},
		{
			"condition value null",
			stmt(base + `,"Condition":{"StringEquals":{"aws:Referer":null}}`),
			"Invalid Condition value",
		},
		{
			"numeric not a number",
			stmt(base + `,"Condition":{"NumericEquals":{"s3:max-keys":"ten"}}`),
			"Invalid Condition value",
		},
		{
			"date not a date",
			stmt(base + `,"Condition":{"DateEquals":{"aws:CurrentTime":"tomorrow"}}`),
			"Invalid Condition value",
		},
		{
			"bool not a bool",
			stmt(base + `,"Condition":{"Bool":{"aws:SecureTransport":"yes"}}`),
			"Invalid Condition value",
		},
		{
			"ip not an ip",
			stmt(base + `,"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/33"}}`),
			"Invalid Condition value",
		},
		{
			"null not a bool",
			stmt(base + `,"Condition":{"Null":{"aws:Referer":"maybe"}}`),
			"Invalid Condition value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketPolicy(tt.policy, "bkt")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateBucketPolicy() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateBucketPolicy() = nil, want error containing %q", tt.wantErr)
			}
			if !errors.Is(err, ErrMalformedPolicy) {
				t.Fatalf("error %v does not match ErrMalformedPolicy", err)
			}
			var ve *PolicyValidationError
			if !errors.As(err, &ve) || !strings.Contains(ve.Message, tt.wantErr) {
				t.Fatalf("ValidateBucketPolicy() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBucketPolicyWithoutBucketSkipsResourceBucketCheck(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::any/*"}]}`
	if err := ValidateBucketPolicy(policy, ""); err != nil {
		t.Fatalf("ValidateBucketPolicy without bucket = %v", err)
	}
	if err := ValidateBucketPolicy(policy, "tenant:any"); err != nil {
		t.Fatalf("tenant-qualified bucket name should match the bucket part: %v", err)
	}
}

func TestPutBucketPolicyRejectsInvalidPolicyWithoutChangingState(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bkt"); err != nil {
		t.Fatal(err)
	}
	good := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*"}]}`
	if err := b.PutBucketPolicy("bkt", good, true); err != nil {
		t.Fatalf("PutBucketPolicy(good) = %v", err)
	}
	bad := `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:Foo","Resource":"*"}]}`
	err := b.PutBucketPolicy("bkt", bad, false)
	var ve *PolicyValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("PutBucketPolicy(bad) = %v, want PolicyValidationError", err)
	}
	got, err := b.GetBucketPolicy("bkt")
	if err != nil || got != good {
		t.Fatalf("policy after rejected put = %q, %v; want the previous policy", got, err)
	}
	bucket, _ := b.GetBucket("bkt")
	if !bucket.PolicyDenySelfAccess {
		t.Fatal("rejected put must not reset PolicyDenySelfAccess")
	}
}

func TestKnownS3PolicyActions(t *testing.T) {
	for _, action := range []string{
		"s3:GetObject", "s3:PUTOBJECT", "s3:ListBucket", "s3:ListBucketVersions",
		"s3:PutBucketPolicy", "s3:BypassGovernanceRetention", "s3:GetObjectVersionTagging",
	} {
		if !IsKnownS3PolicyAction(action) {
			t.Errorf("IsKnownS3PolicyAction(%q) = false", action)
		}
	}
	for _, action := range []string{"s3:DeleteBucketTagging", "s3:GetObjects", "GetObject", "iam:GetUser", ""} {
		if IsKnownS3PolicyAction(action) {
			t.Errorf("IsKnownS3PolicyAction(%q) = true", action)
		}
	}
}
