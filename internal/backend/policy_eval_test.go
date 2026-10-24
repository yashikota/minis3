package backend

import (
	"fmt"
	"testing"
	"time"
)

func evalOne(t *testing.T, statement string, ctx PolicyEvalContext) PolicyEffect {
	t.Helper()
	policy := `{"Version":"2012-10-17","Statement":[` + statement + `]}`
	if err := ValidateBucketPolicy(policy, ""); err != nil {
		t.Fatalf("test policy is invalid: %v\n%s", err, policy)
	}
	return EvaluateBucketPolicyAccess(policy, ctx)
}

func TestPolicyConditionOperatorKinds(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	keys := map[string][]string{
		"s3:max-keys":         {"50"},
		"aws:sourceip":        {"10.1.2.3"},
		"aws:securetransport": {"false"},
		"aws:sourcearn":       {"arn:aws:s3:::src-bucket"},
		"aws:custom":          {"Hello"},
	}
	tests := []struct {
		condition string
		want      bool
	}{
		{`{"NumericEquals":{"s3:max-keys":"50"}}`, true},
		{`{"NumericEquals":{"s3:max-keys":"50.0"}}`, true},
		{`{"NumericNotEquals":{"s3:max-keys":"50"}}`, false},
		{`{"NumericLessThan":{"s3:max-keys":"51"}}`, true},
		{`{"NumericLessThan":{"s3:max-keys":"50"}}`, false},
		{`{"NumericLessThanEquals":{"s3:max-keys":"50"}}`, true},
		{`{"NumericGreaterThan":{"s3:max-keys":"49"}}`, true},
		{`{"NumericGreaterThan":{"s3:max-keys":50}}`, false},
		{`{"NumericGreaterThanEquals":{"s3:max-keys":"50"}}`, true},
		{`{"NumericLessThan":{"s3:max-keys":["10","100"]}}`, true},
		{`{"DateLessThan":{"aws:CurrentTime":"2026-10-25T00:00:00Z"}}`, true},
		{`{"DateLessThan":{"aws:CurrentTime":"2026-10-24"}}`, false},
		{`{"DateGreaterThan":{"aws:CurrentTime":"2026-10-24T11:59:59Z"}}`, true},
		{`{"DateGreaterThanEquals":{"aws:CurrentTime":"2026-10-24T12:00:00Z"}}`, true},
		{`{"DateLessThanEquals":{"aws:CurrentTime":"2026-10-24T21:00:00+09:00"}}`, true},
		{`{"DateEquals":{"aws:CurrentTime":"2026-10-24T12:00:00Z"}}`, true},
		{`{"DateNotEquals":{"aws:CurrentTime":"2026-10-24T12:00:00Z"}}`, false},
		{fmt.Sprintf(`{"DateEquals":{"aws:EpochTime":"%d"}}`, now.Unix()), true},
		{fmt.Sprintf(`{"NumericEquals":{"aws:EpochTime":"%d"}}`, now.Unix()), true},
		{`{"Bool":{"aws:SecureTransport":"false"}}`, true},
		{`{"Bool":{"aws:SecureTransport":true}}`, false},
		{`{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, true},
		{`{"IpAddress":{"aws:SourceIp":"10.1.2.3"}}`, true},
		{`{"IpAddress":{"aws:SourceIp":["192.168.0.0/16","10.1.0.0/16"]}}`, true},
		{`{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}`, false},
		{`{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, false},
		{`{"NotIpAddress":{"aws:SourceIp":"192.168.0.0/16"}}`, true},
		{`{"ArnEquals":{"aws:SourceArn":"arn:aws:s3:::src-bucket"}}`, true},
		{`{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::src-*"}}`, true},
		{`{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::other"}}`, false},
		{`{"ArnLike":{"aws:SourceArn":"src-bucket"}}`, false},
		{`{"ArnNotLike":{"aws:SourceArn":"arn:aws:s3:::other*"}}`, true},
		{`{"ArnNotEquals":{"aws:SourceArn":"arn:aws:s3:::src-bucket"}}`, false},
		{`{"StringEquals":{"aws:Custom":"Hello"}}`, true},
		{`{"StringEquals":{"aws:Custom":"hello"}}`, false},
		{`{"StringEqualsIgnoreCase":{"aws:Custom":"hello"}}`, true},
		{`{"StringNotEqualsIgnoreCase":{"aws:Custom":"HELLO"}}`, false},
		{`{"StringLike":{"aws:Custom":"H?l*"}}`, true},
		{`{"StringNotLike":{"aws:Custom":"x*"}}`, true},
		{`{"BinaryEquals":{"aws:Custom":"Hello"}}`, true},
		{`{"StringEquals":{"AWS:CUSTOM":"Hello"}}`, true}, // key names are case-insensitive
		{`{"StringEquals":{"aws:Missing":"x"}}`, false},
		{`{"StringNotEquals":{"aws:Missing":"x"}}`, true},
		{`{"StringEqualsIfExists":{"aws:Missing":"x"}}`, true},
		{`{"StringEqualsIfExists":{"aws:Custom":"x"}}`, false},
		{`{"NumericLessThanIfExists":{"s3:max-keys":"10"}}`, false},
		{`{"Null":{"aws:Missing":"true"}}`, true},
		{`{"Null":{"aws:Custom":"true"}}`, false},
		{`{"Null":{"aws:Custom":"false"}}`, true},
		{`{"StringEquals":{"aws:Custom":"Hello"},"NumericLessThan":{"s3:max-keys":"10"}}`, false},
		{`{"StringEquals":{"aws:Custom":"Hello","s3:max-keys":"50"}}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			stmt := `{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":` +
				tt.condition + `}`
			got := evalOne(t, stmt, PolicyEvalContext{
				Action:        "s3:GetObject",
				Resource:      "arn:aws:s3:::b/k",
				AccessKey:     "minis3-access-key",
				ConditionKeys: keys,
				CurrentTime:   now,
			})
			if (got == PolicyEffectDeny) != tt.want {
				t.Fatalf("condition matched = %v, want %v", got == PolicyEffectDeny, tt.want)
			}
		})
	}
}

func TestPolicyMultivaluedConditionKeys(t *testing.T) {
	ctx := PolicyEvalContext{
		Action:            "s3:PutObject",
		Resource:          "arn:aws:s3:::b/k",
		AccessKey:         "minis3-access-key",
		RequestObjectTags: map[string]string{"env": "dev", "team": "a"},
	}
	tests := []struct {
		condition string
		want      bool
	}{
		{`{"ForAllValues:StringEquals":{"s3:RequestObjectTagKeys":["env","team","owner"]}}`, true},
		{`{"ForAllValues:StringEquals":{"s3:RequestObjectTagKeys":["env"]}}`, false},
		{`{"ForAnyValue:StringEquals":{"s3:RequestObjectTagKeys":["env"]}}`, true},
		{`{"ForAnyValue:StringEquals":{"s3:RequestObjectTagKeys":["owner"]}}`, false},
		{`{"ForAnyValue:StringLike":{"s3:RequestObjectTagKeys":["te*"]}}`, true},
		{`{"ForAllValues:StringNotEquals":{"s3:RequestObjectTagKeys":["secret"]}}`, true},
		{`{"ForAnyValue:StringNotEquals":{"s3:RequestObjectTagKeys":["env"]}}`, true},
		{`{"StringEquals":{"s3:RequestObjectTag/env":"dev"}}`, true},
		{
			`{"StringEquals":{"s3:RequestObjectTag/Env":"dev"}}`,
			false,
		}, // tag keys are case-sensitive
	}
	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			stmt := `{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":` +
				tt.condition + `}`
			if got := evalOne(t, stmt, ctx) == PolicyEffectDeny; got != tt.want {
				t.Fatalf("condition matched = %v, want %v", got, tt.want)
			}
		})
	}

	noTags := ctx
	noTags.RequestObjectTags = nil
	stmt := `{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":` +
		`{"ForAllValues:StringEquals":{"s3:RequestObjectTagKeys":["env"]}}}`
	if evalOne(t, stmt, noTags) != PolicyEffectDeny {
		t.Fatal("ForAllValues over a missing key is vacuously true")
	}
	stmt = `{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"*","Condition":` +
		`{"ForAnyValue:StringEquals":{"s3:RequestObjectTagKeys":["env"]}}}`
	if evalOne(t, stmt, noTags) == PolicyEffectDeny {
		t.Fatal("ForAnyValue over a missing key is false")
	}
}

func TestPolicyPrincipalMatching(t *testing.T) {
	root := PrincipalForAccessKey("root-access-key")
	alt := PrincipalForAccessKey("minis3-alt-access-key")
	iamUser := PrincipalForIAMUser(&IAMUser{
		UserName: "alice",
		Arn:      "arn:aws:iam::123456789012:user/team/alice",
	}, "AKIAALICE")
	service := &PolicyPrincipal{Service: LoggingServicePrincipal}
	anon := &PolicyPrincipal{Anonymous: true}

	tests := []struct {
		name      string
		principal string
		caller    *PolicyPrincipal
		want      bool
	}{
		{"star matches anonymous", `"*"`, anon, true},
		{"aws star matches anonymous", `{"AWS":"*"}`, anon, true},
		{"aws star matches user", `{"AWS":"*"}`, alt, true},
		{"aws star does not match service", `{"AWS":"*"}`, service, false},
		{"named arn does not match anonymous", `{"AWS":"` + alt.ARN + `"}`, anon, false},
		{"user arn", `{"AWS":"` + alt.ARN + `"}`, alt, true},
		{"other user arn", `{"AWS":"` + alt.ARN + `"}`, root, false},
		{"legacy access key", `{"AWS":"minis3-alt-access-key"}`, alt, true},
		{"account id", `{"AWS":"123456789012"}`, root, true},
		{"account root arn", `{"AWS":"arn:aws:iam::123456789012:root"}`, root, true},
		{
			"account root arn covers iam users",
			`{"AWS":"arn:aws:iam::123456789012:root"}`,
			iamUser,
			true,
		},
		{"account id covers iam users", `{"AWS":["111111111111","123456789012"]}`, iamUser, true},
		{"other account", `{"AWS":"arn:aws:iam::210987654321:root"}`, root, false},
		{"iam user arn", `{"AWS":"arn:aws:iam::123456789012:user/team/alice"}`, iamUser, true},
		{
			"iam user arn other user",
			`{"AWS":"arn:aws:iam::123456789012:user/team/bob"}`,
			iamUser,
			false,
		},
		{"canonical user", `{"CanonicalUser":"` + alt.CanonicalID + `"}`, alt, true},
		{"canonical user mismatch", `{"CanonicalUser":"` + alt.CanonicalID + `"}`, root, false},
		{"canonical user anonymous", `{"CanonicalUser":"` + alt.CanonicalID + `"}`, anon, false},
		{"service", `{"Service":"logging.s3.amazonaws.com"}`, service, true},
		{"service case-insensitive", `{"Service":"Logging.S3.amazonaws.com"}`, service, true},
		{"other service", `{"Service":"s3.amazonaws.com"}`, service, false},
		{"service does not match users", `{"Service":"logging.s3.amazonaws.com"}`, alt, false},
		{"federated never matches", `{"Federated":"cognito-identity.amazonaws.com"}`, alt, false},
		{"mixed types", `{"Service":"x","AWS":["` + alt.ARN + `"]}`, alt, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt := `{"Effect":"Allow","Principal":` + tt.principal +
				`,"Action":"s3:GetObject","Resource":"*"}`
			got := evalOne(t, stmt, PolicyEvalContext{
				Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", Principal: tt.caller,
			})
			if (got == PolicyEffectAllow) != tt.want {
				t.Fatalf("principal matched = %v, want %v", got == PolicyEffectAllow, tt.want)
			}
			// NotPrincipal (with Deny) applies exactly when Principal does not.
			notStmt := `{"Effect":"Deny","NotPrincipal":` + tt.principal +
				`,"Action":"s3:GetObject","Resource":"*"}`
			got = evalOne(t, notStmt, PolicyEvalContext{
				Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", Principal: tt.caller,
			})
			if (got == PolicyEffectDeny) == tt.want {
				t.Fatalf("NotPrincipal applied = %v, want %v", got == PolicyEffectDeny, !tt.want)
			}
		})
	}
}

func TestPrincipalForAccessKeyMatchesIAMGetUser(t *testing.T) {
	tests := []struct {
		accessKey, account, arn, userName string
	}{
		{"root-access-key", "123456789012", "arn:aws:iam::123456789012:root", ""},
		{"altroot-access-key", "210987654321", "arn:aws:iam::210987654321:root", ""},
		{
			"minis3-access-key",
			DefaultOwner().ID,
			"arn:aws:iam::" + DefaultOwner().ID + ":user/minis3",
			"minis3",
		},
	}
	for _, tt := range tests {
		p := PrincipalForAccessKey(tt.accessKey)
		if p.AccountID != tt.account || p.ARN != tt.arn || p.UserName != tt.userName {
			t.Errorf("PrincipalForAccessKey(%q) = %+v", tt.accessKey, p)
		}
	}
	if p := PrincipalForAccessKey(""); !p.Anonymous {
		t.Fatalf("empty access key should be anonymous, got %+v", p)
	}

	b := New()
	if _, err := b.CreateIAMUser("carol", "/"); err != nil {
		t.Fatal(err)
	}
	key, err := b.CreateIAMAccessKey("carol")
	if err != nil {
		t.Fatal(err)
	}
	p := b.PrincipalForAccessKey(key.AccessKeyId)
	if p.ARN != "arn:aws:iam::123456789012:user/carol" || p.AccountID != "123456789012" ||
		p.UserName != "carol" {
		t.Fatalf("Backend.PrincipalForAccessKey(iam user) = %+v", p)
	}
	if got := b.PrincipalForAccessKey(
		"minis3-alt-access-key",
	); got.ARN != PrincipalForAccessKey(
		"minis3-alt-access-key",
	).ARN {
		t.Fatalf("static keys resolve as before, got %+v", got)
	}
}

func TestPolicyPrincipalConditionKeys(t *testing.T) {
	ctx := PolicyEvalContext{
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::b/k",
		Principal: PrincipalForAccessKey("root-access-key"),
	}
	for _, cond := range []string{
		`{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}`,
		`{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::123456789012:root"}}`,
		`{"StringEquals":{"aws:PrincipalType":"Account"}}`,
		`{"Null":{"aws:username":"true"}}`,
	} {
		stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":` + cond + `}`
		if evalOne(t, stmt, ctx) != PolicyEffectDeny {
			t.Errorf("condition %s should hold for the account root", cond)
		}
	}
	anon := PolicyEvalContext{
		Action:      "s3:GetObject",
		Resource:    "arn:aws:s3:::b/k",
		IsAnonymous: true,
	}
	for _, cond := range []string{
		`{"StringEquals":{"aws:PrincipalType":"Anonymous"}}`,
		`{"StringEquals":{"aws:userid":"anonymous"}}`,
		`{"Null":{"aws:PrincipalArn":"true"}}`,
	} {
		stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":` + cond + `}`
		if evalOne(t, stmt, anon) != PolicyEffectDeny {
			t.Errorf("condition %s should hold for an anonymous caller", cond)
		}
	}
	user := PolicyEvalContext{
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::b/k",
		AccessKey: "minis3-alt-access-key",
	}
	stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":` +
		`{"StringEquals":{"aws:username":"minis3-alt","aws:PrincipalType":"User"}}}`
	if evalOne(t, stmt, user) != PolicyEffectDeny {
		t.Error("aws:username/aws:PrincipalType should describe an IAM user")
	}
}

func TestPolicyNotActionAndNotResource(t *testing.T) {
	ctx := func(action, resource string) PolicyEvalContext {
		return PolicyEvalContext{
			Action:    action,
			Resource:  resource,
			AccessKey: "minis3-alt-access-key",
		}
	}
	notAction := `{"Effect":"Deny","Principal":"*","NotAction":["s3:Get*","s3:ListBucket"],"Resource":"*"}`
	if evalOne(t, notAction, ctx("s3:GetObject", "arn:aws:s3:::b/k")) == PolicyEffectDeny {
		t.Error("NotAction must not apply to a listed action")
	}
	if evalOne(t, notAction, ctx("s3:listbucket", "arn:aws:s3:::b")) == PolicyEffectDeny {
		t.Error("NotAction matching is case-insensitive")
	}
	if evalOne(t, notAction, ctx("s3:PutObject", "arn:aws:s3:::b/k")) != PolicyEffectDeny {
		t.Error("NotAction must apply to every other action")
	}
	notResource := `{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::b/public/*"}`
	if evalOne(t, notResource, ctx("s3:GetObject", "arn:aws:s3:::b/public/x")) == PolicyEffectDeny {
		t.Error("NotResource must not apply to a listed resource")
	}
	if evalOne(
		t,
		notResource,
		ctx("s3:GetObject", "arn:aws:s3:::b/private/x"),
	) != PolicyEffectDeny {
		t.Error("NotResource must apply to every other resource")
	}
	allowAllBut := `{"Effect":"Allow","Principal":"*","NotAction":"s3:DeleteObject","Resource":"*"}`
	if evalOne(t, allowAllBut, ctx("s3:DeleteObject", "arn:aws:s3:::b/k")) == PolicyEffectAllow {
		t.Error("Allow with NotAction must not allow the excluded action")
	}
	if evalOne(t, allowAllBut, ctx("s3:PutObject", "arn:aws:s3:::b/k")) != PolicyEffectAllow {
		t.Error("Allow with NotAction allows the other actions")
	}
}

func TestHasAllowStatementForRequestHonoursNotElements(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:PutObject","Resource":"*",` +
		`"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`
	get := PolicyEvalContext{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", AccessKey: "x"}
	if !HasAllowStatementForRequest(policy, get) {
		t.Fatal("an Allow statement exists for GetObject (conditions ignored)")
	}
	put := get
	put.Action = "s3:PutObject"
	if HasAllowStatementForRequest(policy, put) {
		t.Fatal("NotAction excludes PutObject")
	}
	if HasAllowStatementForRequest("", get) || HasAllowStatementForRequest("{", get) {
		t.Fatal("no policy has no Allow statement")
	}
}

func TestPolicyStringOrSliceKeepsNumberSpelling(t *testing.T) {
	var p PolicyStringOrSlice
	if err := p.UnmarshalJSON([]byte(`[123456789012, 1.50, true, "x"]`)); err != nil {
		t.Fatal(err)
	}
	want := []string{"123456789012", "1.50", "true", "x"}
	if fmt.Sprint([]string(p)) != fmt.Sprint(want) {
		t.Fatalf("PolicyStringOrSlice = %q, want %q", p, want)
	}
	if err := p.UnmarshalJSON([]byte(`[null]`)); err == nil {
		t.Fatal("null values are rejected")
	}
	// An account ID written as a JSON number still matches its string form.
	stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalAccount":123456789012}}}`
	ctx := PolicyEvalContext{
		Action:    "s3:GetObject",
		Principal: PrincipalForAccessKey("root-access-key"),
	}
	if evalOne(t, stmt, ctx) != PolicyEffectDeny {
		t.Fatal("numeric account ID condition should match")
	}
}

func TestIsPolicyPublicFollowsAWSDefinition(t *testing.T) {
	wrap := func(effect, principal, condition string) string {
		s := `{"Statement":[{"Effect":"` + effect + `","Principal":` + principal +
			`,"Action":"s3:GetObject","Resource":"*"`
		if condition != "" {
			s += `,"Condition":` + condition
		}
		return s + `}]}`
	}
	tests := []struct {
		name   string
		policy string
		want   bool
	}{
		{"unconditional star", wrap("Allow", `"*"`, ""), true},
		{"aws star", wrap("Allow", `{"AWS":"*"}`, ""), true},
		{"aws star in list", wrap("Allow", `{"AWS":["arn:aws:iam::1:root","*"]}`, ""), true},
		{"deny is never public", wrap("Deny", `"*"`, ""), false},
		{"named principal", wrap("Allow", `{"AWS":"arn:aws:iam::123456789012:root"}`, ""), false},
		{"service principal", wrap("Allow", `{"Service":"logging.s3.amazonaws.com"}`, ""), false},
		{
			"source ip /32",
			wrap("Allow", `"*"`, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/32"}}`),
			false,
		},
		{
			"source ip /8",
			wrap("Allow", `"*"`, `{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`),
			false,
		},
		{"source ip /0", wrap("Allow", `"*"`, `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`), true},
		{
			"source ipv6 /16",
			wrap("Allow", `"*"`, `{"IpAddress":{"aws:SourceIp":"2001::/16"}}`),
			true,
		},
		{
			"not ip address",
			wrap("Allow", `"*"`, `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`),
			true,
		},
		{
			"source account",
			wrap("Allow", `"*"`, `{"StringEquals":{"aws:SourceAccount":"123456789012"}}`),
			false,
		},
		{
			"source arn like fixed",
			wrap("Allow", `"*"`, `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::src"}}`),
			false,
		},
		{
			"source arn wildcard",
			wrap("Allow", `"*"`, `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::*"}}`),
			true,
		},
		{
			"principal org",
			wrap("Allow", `"*"`, `{"StringEquals":{"aws:PrincipalOrgID":"o-123"}}`),
			false,
		},
		{
			"ifexists does not restrict",
			wrap("Allow", `"*"`, `{"StringEqualsIfExists":{"aws:SourceAccount":"1"}}`),
			true,
		},
		{
			"forallvalues does not restrict",
			wrap("Allow", `"*"`, `{"ForAllValues:StringEquals":{"aws:SourceAccount":"1"}}`),
			true,
		},
		{
			"negated does not restrict",
			wrap("Allow", `"*"`, `{"StringNotEquals":{"aws:SourceAccount":"1"}}`),
			true,
		},
		{
			"policy variable is not fixed",
			wrap("Allow", `"*"`, `{"StringEquals":{"aws:userid":"${aws:userid}"}}`),
			true,
		},
		{
			"non-restricting key",
			wrap("Allow", `"*"`, `{"StringEquals":{"s3:x-amz-acl":"private"}}`),
			true,
		},
		{
			"referer",
			wrap("Allow", `"*"`, `{"StringLike":{"aws:Referer":"https://example.com/*"}}`),
			true,
		},
		{"invalid json", `{`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPolicyPublic(tt.policy); got != tt.want {
				t.Fatalf("IsPolicyPublic() = %v, want %v\n%s", got, tt.want, tt.policy)
			}
		})
	}
}

func TestEvaluateRejectsMalformedStoredPolicyAsDefault(t *testing.T) {
	ctx := PolicyEvalContext{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k"}
	for _, policy := range []string{"", "{", `{"Statement":"x"}`} {
		if got := EvaluateBucketPolicyAccess(policy, ctx); got != PolicyEffectDefault {
			t.Errorf("EvaluateBucketPolicyAccess(%q) = %v, want Default", policy, got)
		}
	}
	// Unknown operators (impossible after validation) never match, so they
	// can neither deny nor allow.
	unknown := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*",` +
		`"Condition":{"StringMaybe":{"aws:Referer":"x"}}}]}`
	if got := EvaluateBucketPolicyAccess(unknown, ctx); got != PolicyEffectDefault {
		t.Errorf("unknown operator = %v, want Default", got)
	}
}

func TestPolicyEvaluationEdgeCases(t *testing.T) {
	var list PolicyStatementList
	if err := list.UnmarshalJSON([]byte(`{"Effect":1}`)); err == nil {
		t.Fatal("a malformed single statement must fail to decode")
	}

	ctx := PolicyEvalContext{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::b/k",
		ConditionKeys: map[string][]string{
			"aws:currenttime": {"not-a-date"},
			"aws:sourceip":    {"not-an-ip"},
		},
		AccessKey: "minis3-alt-access-key",
	}
	for _, cond := range []string{
		`{"DateGreaterThan":{"aws:CurrentTime":"2000-01-01"}}`,
		`{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`,
	} {
		stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":` + cond + `}`
		if evalOne(t, stmt, ctx) == PolicyEffectDeny {
			t.Errorf("%s must not match an unparsable request value", cond)
		}
	}
	if _, ok := parsePolicyDate("  "); ok {
		t.Error("blank date parsed")
	}
	if ipInRange("10.0.0.1", "not-a-cidr") {
		t.Error("invalid CIDR matched")
	}
	if conditionValueMatches(condNull, "x", "x") {
		t.Error("Null is not a value comparison")
	}

	// aws:CurrentTime defaults to the wall clock.
	clock := PolicyEvalContext{
		Action:    "s3:GetObject",
		Resource:  "arn:aws:s3:::b/k",
		AccessKey: "minis3-alt-access-key",
	}
	stmt := `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*",` +
		`"Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}`
	if evalOne(t, stmt, clock) != PolicyEffectDeny {
		t.Error("aws:CurrentTime should default to now")
	}

	alt := PrincipalForAccessKey("minis3-alt-access-key")
	stmt = `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:userid":"` + alt.CanonicalID + `"}}}`
	if evalOne(t, stmt, clock) != PolicyEffectDeny {
		t.Error("aws:userid of a user is its canonical ID")
	}

	service := PolicyEvalContext{
		Action:    "s3:PutObject",
		Principal: &PolicyPrincipal{Service: LoggingServicePrincipal},
	}
	stmt = `{"Effect":"Deny","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"*","Resource":"*",` +
		`"Condition":{"StringEquals":{"aws:PrincipalType":"Service"}}}`
	if evalOne(t, stmt, service) != PolicyEffectDeny {
		t.Error("a service principal has aws:PrincipalType Service")
	}
}

func TestIsPolicyPublicIgnoresNonRestrictingConditionShapes(t *testing.T) {
	for _, condition := range []string{
		// IpAddress restricts only on aws:SourceIp.
		`{"IpAddress":{"aws:SourceArn":"10.0.0.0/8"}}`,
		// A broken CIDR (never stored, PutBucketPolicy rejects it).
		`{"IpAddress":{"aws:SourceIp":"bogus"}}`,
		// Numeric comparisons do not pin a caller.
		`{"NumericEquals":{"aws:SourceAccount":"1"}}`,
	} {
		policy := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*",` +
			`"Condition":` + condition + `}]}`
		if !IsPolicyPublic(policy) {
			t.Errorf("IsPolicyPublic(%s) = false, want true", condition)
		}
	}
}

func TestPolicyValidationErrorMessage(t *testing.T) {
	err := ValidateBucketPolicy(
		`{"Statement":[{"Effect":"Allow","Principal":["*"],"Action":"s3:GetObject","Resource":"*"}]}`,
		"",
	)
	if err == nil || err.Error() != "Invalid principal in policy" {
		t.Fatalf("ValidateBucketPolicy(principal array) = %v", err)
	}
}
