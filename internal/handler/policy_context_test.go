package handler

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func setupPolicyBucket(t *testing.T, policy string) *Handler {
	t.Helper()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "pol")
	b.SetBucketOwner("pol", "minis3-access-key")
	mustPutObject(t, b, "pol", "public/a", "a")
	mustPutObject(t, b, "pol", "private/b", "b")
	if policy != "" {
		if err := b.PutBucketPolicy("pol", policy, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
	}
	return h
}

func TestPutBucketPolicyReportsValidationMessage(t *testing.T) {
	t.Parallel()
	h := setupPolicyBucket(t, "")
	owner := map[string]string{"Authorization": authHeader("minis3-access-key")}
	tests := []struct {
		policy, message string
	}{
		{
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObjectz","Resource":"*"}]}`,
			"Policy has invalid action",
		},
		{
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}]}`,
			"Policy has invalid resource",
		},
		{
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"NumericFoo":{"s3:max-keys":"1"}}}]}`,
			"Invalid Condition type : NumericFoo",
		},
		{
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
			"Missing required field Principal",
		},
		{`not json`, "This policy contains invalid Json"},
	}
	for _, tt := range tests {
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/pol?policy", tt.policy, owner),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedPolicy")
		if !strings.Contains(w.Body.String(), tt.message) {
			t.Errorf(
				"PutBucketPolicy(%s) body = %s, want message %q",
				tt.policy,
				w.Body.String(),
				tt.message,
			)
		}
	}
}

func TestBucketPolicyNotPrincipalDenyOverHTTP(t *testing.T) {
	t.Parallel()
	ownerARN := backend.PrincipalForAccessKey("minis3-access-key").ARN
	h := setupPolicyBucket(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"},
		{"Effect":"Deny","NotPrincipal":{"AWS":"`+ownerARN+`"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/private/*"}]}`)
	get := func(key, accessKey string) int {
		headers := map[string]string{}
		if accessKey != "" {
			headers["Authorization"] = authHeader(accessKey)
		}
		return doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/pol/"+key, "", headers),
		).Code
	}
	if code := get("public/a", ""); code != http.StatusOK {
		t.Fatalf("anonymous GET public = %d, want 200", code)
	}
	if code := get("private/b", ""); code != http.StatusForbidden {
		t.Fatalf("anonymous GET private = %d, want 403 (NotPrincipal covers anonymous)", code)
	}
	if code := get("private/b", "minis3-alt-access-key"); code != http.StatusForbidden {
		t.Fatalf("other user GET private = %d, want 403", code)
	}
	if code := get("private/b", "minis3-access-key"); code != http.StatusOK {
		t.Fatalf("owner GET private = %d, want 200", code)
	}
}

func TestBucketPolicySourceIPCondition(t *testing.T) {
	t.Parallel()
	h := setupPolicyBucket(
		t,
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
		"Resource":"arn:aws:s3:::pol/*","Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]}`,
	)
	for _, tt := range []struct {
		remote string
		want   int
	}{
		{"192.0.2.10:5555", http.StatusOK},
		{"198.51.100.1:5555", http.StatusForbidden},
		{"[2001:db8::1]:5555", http.StatusForbidden},
	} {
		req := newRequest(http.MethodGet, "http://example.test/pol/public/a", "", nil)
		req.RemoteAddr = tt.remote
		if w := doRequest(h, req); w.Code != tt.want {
			t.Errorf("GET from %s = %d, want %d", tt.remote, w.Code, tt.want)
		}
	}
}

func TestBucketPolicySecureTransportCondition(t *testing.T) {
	t.Parallel()
	h := setupPolicyBucket(t, `{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pol/*"},
		{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::pol/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`)
	plain := newRequest(http.MethodGet, "http://example.test/pol/public/a", "", nil)
	if w := doRequest(h, plain); w.Code != http.StatusForbidden {
		t.Fatalf("plain HTTP GET = %d, want 403", w.Code)
	}
	secure := newRequest(http.MethodGet, "https://example.test/pol/public/a", "", nil)
	secure.TLS = &tls.ConnectionState{}
	if w := doRequest(h, secure); w.Code != http.StatusOK {
		t.Fatalf("HTTPS GET = %d, want 200", w.Code)
	}
}

func TestBucketPolicyListPrefixCondition(t *testing.T) {
	t.Parallel()
	h := setupPolicyBucket(t, `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"`+
		backend.PrincipalForAccessKey("minis3-alt-access-key").ARN+
		`"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::pol","Condition":{"StringLike":{"s3:prefix":"public/*"}}}]}`)
	alt := map[string]string{"Authorization": authHeader("minis3-alt-access-key")}
	if w := doRequest(
		h,
		newRequest(http.MethodGet, "http://example.test/pol?prefix=public/", "", alt),
	); w.Code != http.StatusOK {
		t.Fatalf("list public/ = %d, want 200 body=%s", w.Code, w.Body.String())
	}
	if w := doRequest(
		h,
		newRequest(http.MethodGet, "http://example.test/pol?prefix=private/", "", alt),
	); w.Code != http.StatusForbidden {
		t.Fatalf("list private/ = %d, want 403", w.Code)
	}
	if w := doRequest(
		h,
		newRequest(http.MethodGet, "http://example.test/pol", "", alt),
	); w.Code != http.StatusForbidden {
		t.Fatalf("list without prefix = %d, want 403", w.Code)
	}
}

func TestBucketPolicyAccountPrincipal(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "acct")
	b.SetBucketOwner("acct", "minis3-access-key")
	mustPutObject(t, b, "acct", "k", "v")
	user, err := b.CreateIAMUser("dave", "/")
	if err != nil {
		t.Fatal(err)
	}
	key, err := b.CreateIAMAccessKey(user.UserName)
	if err != nil {
		t.Fatal(err)
	}
	// Granting the account root grants every IAM user of the account.
	if err := b.PutBucketPolicy("acct", `{"Statement":[{"Effect":"Allow",
		"Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::acct/*"}]}`, false); err != nil {
		t.Fatal(err)
	}
	req := newRequest(http.MethodGet, "http://example.test/acct/k", "", map[string]string{
		"Authorization": authHeader(key.AccessKeyId),
	})
	if w := doRequest(h, req); w.Code != http.StatusOK {
		t.Fatalf(
			"IAM user of the granted account GET = %d, want 200 body=%s",
			w.Code,
			w.Body.String(),
		)
	}
	other := newRequest(http.MethodGet, "http://example.test/acct/k", "", map[string]string{
		"Authorization": authHeader("altroot-access-key"),
	})
	if w := doRequest(h, other); w.Code != http.StatusForbidden {
		t.Fatalf("other account GET = %d, want 403", w.Code)
	}
}

func TestRequestConditionKeys(t *testing.T) {
	t.Parallel()
	req := newRequest(
		http.MethodGet,
		"http://example.test/b?prefix=p/&delimiter=/&max-keys=5&versionId=v1",
		"",
		map[string]string{
			"Authorization": "AWS4-HMAC-SHA256 Credential=x/20260101/us-east-1/s3/aws4_request",
			"User-Agent":    "agent/1",
		},
	)
	req.RemoteAddr = "[2001:db8::7]:443"
	keys := requestConditionKeys(req)
	want := map[string]string{
		"aws:sourceip":        "2001:db8::7",
		"aws:securetransport": "false",
		"aws:useragent":       "agent/1",
		"s3:signatureversion": "AWS4-HMAC-SHA256",
		"s3:authtype":         "REST-HEADER",
		"s3:prefix":           "p/",
		"s3:delimiter":        "/",
		"s3:max-keys":         "5",
		"s3:versionid":        "v1",
	}
	for k, v := range want {
		if got := keys[k]; len(got) != 1 || got[0] != v {
			t.Errorf("condition key %s = %q, want %q", k, got, v)
		}
	}

	for _, tt := range []struct {
		auth, query, version, authType string
	}{
		{"AWS a:b", "", "AWS", "REST-HEADER"},
		{"", "X-Amz-Signature=x", "AWS4-HMAC-SHA256", "REST-QUERY-STRING"},
		{"", "Signature=x", "AWS", "REST-QUERY-STRING"},
		{"", "", "", ""},
	} {
		r := newRequest(
			http.MethodGet,
			"http://example.test/b?"+tt.query,
			"",
			map[string]string{"Authorization": tt.auth},
		)
		version, authType := requestSignatureInfo(r)
		if version != tt.version || authType != tt.authType {
			t.Errorf("requestSignatureInfo(%q, %q) = %q, %q", tt.auth, tt.query, version, authType)
		}
	}

	bad := newRequest(http.MethodGet, "http://example.test/b", "", nil)
	bad.RemoteAddr = "not-an-address"
	if ip := requestSourceIP(bad); ip != "" {
		t.Errorf("requestSourceIP(invalid) = %q, want empty", ip)
	}
	if _, ok := requestConditionKeys(bad)["aws:sourceip"]; ok {
		t.Error("an unparsable remote address must leave aws:SourceIp absent")
	}
}

func TestExtractPolicyHeadersIncludesAllAmzHeaders(t *testing.T) {
	t.Parallel()
	req := newRequest(http.MethodPut, "http://example.test/b/k", "", map[string]string{
		"X-Amz-Storage-Class":    "STANDARD_IA",
		"X-Amz-Object-Lock-Mode": "GOVERNANCE",
		"X-Amz-Empty":            "",
		"Referer":                "https://example.com",
	})
	headers := extractPolicyHeaders(req)
	if headers["x-amz-storage-class"] != "STANDARD_IA" ||
		headers["x-amz-object-lock-mode"] != "GOVERNANCE" {
		t.Fatalf("x-amz-* headers missing: %v", headers)
	}
	if _, ok := headers["x-amz-empty"]; ok {
		t.Fatal("empty headers must stay absent")
	}
	ctx := backend.PolicyEvalContext{
		Action:    "s3:PutObject",
		Resource:  "arn:aws:s3:::b/k",
		Headers:   headers,
		AccessKey: "x",
	}
	policy := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"*",` +
		`"Condition":{"StringEquals":{"s3:x-amz-storage-class":"STANDARD_IA"}}}]}`
	if backend.EvaluateBucketPolicyAccess(policy, ctx) != backend.PolicyEffectDeny {
		t.Fatal("s3:x-amz-storage-class condition should see the header")
	}
}

func TestFillPolicyContextKeepsCallerValues(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)
	req := newRequest(http.MethodGet, "http://example.test/b/k?prefix=x", "", map[string]string{
		"Authorization": authHeader("minis3-alt-access-key"),
	})
	custom := &backend.PolicyPrincipal{AccountID: "999"}
	ctx := h.fillPolicyContext(req, "b", "s3:GetObject", "k", backend.PolicyEvalContext{
		Principal:     custom,
		ConditionKeys: map[string][]string{"S3:Prefix": {"override"}},
	})
	if ctx.Principal != custom {
		t.Fatal("an explicit principal must be kept")
	}
	if got := ctx.ConditionKeys["s3:prefix"]; len(got) != 1 || got[0] != "override" {
		t.Fatalf("explicit condition keys win over request ones, got %q", got)
	}
	if ctx.Resource != "arn:aws:s3:::b/k" || ctx.Action != "s3:GetObject" ||
		ctx.CurrentTime.IsZero() {
		t.Fatalf("defaults not filled: %+v", ctx)
	}
	anon := h.fillPolicyContext(newRequest(http.MethodGet, "http://example.test/b", "", nil),
		"b", "s3:ListBucket", "", backend.PolicyEvalContext{})
	if anon.Principal == nil || !anon.Principal.Anonymous || !anon.IsAnonymous {
		t.Fatalf("unsigned request should be anonymous: %+v", anon.Principal)
	}
}
