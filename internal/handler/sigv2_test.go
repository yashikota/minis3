package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sigV2Vectors were produced by botocore's HmacV1Auth (the SigV2 signer
// boto3 and the Ceph s3-tests use) with Date "Sat, 24 Oct 2026 03:00:00
// GMT", plus the example from the Amazon S3 SigV2 documentation.
var sigV2Vectors = []struct {
	name, method, target, accessKey, secretKey, signature string
	headers                                               map[string]string
}{
	{
		name: "AWS documentation example", method: "GET",
		target:    "/awsexamplebucket1/photos/puppy.jpg",
		accessKey: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		headers:   map[string]string{"Date": "Tue, 27 Mar 2007 19:36:42 +0000"},
		signature: "qgk2+6Sv9/oM7G3qLEjTH1a1l1g=",
	},
	{
		name:      "object GET",
		method:    "GET",
		target:    "/bucket/key",
		signature: "9KOiSNvlYFOGZuvGUp1ARBoe7no=",
	},
	{
		name: "headers, x-amz headers and a subresource", method: "PUT",
		target: "/bucket/photos/puppy.jpg?acl",
		headers: map[string]string{
			"Content-Type": "image/jpeg", "Content-MD5": "1B2M2Y8AsgTpgAmY7PhCfg==",
			"x-amz-acl": "public-read", "X-Amz-Meta-Color": "red", "x-amz-meta-tags": "a",
		},
		signature: "qY3JD/lEvgn8kJAJhJ7kh7ucAF8=",
	},
	{
		name:      "bucket subresource",
		method:    "GET",
		target:    "/bucket?versioning",
		signature: "J6B13qevZd8uWEyg/GZ05dpnNn4=",
	},
	{
		name:      "escaped key and versionId",
		method:    "DELETE",
		target:    "/bucket/key%20with%20space?versionId=abc",
		signature: "4blJ7FO1z8qElhIn7p4lvJhQyeE=",
	},
	{
		name: "subresource botocore does not sign", method: "GET",
		target: "/bucket/key?retention", signature: "9KOiSNvlYFOGZuvGUp1ARBoe7no=",
	},
	{
		name: "ordinary query parameters are not signed", method: "GET",
		target: "/bucket?list-type=2&prefix=a", signature: "N7yJa0UJ3uKEhpqwiefQf6HZoWk=",
	},
	{
		name: "x-amz-date replaces Date", method: "PUT",
		target:    "/bucket/key?partNumber=2&uploadId=xyz",
		headers:   map[string]string{"x-amz-date": "Sat, 24 Oct 2026 03:00:00 GMT"},
		signature: "Jk27mBETiEoO14KAZndEbTfQRuY=",
	},
	{
		name:      "UTF-8 key and response override",
		method:    "GET",
		target:    "/bucket/k%C3%A9y?response-content-type=text/plain",
		signature: "W6LdCZGlBeKqAZJk1NsOk+kt0gE=",
	},
}

func sigV2VectorRequest(method, target string, headers map[string]string) (*http.Request, string) {
	req := httptest.NewRequest(method, "http://127.0.0.1:9000"+target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	date := "Sat, 24 Oct 2026 03:00:00 GMT"
	if d, ok := headers["Date"]; ok {
		date = d
	}
	req.Header.Set("Date", date)
	return req, date
}

func TestSigV2KnownAnswers(t *testing.T) {
	for _, v := range sigV2Vectors {
		t.Run(v.name, func(t *testing.T) {
			secret := v.secretKey
			if secret == "" {
				secret = DefaultCredentials()["minis3-access-key"]
			}
			req, date := sigV2VectorRequest(v.method, v.target, v.headers)
			if !verifySigV2Signature(req, secret, date, v.signature) {
				t.Fatalf("signature %s not accepted; strings to sign: %q",
					v.signature, sigV2StringsToSign(req, date))
			}
			for _, wrong := range []string{secret + "x", ""} {
				if verifySigV2Signature(req, wrong, date, v.signature) {
					t.Fatalf("signature accepted with secret %q", wrong)
				}
			}
			// Any change to a signed element breaks the signature.
			tampered, _ := sigV2VectorRequest(v.method, v.target, v.headers)
			tampered.Method = "POST"
			if verifySigV2Signature(tampered, secret, date, v.signature) {
				t.Fatal("signature accepted for another method")
			}
			tampered, _ = sigV2VectorRequest(v.method, v.target, v.headers)
			tampered.Header.Set("x-amz-meta-injected", "1")
			if verifySigV2Signature(tampered, secret, date, v.signature) {
				t.Fatal("signature accepted with an added x-amz header")
			}
			tampered, _ = sigV2VectorRequest(v.method, "/other"+v.target, v.headers)
			if verifySigV2Signature(tampered, secret, date, v.signature) {
				t.Fatal("signature accepted for another resource")
			}
		})
	}
}

func TestSigV2PresignedKnownAnswer(t *testing.T) {
	// botocore HmacV1QueryAuth with Expires 1800000000.
	target := "/bucket/key?AWSAccessKeyId=minis3-access-key&Signature=QZUF06n9IU8iFqLxPNLYkWtg4iQ%3D&Expires=1800000000"
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9000"+target, nil)
	if err := verifyPresignedURL(req); err != nil {
		t.Fatalf("botocore presigned URL rejected: %v", err)
	}
	for name, mutate := range map[string]func(q url.Values){
		"other key":         func(q url.Values) { q.Set("AWSAccessKeyId", "minis3-alt-access-key") },
		"unknown key":       func(q url.Values) { q.Set("AWSAccessKeyId", "nobody") },
		"no key":            func(q url.Values) { q.Del("AWSAccessKeyId") },
		"later expiry":      func(q url.Values) { q.Set("Expires", "1800000001") },
		"bad signature":     func(q url.Values) { q.Set("Signature", "QZUF06n9IU8iFqLxPNLYkWtg4iR=") },
		"added subresource": func(q url.Values) { q.Set("acl", "") },
	} {
		t.Run(name, func(t *testing.T) {
			u, _ := url.Parse("http://127.0.0.1:9000" + target)
			q := u.Query()
			mutate(q)
			u.RawQuery = q.Encode()
			err := verifyPresignedURL(httptest.NewRequest(http.MethodGet, u.String(), nil))
			want := map[string]string{
				"unknown key": "InvalidAccessKeyId", "no key": "AccessDenied",
			}[name]
			if want == "" {
				want = "SignatureDoesNotMatch"
			}
			requirePresignedErrCode(t, err, want)
		})
	}
}

func TestCanonicalizedAmzHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("X-Amz-Meta-B", " two ")
	h.Add("X-Amz-Meta-B", "three")
	h.Add("x-amz-acl", "private")
	h.Add("Content-Type", "text/plain")
	want := "x-amz-acl:private\nx-amz-meta-b:two,three\n"
	if got := canonicalizedAmzHeaders(h); got != want {
		t.Fatalf("canonicalizedAmzHeaders = %q, want %q", got, want)
	}
	if got := canonicalizedAmzHeaders(http.Header{}); got != "" {
		t.Fatalf("no x-amz headers = %q", got)
	}
}

func TestCanonicalizedSubresources(t *testing.T) {
	q, _ := url.ParseQuery("versionId=v1&acl&prefix=p&uploadId=u&partNumber=3")
	want := "?acl&partNumber=3&uploadId=u&versionId=v1"
	if got := canonicalizedSubresources(q, sigV2Subresources); got != want {
		t.Fatalf("canonicalizedSubresources = %q, want %q", got, want)
	}
	if got := canonicalizedSubresources(url.Values{"prefix": {"p"}}, sigV2Subresources); got != "" {
		t.Fatalf("unsigned parameters only = %q", got)
	}
}

func TestSigV2AuthorizationHeaderThroughHandler(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "sigv2")
	b.SetBucketOwner("sigv2", "minis3-access-key")
	mustPutObject(t, b, "sigv2", "key", "data")

	sign := func(req *http.Request, accessKey, secretKey string) {
		date := req.Header.Get("Date")
		if _, ok := req.Header["X-Amz-Date"]; ok {
			date = ""
		}
		req.Header.Set("Authorization", "AWS "+accessKey+":"+
			sigV2Signature(secretKey, sigV2StringsToSign(req, date)[0]))
	}
	get := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/sigv2/key", nil)
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		return req
	}
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	req := get()
	sign(req, "minis3-access-key", "minis3-secret-key")
	requireStatus(t, serve(req), http.StatusOK)

	req = get()
	sign(req, "minis3-access-key", "wrong-secret")
	w := serve(req)
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "SignatureDoesNotMatch")

	req = get()
	sign(req, "nobody", "whatever")
	w = serve(req)
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "InvalidAccessKeyId")

	// A signature for another key cannot be replayed under this one.
	req = get()
	sign(req, "minis3-alt-access-key", "minis3-alt-secret-key")
	req.Header.Set("Authorization", strings.Replace(
		req.Header.Get("Authorization"), "minis3-alt-access-key", "minis3-access-key", 1))
	requireStatus(t, serve(req), http.StatusForbidden)

	// Date is required and must be recent unless x-amz-date is sent.
	req = get()
	req.Header.Del("Date")
	sign(req, "minis3-access-key", "minis3-secret-key")
	requireStatus(t, serve(req), http.StatusForbidden)
	req = get()
	req.Header.Set("Date", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	sign(req, "minis3-access-key", "minis3-secret-key")
	w = serve(req)
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "RequestTimeTooSkewed")
	req = get()
	req.Header.Set("Date", "garbage")
	req.Header.Set("x-amz-date", time.Now().UTC().Format(http.TimeFormat))
	sign(req, "minis3-access-key", "minis3-secret-key")
	requireStatus(t, serve(req), http.StatusOK)

	// IAM access keys created through the IAM API sign SigV2 too.
	if _, err := b.CreateIAMUser("sigv2-user", "/"); err != nil {
		t.Fatalf("CreateIAMUser: %v", err)
	}
	key, err := b.CreateIAMAccessKey("sigv2-user")
	if err != nil {
		t.Fatalf("CreateIAMAccessKey: %v", err)
	}
	req = get()
	sign(req, key.AccessKeyId, key.SecretAccessKey)
	if w := serve(req); w.Code == http.StatusForbidden {
		requireS3ErrorCode(t, w, "AccessDenied")
	}
	req = get()
	sign(req, key.AccessKeyId, "wrong")
	requireS3ErrorCode(t, serve(req), "SignatureDoesNotMatch")
}

func TestSigV2PresignedURLThroughHandler(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "sigv2")
	b.SetBucketOwner("sigv2", "minis3-access-key")
	mustPutObject(t, b, "sigv2", "key", "data")

	presign := func(secretKey string, expires time.Time) *http.Request {
		e := strconv.FormatInt(expires.Unix(), 10)
		req := httptest.NewRequest(http.MethodGet, "http://example.test/sigv2/key", nil)
		sig := sigV2Signature(secretKey, sigV2StringsToSign(req, e)[0])
		q := url.Values{"AWSAccessKeyId": {"minis3-access-key"}, "Expires": {e}, "Signature": {sig}}
		return httptest.NewRequest(http.MethodGet, "http://example.test/sigv2/key?"+q.Encode(), nil)
	}
	serve := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	requireStatus(t, serve(presign("minis3-secret-key", time.Now().Add(time.Hour))), http.StatusOK)
	w := serve(presign("wrong", time.Now().Add(time.Hour)))
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "SignatureDoesNotMatch")
	w = serve(presign("minis3-secret-key", time.Now().Add(-time.Minute)))
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "AccessDenied")
}
