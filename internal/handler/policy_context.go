package handler

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// fillPolicyContext completes ctx with everything bucket policy evaluation
// needs to know about the request: the caller's identity, the request headers
// and the global and S3-specific condition keys. Fields already set in ctx
// (for example object tags) are kept.
func (h *Handler) fillPolicyContext(
	r *http.Request,
	bucketName, action, key string,
	ctx backend.PolicyEvalContext,
) backend.PolicyEvalContext {
	if ctx.Action == "" {
		ctx.Action = action
	}
	if ctx.Resource == "" {
		ctx.Resource = policyResourceARN(bucketName, key)
	}
	if ctx.Headers == nil {
		ctx.Headers = extractPolicyHeaders(r)
	}
	if ctx.AccessKey == "" {
		ctx.AccessKey = extractAccessKey(r)
	}
	ctx.IsAnonymous = isAnonymousRequest(r)
	if ctx.Principal == nil {
		if ctx.IsAnonymous {
			ctx.Principal = &backend.PolicyPrincipal{Anonymous: true}
		} else {
			ctx.Principal = h.backend.PrincipalForAccessKey(ctx.AccessKey)
		}
	}
	if ctx.CurrentTime.IsZero() {
		ctx.CurrentTime = time.Now().UTC()
	}
	keys := requestConditionKeys(r)
	for k, v := range ctx.ConditionKeys {
		keys[strings.ToLower(k)] = v
	}
	ctx.ConditionKeys = keys
	return ctx
}

// requestConditionKeys returns the condition keys derived from the HTTP
// request itself, keyed by lower-cased condition key name.
func requestConditionKeys(r *http.Request) map[string][]string {
	keys := make(map[string][]string)
	if ip := requestSourceIP(r); ip != "" {
		keys["aws:sourceip"] = []string{ip}
	}
	keys["aws:securetransport"] = []string{strconv.FormatBool(r.TLS != nil)}
	if ua := r.Header.Get("User-Agent"); ua != "" {
		keys["aws:useragent"] = []string{ua}
	}

	if version, authType := requestSignatureInfo(r); version != "" {
		keys["s3:signatureversion"] = []string{version}
		keys["s3:authtype"] = []string{authType}
	}

	query := r.URL.Query()
	for _, name := range []string{"prefix", "delimiter", "max-keys", "versionId"} {
		if query.Has(name) {
			keys["s3:"+strings.ToLower(name)] = []string{query.Get(name)}
		}
	}
	return keys
}

// requestSourceIP returns the client IP of the TCP connection.
func requestSourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}

// requestSignatureInfo returns the s3:signatureversion and s3:authType
// condition values ("AWS"/"AWS4-HMAC-SHA256" and
// "REST-HEADER"/"REST-QUERY-STRING").
func requestSignatureInfo(r *http.Request) (string, string) {
	auth := r.Header.Get("Authorization")
	query := r.URL.Query()
	switch {
	case strings.HasPrefix(auth, "AWS4-HMAC-SHA256"):
		return "AWS4-HMAC-SHA256", "REST-HEADER"
	case strings.HasPrefix(auth, "AWS "):
		return "AWS", "REST-HEADER"
	case query.Has("X-Amz-Signature"):
		return "AWS4-HMAC-SHA256", "REST-QUERY-STRING"
	case query.Has("Signature"):
		return "AWS", "REST-QUERY-STRING"
	default:
		return "", ""
	}
}
