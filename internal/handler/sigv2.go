package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// sigV2Subresources are the query parameters that belong to the
// CanonicalizedResource of a Signature Version 2 string to sign (Amazon S3
// "Signing and authenticating REST requests", plus the subresources added
// since, as botocore's HmacV1Auth signs them).
var sigV2Subresources = []string{
	"accelerate", "acl", "analytics", "cors", "defaultObjectAcl", "delete",
	"encryption", "intelligent-tiering", "inventory", "legal-hold", "lifecycle",
	"location", "logging", "metrics", "notification", "object-lock",
	"ownershipControls", "partNumber", "policy", "policyStatus", "publicAccessBlock",
	"replication", "requestPayment", "response-cache-control",
	"response-content-disposition", "response-content-encoding",
	"response-content-language", "response-content-type", "response-expires",
	"restore", "retention", "select", "select-type", "storageClass", "tagging",
	"torrent", "uploadId", "uploads", "versionId", "versioning", "versions",
	"website",
}

// botocoreSigV2Subresources is the subset botocore signs. Clients that use
// it leave out newer subresources (e.g. ?retention), so both forms of the
// CanonicalizedResource are accepted.
var botocoreSigV2Subresources = []string{
	"accelerate", "acl", "analytics", "cors", "defaultObjectAcl", "delete",
	"inventory", "lifecycle", "location", "logging", "metrics", "notification",
	"object-lock", "partNumber", "policy", "replication", "requestPayment",
	"response-cache-control", "response-content-disposition",
	"response-content-encoding", "response-content-language",
	"response-content-type", "response-expires", "restore", "select",
	"select-type", "storageClass", "tagging", "torrent", "uploadId", "uploads",
	"versionId", "versioning", "versions", "website",
}

// sigV2StringsToSign returns the Signature Version 2 strings to sign for r
// that a client may have used. date is the Date element: the Date header
// (empty when x-amz-date is sent) or, for presigned URLs, Expires.
func sigV2StringsToSign(r *http.Request, date string) []string {
	head := r.Method + "\n" +
		r.Header.Get("Content-MD5") + "\n" +
		r.Header.Get("Content-Type") + "\n" +
		date + "\n" +
		canonicalizedAmzHeaders(r.Header)
	var out []string
	for _, path := range sigV2Paths(r) {
		for _, subresources := range [][]string{sigV2Subresources, botocoreSigV2Subresources} {
			s := head + path + canonicalizedSubresources(r.URL.Query(), subresources)
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// sigV2Paths returns the request path as sent and in its canonical
// escaping; clients differ in how they escape keys.
func sigV2Paths(r *http.Request) []string {
	paths := []string{r.URL.EscapedPath()}
	if escaped := (&url.URL{Path: r.URL.Path}).EscapedPath(); escaped != paths[0] {
		paths = append(paths, escaped)
	}
	return paths
}

// canonicalizedAmzHeaders lower-cases the x-amz-* header names, sorts them,
// joins repeated values with commas and ends every header with a newline.
func canonicalizedAmzHeaders(header http.Header) string {
	values := map[string][]string{}
	for name, vs := range header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		for _, v := range vs {
			values[lower] = append(values[lower], strings.TrimSpace(v))
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(values[name], ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// canonicalizedSubresources returns "?a&b=v..." for the signed query
// parameters present in query, in sorted order.
func canonicalizedSubresources(query url.Values, signed []string) string {
	var parts []string
	for _, name := range signed {
		vs, ok := query[name]
		if !ok {
			continue
		}
		if len(vs) == 0 || vs[0] == "" {
			parts = append(parts, name)
		} else {
			parts = append(parts, name+"="+vs[0])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return "?" + strings.Join(parts, "&")
}

// sigV2Signature is base64(HMAC-SHA1(secretKey, stringToSign)).
func sigV2Signature(secretKey, stringToSign string) string {
	mac := hmac.New(sha1.New, []byte(secretKey))
	_, _ = mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// verifySigV2Signature reports whether signature signs one of the strings
// a client may have signed for r.
func verifySigV2Signature(r *http.Request, secretKey, date, signature string) bool {
	for _, stringToSign := range sigV2StringsToSign(r, date) {
		if hmac.Equal([]byte(sigV2Signature(secretKey, stringToSign)), []byte(signature)) {
			return true
		}
	}
	return false
}

var errSignatureDoesNotMatch = &presignedError{
	code:    "SignatureDoesNotMatch",
	message: "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
}

var errInvalidAccessKeyID = &presignedError{
	code:    "InvalidAccessKeyId",
	message: "The AWS Access Key Id you provided does not exist in our records",
}
