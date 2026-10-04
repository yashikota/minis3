package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Credentials holds AWS credentials for signature verification.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// DefaultCredentials returns the default credentials for minis3.
// These match the s3tests.conf configuration.
func DefaultCredentials() map[string]string {
	return map[string]string{
		"test":                  "test",
		"minis3-access-key":     "minis3-secret-key",
		"minis3-alt-access-key": "minis3-alt-secret-key",
		"tenant-access-key":     "tenant-secret-key",
		"iam-access-key":        "iam-secret-key",
		"root-access-key":       "root-secret-key",
		"altroot-access-key":    "altroot-secret-key",
	}
}

func defaultCredentialLookup(accessKey string) (string, bool) {
	secret, ok := DefaultCredentials()[accessKey]
	return secret, ok
}

// credentialLookupFn resolves an access key to its secret key.
// Overridden at handler initialization to also check dynamic IAM credentials.
var credentialLookupFn = defaultCredentialLookup

// isPresignedURL checks if the request is a presigned URL request.
func isPresignedURL(r *http.Request) bool {
	query := r.URL.Query()
	return query.Has("X-Amz-Signature") || query.Has("Signature")
}

// verifyAuthorizationHeader verifies standard Authorization header signatures.
func verifyAuthorizationHeader(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil
	}

	if strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		accessKey := extractAccessKey(r)
		secretKey, ok := credentialLookupFn(accessKey)
		if !ok {
			return &presignedError{
				code:    "InvalidAccessKeyId",
				message: "The AWS Access Key Id you provided does not exist in our records",
			}
		}
		return verifyAuthorizationHeaderV4(r, auth, secretKey)
	}
	if strings.HasPrefix(auth, "AWS ") {
		return verifyAuthorizationHeaderV2(r, auth)
	}

	return &presignedError{code: "AccessDenied", message: "Access Denied"}
}

// iso8601FromHTTPDateHeader converts an HTTP Date header value to the SigV4
// yyyyMMddTHHmmssZ format, accepting RFC 1123 and its numeric-zone variants
// (e.g. "Sat, 03 Oct 2026 17:56:02 GMT" and "... -0000" as emitted by AWS
// SDKs). It returns "" when the value cannot be parsed.
func iso8601FromHTTPDateHeader(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC().Format("20060102T150405Z")
		}
	}
	return ""
}

func verifyAuthorizationHeaderV4(r *http.Request, auth, secretKey string) error {
	const prefix = "AWS4-HMAC-SHA256 "
	kvStr := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	fields := strings.Split(kvStr, ",")
	values := map[string]string{}
	for _, f := range fields {
		parts := strings.SplitN(strings.TrimSpace(f), "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[parts[0]] = parts[1]
	}

	credential := values["Credential"]
	signedHeadersStr := values["SignedHeaders"]
	signature := values["Signature"]
	if credential == "" || signedHeadersStr == "" || signature == "" {
		return &presignedError{code: "AccessDenied", message: "Access Denied"}
	}

	credParts := strings.Split(credential, "/")
	if len(credParts) < 5 {
		return &presignedError{code: "AccessDenied", message: "Access Denied"}
	}
	dateStamp := credParts[1]
	region := credParts[2]
	service := credParts[3]

	dateTime := r.Header.Get("x-amz-date")
	if dateTime == "" {
		// Fall back to the HTTP Date header. Per AWS SigV4 documentation
		// the request date may be carried by either header, with x-amz-date
		// taking precedence when both are present.
		dateTime = iso8601FromHTTPDateHeader(r.Header.Get("Date"))
	}
	if dateTime == "" {
		return &presignedError{code: "AccessDenied", message: "Access Denied"}
	}

	canonicalURI := r.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	params := make([]string, 0)
	query := r.URL.Query()
	for key := range query {
		values := query[key]
		for _, value := range values {
			params = append(params, awsQueryEscape(key)+"="+awsQueryEscape(value))
		}
	}
	sort.Strings(params)
	canonicalQueryString := strings.Join(params, "&")

	// Build canonical headers (header names are case-insensitive per AWS spec).
	// Normalize SignedHeaders to lowercase so mixed-case values like
	// "Host;X-Amz-Date" verify the same as "host;x-amz-date".
	signedHeaders := strings.Split(strings.ToLower(signedHeadersStr), ";")
	for i, header := range signedHeaders {
		signedHeaders[i] = strings.TrimSpace(header)
	}
	normalizedParts := make([]string, 0, len(signedHeaders))
	for _, header := range signedHeaders {
		if header == "" {
			continue
		}
		normalizedParts = append(normalizedParts, header)
	}
	normalizedSignedHeaders := strings.Join(normalizedParts, ";")
	canonicalHeaders := ""
	for _, header := range normalizedParts {
		var value string
		if header == "host" {
			value = r.Host
		} else {
			value = strings.Join(r.Header.Values(header), ",")
		}
		canonicalHeaders += header + ":" + strings.TrimSpace(value) + "\n"
	}

	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		body := []byte{}
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(r.Body)
			if err != nil {
				return &presignedError{code: "AccessDenied", message: "Access Denied"}
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		normalizedSignedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		dateTime,
		dateStamp + "/" + region + "/" + service + "/aws4_request",
		sha256Hash(canonicalRequest),
	}, "\n")

	signingKey := getSignatureKey(secretKey, dateStamp, region, service)
	expectedSignature := hmacSHA256Hex(signingKey, stringToSign)
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return &presignedError{
			code:    "SignatureDoesNotMatch",
			message: "The request signature we calculated does not match the signature you provided",
		}
	}

	return nil
}

func verifyAuthorizationHeaderV2(r *http.Request, auth string) error {
	parts := strings.SplitN(strings.TrimPrefix(auth, "AWS "), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return &presignedError{code: "AccessDenied", message: "Access Denied"}
	}
	// AWS validates the x-amz-date header when present on SigV2 requests.
	// boto never sends it for SigV2, so only tampered requests reach here.
	if values, present := r.Header["X-Amz-Date"]; present {
		dateHeader := ""
		if len(values) > 0 {
			dateHeader = values[0]
		}
		if err := checkSigV2RequestDate(dateHeader); err != nil {
			return err
		}
	}
	return nil
}

// checkSigV2RequestDate validates an x-amz-date header value on SigV2
// requests. Unparseable and pre-epoch values yield AccessDenied, while dates
// outside the 15-minute skew window yield RequestTimeTooSkewed.
func checkSigV2RequestDate(value string) error {
	parsed, ok := parseLenientHTTPDate(value)
	if !ok || parsed.Unix() < 0 {
		return &presignedError{code: "AccessDenied", message: "Access Denied"}
	}
	if skew := time.Since(parsed); skew > 15*time.Minute || skew < -15*time.Minute {
		return &presignedError{
			code:    "RequestTimeTooSkewed",
			message: "The difference between the request time and the current time is too large.",
		}
	}
	return nil
}

// parseLenientHTTPDate parses HTTP date headers while ignoring weekday
// mismatch: AWS evaluates dates (e.g. for skew) even when the weekday label
// is inconsistent with the calendar date.
func parseLenientHTTPDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if idx := strings.Index(value, ","); idx != -1 {
		candidate := strings.TrimSpace(value[idx+1:])
		for _, layout := range []string{"02 Jan 2006 15:04:05 MST", "02 Jan 2006 15:04:05 -0700"} {
			if parsed, err := time.Parse(layout, candidate); err == nil {
				return parsed, true
			}
		}
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

// verifyPresignedURL verifies a presigned URL request.
// Returns nil if valid, error message otherwise.
func verifyPresignedURL(r *http.Request) error {
	query := r.URL.Query()

	// Check for V4 signature (X-Amz-Signature)
	if query.Has("X-Amz-Signature") {
		return verifyPresignedURLV4(r)
	}

	// Check for V2 signature (Signature)
	if query.Has("Signature") {
		return verifyPresignedURLV2(r)
	}

	return nil
}

// verifyPresignedURLV4 verifies AWS Signature Version 4 presigned URL.
func verifyPresignedURLV4(r *http.Request) error {
	query := r.URL.Query()

	// Check required parameters
	algorithm := query.Get("X-Amz-Algorithm")
	if algorithm != "AWS4-HMAC-SHA256" {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Invalid algorithm",
		}
	}

	credential := query.Get("X-Amz-Credential")
	if credential == "" {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Missing X-Amz-Credential",
		}
	}

	dateStr := query.Get("X-Amz-Date")
	if dateStr == "" {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Missing X-Amz-Date",
		}
	}

	expiresStr := query.Get("X-Amz-Expires")
	if expiresStr == "" {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Missing X-Amz-Expires",
		}
	}

	signature := query.Get("X-Amz-Signature")
	if signature == "" {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Missing X-Amz-Signature",
		}
	}

	// Parse and check expiration
	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || expires <= 0 {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Invalid X-Amz-Expires",
		}
	}

	// Maximum expiration is 7 days (604800 seconds)
	if expires > 604800 {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "X-Amz-Expires must be less than 604800 seconds",
		}
	}

	// Parse request time
	requestTime, err := time.Parse("20060102T150405Z", dateStr)
	if err != nil {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Invalid X-Amz-Date format",
		}
	}

	// Check if URL has expired
	expirationTime := requestTime.Add(time.Duration(expires) * time.Second)
	if time.Now().After(expirationTime) {
		return &presignedError{code: "AccessDenied", message: "Request has expired"}
	}

	// Parse credential to get access key
	credParts := strings.Split(credential, "/")
	if len(credParts) < 5 {
		return &presignedError{
			code:    "AuthorizationQueryParametersError",
			message: "Invalid X-Amz-Credential format",
		}
	}

	accessKey := credParts[0]
	dateStamp := credParts[1]
	region := credParts[2]
	service := credParts[3]

	// Look up secret key
	secretKey, ok := credentialLookupFn(accessKey)
	if !ok {
		return &presignedError{
			code:    "InvalidAccessKeyId",
			message: "The AWS Access Key Id you provided does not exist in our records",
		}
	}

	// Verify signature
	signedHeaders := query.Get("X-Amz-SignedHeaders")
	expectedSignature := calculatePresignedSignatureV4(
		r,
		secretKey,
		dateStamp,
		region,
		service,
		signedHeaders,
	)

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return &presignedError{
			code:    "SignatureDoesNotMatch",
			message: "The request signature we calculated does not match the signature you provided",
		}
	}

	return nil
}

// calculatePresignedSignatureV4 calculates the AWS Signature Version 4 for presigned URL.
func calculatePresignedSignatureV4(
	r *http.Request,
	secretKey, dateStamp, region, service, signedHeadersStr string,
) string {
	// Get canonical URI (must use escaped path for SigV4)
	canonicalURI := r.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Build canonical query string (excluding X-Amz-Signature)
	query := r.URL.Query()
	params := make([]string, 0, len(query))
	for key := range query {
		if key != "X-Amz-Signature" {
			values := query[key]
			for _, value := range values {
				params = append(params, awsQueryEscape(key)+"="+awsQueryEscape(value))
			}
		}
	}
	sort.Strings(params)
	canonicalQueryString := strings.Join(params, "&")

	// Build canonical headers (header names are case-insensitive per AWS spec).
	// Normalize SignedHeaders to lowercase so mixed-case values like
	// "Host;X-Amz-Date" verify the same as "host;x-amz-date".
	signedHeaders := strings.Split(strings.ToLower(signedHeadersStr), ";")
	for i, header := range signedHeaders {
		signedHeaders[i] = strings.TrimSpace(header)
	}
	sort.Strings(signedHeaders)
	normalizedParts := make([]string, 0, len(signedHeaders))
	for _, header := range signedHeaders {
		if header == "" {
			continue
		}
		normalizedParts = append(normalizedParts, header)
	}
	normalizedSignedHeaders := strings.Join(normalizedParts, ";")
	canonicalHeaders := ""
	for _, header := range normalizedParts {
		var value string
		if header == "host" {
			value = r.Host
		} else {
			value = r.Header.Get(header)
		}
		canonicalHeaders += header + ":" + strings.TrimSpace(value) + "\n"
	}

	// For presigned URLs, payload hash is always UNSIGNED-PAYLOAD
	payloadHash := "UNSIGNED-PAYLOAD"

	// Create canonical request
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		normalizedSignedHeaders,
		payloadHash,
	}, "\n")

	// Calculate string to sign
	algorithm := "AWS4-HMAC-SHA256"
	requestDateTime := query.Get("X-Amz-Date")
	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	canonicalRequestHash := sha256Hash(canonicalRequest)

	stringToSign := strings.Join([]string{
		algorithm,
		requestDateTime,
		credentialScope,
		canonicalRequestHash,
	}, "\n")

	// Calculate signing key
	signingKey := getSignatureKey(secretKey, dateStamp, region, service)

	// Calculate signature
	signature := hmacSHA256Hex(signingKey, stringToSign)

	return signature
}

// verifyPresignedURLV2 verifies AWS Signature Version 2 presigned URL.
// V2 is deprecated but still supported for backward compatibility.
func verifyPresignedURLV2(r *http.Request) error {
	query := r.URL.Query()

	expiresStr := query.Get("Expires")
	if expiresStr == "" {
		return &presignedError{code: "MissingSecurityHeader", message: "Missing Expires"}
	}

	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return &presignedError{code: "InvalidArgument", message: "Invalid Expires format"}
	}

	// Check if URL has expired
	expirationTime := time.Unix(expires, 0)
	if time.Now().After(expirationTime) {
		return &presignedError{code: "AccessDenied", message: "Request has expired"}
	}

	// For V2, we'll accept any valid-looking signature for mock purposes
	// A full implementation would verify the signature
	return nil
}

// presignedError represents a presigned URL verification error.
type presignedError struct {
	code    string
	message string
}

func (e *presignedError) Error() string {
	return e.message
}

// getSignatureKey generates the AWS Signature Version 4 signing key.
func getSignatureKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// hmacSHA256 calculates HMAC-SHA256.
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// hmacSHA256Hex calculates HMAC-SHA256 and returns hex-encoded string.
func hmacSHA256Hex(key []byte, data string) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

// sha256Hash calculates SHA256 and returns hex-encoded string.
func sha256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func awsQueryEscape(s string) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}
