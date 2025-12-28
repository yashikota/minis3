package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
		"minis3-access-key":     "minis3-secret-key",
		"minis3-alt-access-key": "minis3-alt-secret-key",
		"tenant-access-key":     "tenant-secret-key",
		"iam-access-key":        "iam-secret-key",
		"root-access-key":       "root-secret-key",
		"altroot-access-key":    "altroot-secret-key",
	}
}

// isPresignedURL checks if the request is a presigned URL request.
func isPresignedURL(r *http.Request) bool {
	query := r.URL.Query()
	return query.Has("X-Amz-Signature") || query.Has("Signature")
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
	credentials := DefaultCredentials()
	secretKey, ok := credentials[accessKey]
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
				params = append(params, url.QueryEscape(key)+"="+url.QueryEscape(value))
			}
		}
	}
	sort.Strings(params)
	canonicalQueryString := strings.Join(params, "&")

	// Build canonical headers
	signedHeaders := strings.Split(signedHeadersStr, ";")
	sort.Strings(signedHeaders)
	canonicalHeaders := ""
	for _, header := range signedHeaders {
		header = strings.ToLower(strings.TrimSpace(header))
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
		signedHeadersStr,
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
