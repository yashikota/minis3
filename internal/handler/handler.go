package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/yashikota/minis3/internal/backend"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	backend *backend.Backend
}

// New creates a new Handler with the given backend.
func New(b *backend.Backend) *Handler {
	return &Handler{backend: b}
}

// generateRequestId generates a random request ID (16 hex characters).
func generateRequestId() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-amz-request-id", generateRequestId())
	w.Header().Set("x-amz-id-2", generateRequestId())
	h.handleRequest(w, r)
}

// handleRequest is the main dispatch point.
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		origin := r.Header.Get("Origin")
		requestMethod := r.Header.Get("Access-Control-Request-Method")
		if origin == "" || requestMethod == "" {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Invalid CORS preflight request",
			)
			return
		}
	}

	// Verify presigned URL if applicable
	if isPresignedURL(r) {
		if err := verifyPresignedURL(r); err != nil {
			if pe, ok := err.(*presignedError); ok {
				backend.WriteError(w, http.StatusForbidden, pe.code, pe.message)
			} else {
				backend.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error())
			}
			return
		}
	}

	path := r.URL.Path
	if path == "/" {
		h.handleService(w, r)
		return
	}

	bucketName, key := extractBucketAndKey(path)
	expectedBucketOwner := r.Header.Get("x-amz-expected-bucket-owner")
	if expectedBucketOwner != "" && expectedBucketOwner != backend.DefaultOwner().ID {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	if key == "" {
		h.handleBucket(w, r, bucketName)
	} else {
		h.handleObject(w, r, bucketName, key)
	}
}

// extractAccessKey extracts the AWS access key from the Authorization header.
func extractAccessKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		// Check query parameter for presigned URLs
		if ak := r.URL.Query().Get("X-Amz-Credential"); ak != "" {
			parts := strings.SplitN(ak, "/", 2)
			return parts[0]
		}
		if ak := r.URL.Query().Get("AWSAccessKeyId"); ak != "" {
			return ak
		}
		return ""
	}
	// AWS4-HMAC-SHA256 Credential=ACCESS_KEY/date/region/s3/aws4_request, ...
	if strings.HasPrefix(auth, "AWS4-HMAC-SHA256") {
		parts := strings.SplitN(auth, "Credential=", 2)
		if len(parts) < 2 {
			return ""
		}
		credParts := strings.SplitN(parts[1], "/", 2)
		return credParts[0]
	}
	// AWS ACCESS_KEY:signature
	if strings.HasPrefix(auth, "AWS ") {
		parts := strings.SplitN(auth[4:], ":", 2)
		return parts[0]
	}
	return ""
}

// checkAccess evaluates bucket policy for the current request.
// Returns true if access is allowed, false if denied.
func (h *Handler) checkAccess(r *http.Request, bucketName, action, key string) bool {
	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		return true // bucket doesn't exist yet, allow
	}

	if bucket.Policy == "" {
		return true // no policy, allow all (mock behavior)
	}

	accessKey := extractAccessKey(r)
	isOwner := (accessKey == bucket.OwnerAccessKey)

	// Build resource ARN
	var resource string
	if key != "" {
		resource = fmt.Sprintf("arn:aws:s3:::%s/%s", bucketName, key)
	} else {
		resource = fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	}

	ctx := backend.PolicyEvalContext{
		Action:   action,
		Resource: resource,
		Headers:  extractPolicyHeaders(r),
	}

	effect := backend.EvaluateBucketPolicyAccess(bucket.Policy, ctx)

	// Explicit Deny overrides everything, even for owner
	if effect == backend.PolicyEffectDeny {
		return false
	}

	// Owner is always allowed (unless explicitly denied)
	if isOwner {
		return true
	}

	// Non-owner needs explicit Allow
	return effect == backend.PolicyEffectAllow
}

// checkAccessWithContext evaluates bucket policy with additional context (tags, etc.).
func (h *Handler) checkAccessWithContext(
	r *http.Request,
	bucketName, action, key string,
	ctx backend.PolicyEvalContext,
) bool {
	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		return true
	}

	if bucket.Policy == "" {
		return true
	}

	accessKey := extractAccessKey(r)
	isOwner := (accessKey == bucket.OwnerAccessKey)

	// Build resource ARN if not already set
	if ctx.Resource == "" {
		if key != "" {
			ctx.Resource = fmt.Sprintf("arn:aws:s3:::%s/%s", bucketName, key)
		} else {
			ctx.Resource = fmt.Sprintf("arn:aws:s3:::%s", bucketName)
		}
	}

	if ctx.Action == "" {
		ctx.Action = action
	}

	if ctx.Headers == nil {
		ctx.Headers = extractPolicyHeaders(r)
	}

	effect := backend.EvaluateBucketPolicyAccess(bucket.Policy, ctx)

	if effect == backend.PolicyEffectDeny {
		return false
	}

	if isOwner {
		return true
	}

	return effect == backend.PolicyEffectAllow
}

// extractPolicyHeaders extracts relevant headers for policy evaluation.
func extractPolicyHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for _, h := range []string{
		"x-amz-server-side-encryption",
		"x-amz-server-side-encryption-aws-kms-key-id",
		"x-amz-server-side-encryption-customer-algorithm",
		"x-amz-acl",
		"x-amz-copy-source",
		"x-amz-metadata-directive",
		"x-amz-grant-full-control",
		"x-amz-grant-read",
		"x-amz-grant-write",
		"x-amz-grant-read-acp",
		"x-amz-grant-write-acp",
	} {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	// Also capture Referer for aws:Referer conditions
	if v := r.Header.Get("Referer"); v != "" {
		headers["referer"] = v
	}
	return headers
}

// extractBucketAndKey parses the path into bucket and key components.
func extractBucketAndKey(path string) (string, string) {
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}
