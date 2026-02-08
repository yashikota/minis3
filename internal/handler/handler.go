package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	backend *backend.Backend

	lifecycleMu        sync.Mutex
	lastLifecycleApply time.Time
}

var (
	lifecycleIntervalOnce  sync.Once
	lifecycleIntervalValue time.Duration

	verifyPresignedURLFn         = verifyPresignedURL
	verifyAuthorizationHeaderFn  = verifyAuthorizationHeader
	getBucketACLForAccessCheckFn = func(
		h *Handler,
		bucketName string,
	) (*backend.AccessControlPolicy, error) {
		return h.backend.GetBucketACL(bucketName)
	}
	getObjectACLForAccessCheckFn = func(
		h *Handler,
		bucketName, key, versionID string,
	) (*backend.AccessControlPolicy, error) {
		return h.backend.GetObjectACL(bucketName, key, versionID)
	}
)

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
	h.applyLifecycleIfDue(time.Now().UTC())

	if r.Method == http.MethodOptions {
		origin := r.Header.Get("Origin")
		requestMethod := r.Header.Get("Access-Control-Request-Method")
		requestHeaders := r.Header.Get("Access-Control-Request-Headers")
		if origin == "" || requestMethod == "" {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Invalid CORS preflight request",
			)
			return
		}
		pathValue := r.URL.Path
		if pathValue == "/" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		bucketName, _ := extractBucketAndKey(pathValue)
		if h.setCORSHeadersForRequest(
			w,
			bucketName,
			origin,
			requestMethod,
			requestHeaders,
		) {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	// Verify presigned URL if applicable
	if isPresignedURL(r) {
		if err := verifyPresignedURLFn(r); err != nil {
			if pe, ok := err.(*presignedError); ok {
				backend.WriteError(w, http.StatusForbidden, pe.code, pe.message)
			} else {
				backend.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error())
			}
			return
		}
	}
	if err := verifyAuthorizationHeaderFn(r); err != nil {
		if pe, ok := err.(*presignedError); ok {
			backend.WriteError(w, http.StatusForbidden, pe.code, pe.message)
		} else {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", err.Error())
		}
		return
	}

	path := r.URL.Path
	if path == "/" {
		h.handleService(w, r)
		return
	}

	bucketName, key := extractBucketAndKey(path)
	if origin := r.Header.Get("Origin"); origin != "" {
		corsMethod := r.Header.Get("Access-Control-Request-Method")
		if corsMethod == "" {
			corsMethod = r.Method
		}
		h.setCORSHeadersForRequest(w, bucketName, origin, corsMethod, "")
	}
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

func (h *Handler) applyLifecycleIfDue(now time.Time) {
	interval := lifecycleDebugInterval()

	h.lifecycleMu.Lock()
	if !h.lastLifecycleApply.IsZero() && now.Sub(h.lastLifecycleApply) < interval {
		h.lifecycleMu.Unlock()
		return
	}
	h.lastLifecycleApply = now
	h.lifecycleMu.Unlock()

	h.backend.ApplyLifecycle(now, interval)
}

func lifecycleDebugInterval() time.Duration {
	lifecycleIntervalOnce.Do(func() {
		const defaultSeconds = 10
		seconds := defaultSeconds
		if raw := strings.TrimSpace(os.Getenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				seconds = parsed
			}
		}
		lifecycleIntervalValue = time.Duration(seconds) * time.Second
	})
	return lifecycleIntervalValue
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

	accessKey := extractAccessKey(r)
	isAnonymous := isAnonymousRequest(r)
	isOwner := accessKey == bucket.OwnerAccessKey
	requesterCanonicalID := ""
	if !isAnonymous {
		requesterCanonicalID = backend.OwnerForAccessKey(accessKey).ID
	}

	// Build resource ARN
	var resource string
	if key != "" {
		resource = fmt.Sprintf("arn:aws:s3:::%s/%s", bucketName, key)
	} else {
		resource = fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	}

	ctx := backend.PolicyEvalContext{
		Action:      action,
		Resource:    resource,
		Headers:     extractPolicyHeaders(r),
		AccessKey:   accessKey,
		IsAnonymous: isAnonymous,
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

	publicBlock := h.getBucketPublicAccessBlock(bucketName)
	ignorePublicACLs := publicBlock != nil && publicBlock.IgnorePublicAcls
	restrictPublicBuckets := publicBlock != nil && publicBlock.RestrictPublicBuckets
	hasPublicPolicy := backend.IsPolicyPublic(bucket.Policy)

	// RestrictPublicBuckets blocks non-owner access granted by public policy.
	if restrictPublicBuckets && hasPublicPolicy {
		return false
	}

	// Non-owner can be allowed by explicit policy allow.
	if effect == backend.PolicyEffectAllow {
		return true
	}

	// ACL-based fallback when no explicit policy allow.
	if ignorePublicACLs {
		return false
	}

	switch action {
	case "s3:ListBucket", "s3:ListBucketVersions":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		return aclAllowsRead(acl, requesterCanonicalID, isAnonymous)
	case "s3:PutObject":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		return aclAllowsWrite(acl, requesterCanonicalID, isAnonymous)
	case "s3:GetBucketAcl":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutBucketAcl":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionWriteACP)
	case "s3:GetObjectAcl":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err != nil {
			return false
		}
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutObjectAcl":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err != nil {
			return false
		}
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionWriteACP)
	case "s3:GetObject", "s3:GetObjectVersion":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err == nil {
			return aclAllowsRead(acl, requesterCanonicalID, isAnonymous)
		}
		// Missing objects (including latest delete marker) should be authorized
		// by bucket read ACL so the caller gets 404 instead of 403.
		if errors.Is(err, backend.ErrObjectNotFound) || errors.Is(err, backend.ErrVersionNotFound) {
			bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
			if bucketErr != nil {
				return false
			}
			return aclAllowsRead(bucketACL, requesterCanonicalID, isAnonymous)
		}
		return false
	default:
		return false
	}
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

	accessKey := extractAccessKey(r)
	isOwner := accessKey == bucket.OwnerAccessKey

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
	if ctx.AccessKey == "" {
		ctx.AccessKey = accessKey
	}
	ctx.IsAnonymous = isAnonymousRequest(r)

	effect := backend.EvaluateBucketPolicyAccess(bucket.Policy, ctx)

	if effect == backend.PolicyEffectDeny {
		return false
	}

	if isOwner {
		return true
	}

	if effect == backend.PolicyEffectAllow {
		return true
	}

	return h.checkAccess(r, bucketName, action, key)
}

func (h *Handler) getBucketPublicAccessBlock(
	bucketName string,
) *backend.PublicAccessBlockConfiguration {
	config, err := h.backend.GetPublicAccessBlock(bucketName)
	if err != nil {
		return nil
	}
	return config
}

func requesterOwner(r *http.Request) *backend.Owner {
	return backend.OwnerForAccessKey(extractAccessKey(r))
}

func (h *Handler) bucketOwner(bucketName string) *backend.Owner {
	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		return backend.DefaultOwner()
	}
	return backend.OwnerForAccessKey(bucket.OwnerAccessKey)
}

func isPublicACL(acl *backend.AccessControlPolicy) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Grantee.URI != backend.AllUsersURI &&
			grant.Grantee.URI != backend.AuthenticatedUsersURI {
			continue
		}
		switch grant.Permission {
		case backend.PermissionRead, backend.PermissionWrite, backend.PermissionFullControl:
			return true
		}
	}
	return false
}

func effectiveACLForResponse(
	acl *backend.AccessControlPolicy,
	ignorePublicACLs bool,
) *backend.AccessControlPolicy {
	if acl == nil || !ignorePublicACLs {
		return acl
	}

	filtered := *acl
	filtered.AccessControlList = backend.AccessControlList{
		Grants: make([]backend.Grant, 0, len(acl.AccessControlList.Grants)),
	}

	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee != nil &&
			(grant.Grantee.URI == backend.AllUsersURI ||
				grant.Grantee.URI == backend.AuthenticatedUsersURI) {
			continue
		}
		filtered.AccessControlList.Grants = append(filtered.AccessControlList.Grants, grant)
	}

	return &filtered
}

func aclAllowsRead(
	acl *backend.AccessControlPolicy,
	requesterCanonicalID string,
	isAnonymous bool,
) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Permission != backend.PermissionRead &&
			grant.Permission != backend.PermissionFullControl {
			continue
		}
		if grant.Grantee.URI == backend.AllUsersURI {
			return true
		}
		if !isAnonymous && grant.Grantee.URI == backend.AuthenticatedUsersURI {
			return true
		}
		if requesterCanonicalID != "" && grant.Grantee.ID == requesterCanonicalID {
			return true
		}
	}
	return false
}

func aclAllowsWrite(
	acl *backend.AccessControlPolicy,
	requesterCanonicalID string,
	isAnonymous bool,
) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Permission != backend.PermissionWrite &&
			grant.Permission != backend.PermissionFullControl {
			continue
		}
		if grant.Grantee.URI == backend.AllUsersURI {
			return true
		}
		if !isAnonymous && grant.Grantee.URI == backend.AuthenticatedUsersURI {
			return true
		}
		if requesterCanonicalID != "" && grant.Grantee.ID == requesterCanonicalID {
			return true
		}
	}
	return false
}

func aclAllowsACP(
	acl *backend.AccessControlPolicy,
	requesterCanonicalID string,
	isAnonymous bool,
	permission string,
) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee == nil {
			continue
		}
		if grant.Permission != permission && grant.Permission != backend.PermissionFullControl {
			continue
		}
		if grant.Grantee.URI == backend.AllUsersURI {
			return true
		}
		if !isAnonymous && grant.Grantee.URI == backend.AuthenticatedUsersURI {
			return true
		}
		if requesterCanonicalID != "" && grant.Grantee.ID == requesterCanonicalID {
			return true
		}
	}
	return false
}

type aclValidationError struct {
	code    string
	message string
}

func normalizeAndValidateACL(acl *backend.AccessControlPolicy) *aclValidationError {
	if acl == nil {
		return nil
	}
	if acl.Owner != nil && acl.Owner.ID != "" {
		owner := backend.OwnerForCanonicalID(acl.Owner.ID)
		if owner == nil {
			return &aclValidationError{code: "InvalidArgument", message: "Invalid argument"}
		}
		if acl.Owner.DisplayName == "" {
			acl.Owner.DisplayName = owner.DisplayName
		}
	}

	for i := range acl.AccessControlList.Grants {
		grantee := acl.AccessControlList.Grants[i].Grantee
		if grantee == nil {
			continue
		}

		isEmailGrantee := grantee.Type == "AmazonCustomerByEmail" ||
			(grantee.Type == "" && grantee.EmailAddress != "")
		if isEmailGrantee {
			owner := backend.OwnerForEmail(grantee.EmailAddress)
			if owner == nil {
				return &aclValidationError{
					code:    "UnresolvableGrantByEmailAddress",
					message: "The e-mail address you provided does not match any account on record.",
				}
			}
			grantee.Type = "CanonicalUser"
			grantee.ID = owner.ID
			grantee.DisplayName = owner.DisplayName
			grantee.EmailAddress = ""
		}

		isCanonicalGrantee := grantee.Type == "CanonicalUser" ||
			(grantee.Type == "" && grantee.ID != "")
		if isCanonicalGrantee {
			if grantee.ID == "" {
				return &aclValidationError{code: "InvalidArgument", message: "Invalid argument"}
			}
			owner := backend.OwnerForCanonicalID(grantee.ID)
			if owner == nil {
				return &aclValidationError{code: "InvalidArgument", message: "Invalid argument"}
			}
			grantee.Type = "CanonicalUser"
			if grantee.DisplayName == "" {
				grantee.DisplayName = owner.DisplayName
			}
		}
	}
	return nil
}

func aclFromGrantHeaders(
	r *http.Request,
	owner *backend.Owner,
) (*backend.AccessControlPolicy, *aclValidationError) {
	headerPermissions := []struct {
		header     string
		permission string
	}{
		{header: "x-amz-grant-read", permission: backend.PermissionRead},
		{header: "x-amz-grant-write", permission: backend.PermissionWrite},
		{header: "x-amz-grant-read-acp", permission: backend.PermissionReadACP},
		{header: "x-amz-grant-write-acp", permission: backend.PermissionWriteACP},
		{header: "x-amz-grant-full-control", permission: backend.PermissionFullControl},
	}

	grants := make([]backend.Grant, 0)
	for _, hp := range headerPermissions {
		raw := r.Header.Get(hp.header)
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				return nil, &aclValidationError{
					code:    "InvalidArgument",
					message: "Invalid argument",
				}
			}
			grantKey := strings.ToLower(strings.TrimSpace(kv[0]))
			grantValue := strings.Trim(strings.TrimSpace(kv[1]), "\"")
			if grantValue == "" {
				return nil, &aclValidationError{
					code:    "InvalidArgument",
					message: "Invalid argument",
				}
			}
			grant := backend.Grant{
				Grantee:    &backend.Grantee{},
				Permission: hp.permission,
			}
			switch grantKey {
			case "id":
				grant.Grantee.Type = "CanonicalUser"
				grant.Grantee.ID = grantValue
			case "uri":
				grant.Grantee.Type = "Group"
				grant.Grantee.URI = grantValue
			case "emailaddress":
				grant.Grantee.Type = "AmazonCustomerByEmail"
				grant.Grantee.EmailAddress = grantValue
			default:
				return nil, &aclValidationError{
					code:    "InvalidArgument",
					message: "Invalid argument",
				}
			}
			grants = append(grants, grant)
		}
	}

	if len(grants) == 0 {
		return nil, nil
	}

	acl := &backend.AccessControlPolicy{
		Owner: owner,
		AccessControlList: backend.AccessControlList{
			Grants: grants,
		},
	}
	if err := normalizeAndValidateACL(acl); err != nil {
		return nil, err
	}
	return acl, nil
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

func (h *Handler) setCORSHeadersForRequest(
	w http.ResponseWriter,
	bucketName, origin, method, requestHeaders string,
) bool {
	if bucketName == "" || origin == "" || method == "" {
		return false
	}
	config, err := h.backend.GetBucketCORS(bucketName)
	if err != nil || config == nil {
		return false
	}

	requestMethod := strings.ToUpper(strings.TrimSpace(method))
	for _, rule := range config.CORSRules {
		methodMatch := false
		for _, allowedMethod := range rule.AllowedMethods {
			if strings.EqualFold(allowedMethod, requestMethod) {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			continue
		}
		originMatch := false
		matchedOrigin := ""
		for _, allowedOrigin := range rule.AllowedOrigins {
			if corsOriginMatch(allowedOrigin, origin) {
				originMatch = true
				matchedOrigin = allowedOrigin
				break
			}
		}
		if !originMatch {
			continue
		}
		if !corsRequestHeadersAllowed(requestHeaders, rule.AllowedHeaders) {
			continue
		}
		allowOrigin := origin
		if matchedOrigin == "*" {
			allowOrigin = "*"
		}
		w.Header().Set("access-control-allow-origin", allowOrigin)
		w.Header().Set("access-control-allow-methods", requestMethod)
		return true
	}
	return false
}

func corsOriginMatch(pattern, origin string) bool {
	if pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, origin)
	return err == nil && matched
}

func corsRequestHeadersAllowed(requestHeaders string, allowedHeaders []string) bool {
	requested := parseCORSRequestHeaders(requestHeaders)
	if len(requested) == 0 {
		return true
	}
	if len(allowedHeaders) == 0 {
		return false
	}
	for _, header := range requested {
		allowed := false
		for _, pattern := range allowedHeaders {
			if corsHeaderMatch(pattern, header) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func parseCORSRequestHeaders(value string) []string {
	var headers []string
	for _, part := range strings.Split(value, ",") {
		header := strings.ToLower(strings.TrimSpace(part))
		if header != "" {
			headers = append(headers, header)
		}
	}
	return headers
}

func corsHeaderMatch(pattern, header string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	header = strings.ToLower(strings.TrimSpace(header))
	if pattern == "" || header == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	matched, err := path.Match(pattern, header)
	return err == nil && matched
}
