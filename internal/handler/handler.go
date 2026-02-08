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

	loggingMu         sync.Mutex
	pendingLogBatches map[string]*serverAccessLogBatch
}

const serverAccessLogRollInterval = 5 * time.Second

type requestContextKey string

const deleteLogKeysContextKey requestContextKey = "deleteLogKeys"

type serverAccessLogEntry struct {
	SourceBucket string
	Line         string
}

type serverAccessLogBatch struct {
	TargetBucket    string
	TargetPrefix    string
	ObjectKeyFormat *backend.TargetObjectKeyFormat
	FirstEventAt    time.Time
	Entries         []serverAccessLogEntry
}

type recordingResponseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (rw *recordingResponseWriter) WriteHeader(statusCode int) {
	rw.status = statusCode
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *recordingResponseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

var (
	lifecycleIntervalOnce  sync.Once
	lifecycleIntervalValue time.Duration

	verifyPresignedURLFn        = verifyPresignedURL
	verifyAuthorizationHeaderFn = verifyAuthorizationHeader
	ownerForAccessKeyFn         = backend.OwnerForAccessKey
	getBucketForLoggingFn       = func(h *Handler, bucketName string) (*backend.Bucket, bool) {
		return h.backend.GetBucket(bucketName)
	}
	requestURIForLoggingFn = func(r *http.Request) string {
		return r.URL.RequestURI()
	}
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
	return &Handler{
		backend:           b,
		pendingLogBatches: make(map[string]*serverAccessLogBatch),
	}
}

// generateRequestId generates a random request ID (16 hex characters).
func generateRequestId() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// ServeHTTP implements http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := generateRequestId()
	hostID := generateRequestId()
	w.Header().Set("x-amz-request-id", requestID)
	w.Header().Set("x-amz-id-2", hostID)
	rw := &recordingResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
	h.handleRequest(rw, r)
	h.emitServerAccessLog(r, rw.status, rw.bytes, requestID, hostID)
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

	accessKey := extractAccessKey(r)
	bucketName, key := extractBucketAndKey(path)
	bucketName = normalizeBucketNameForRequestAccessKey(bucketName, accessKey)
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

func tenantFromAccessKey(accessKey string) string {
	if accessKey == "" {
		return ""
	}
	owner := ownerForAccessKeyFn(accessKey)
	if owner == nil {
		return ""
	}
	if i := strings.Index(owner.ID, "$"); i > 0 {
		return owner.ID[:i]
	}
	return ""
}

func normalizeBucketNameForRequestAccessKey(bucketName, accessKey string) string {
	if bucketName == "" || strings.Contains(bucketName, ":") {
		return bucketName
	}
	tenant := tenantFromAccessKey(accessKey)
	if tenant == "" {
		return bucketName
	}
	return tenant + ":" + bucketName
}

func displayBucketName(bucketName string) string {
	if i := strings.Index(bucketName, ":"); i >= 0 && i+1 < len(bucketName) {
		return bucketName[i+1:]
	}
	return bucketName
}

func defaultLogField(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (h *Handler) emitServerAccessLog(
	r *http.Request,
	statusCode int,
	responseBytes int64,
	requestID, hostID string,
) {
	accessKey := extractAccessKey(r)
	bucketName, key := extractBucketAndKey(r.URL.Path)
	bucketName = normalizeBucketNameForRequestAccessKey(bucketName, accessKey)
	if bucketName == "" {
		return
	}
	logging, err := getBucketLoggingFn(h, bucketName)
	if err != nil || logging == nil || logging.LoggingEnabled == nil {
		return
	}
	sourceBucket, ok := getBucketForLoggingFn(h, bucketName)
	if !ok {
		return
	}
	targetBucket := logging.LoggingEnabled.TargetBucket
	prefix := logging.LoggingEnabled.TargetPrefix
	if targetBucket == "" {
		return
	}
	now := time.Now().UTC()

	bucketOwnerID := "-"
	if owner := backend.OwnerForAccessKey(sourceBucket.OwnerAccessKey); owner != nil && owner.ID != "" {
		bucketOwnerID = owner.ID
	}

	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}
	if remoteAddr == "" {
		remoteAddr = "-"
	}
	requester := accessKey
	if requester == "" {
		requester = "-"
	}
	op := mapRequestToLoggingOperation(r, key)
	requestURI := requestURIForLoggingFn(r)
	if requestURI == "" {
		requestURI = r.URL.Path
	}

	referrer := r.Referer()
	if referrer == "" {
		referrer = "-"
	}
	userAgent := r.UserAgent()
	if userAgent == "" {
		userAgent = "-"
	}
	objectSize := "-"
	if r.ContentLength >= 0 {
		objectSize = strconv.FormatInt(r.ContentLength, 10)
	}
	errorCode := "-"
	if statusCode >= 400 {
		errorCode = "Error"
	}
	sigVersion := "-"
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") || r.URL.Query().Has(
		"X-Amz-Signature",
	) {
		sigVersion = "SigV4"
	} else if strings.HasPrefix(r.Header.Get("Authorization"), "AWS ") || r.URL.Query().Has(
		"Signature",
	) {
		sigVersion = "SigV2"
	}
	authType := loggingAuthType(r)
	aclRequired := h.loggingACLRequired(r, bucketName, key)
	requestLine := fmt.Sprintf("%s %s %s", r.Method, requestURI, r.Proto)
	recordBucketName := displayBucketName(bucketName)
	keysToLog := []string{"-"}
	if key != "" {
		keysToLog = []string{key}
	}
	if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
		if deleteKeys, ok := r.Context().Value(deleteLogKeysContextKey).([]string); ok &&
			len(deleteKeys) > 0 {
			keysToLog = deleteKeys
		}
	}

	objectKeyFormat := logging.LoggingEnabled.TargetObjectKeyFormat
	if objectKeyFormat == nil {
		objectKeyFormat = &backend.TargetObjectKeyFormat{
			SimplePrefix: &backend.SimplePrefix{},
		}
	}
	formatKey := "simple"
	if objectKeyFormat.PartitionedPrefix != nil {
		formatKey = "partitioned:" + objectKeyFormat.PartitionedPrefix.PartitionDateSource
	}
	batchKey := targetBucket + "|" + prefix + "|" + formatKey

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()
	batch, ok := h.pendingLogBatches[batchKey]
	if !ok {
		batch = &serverAccessLogBatch{
			TargetBucket:    targetBucket,
			TargetPrefix:    prefix,
			ObjectKeyFormat: objectKeyFormat,
			FirstEventAt:    now,
		}
		h.pendingLogBatches[batchKey] = batch
	}
	for _, loggedKey := range keysToLog {
		logLine := fmt.Sprintf(
			"%s %s [%s] %s %s %s %s %s \"%s\" %d %s %d %s %s %s \"%s\" \"%s\" %s %s %s %s %s %s %s %s %s",
			bucketOwnerID,
			recordBucketName,
			now.Format("02/Jan/2006:15:04:05 +0000"),
			remoteAddr,
			requester,
			defaultLogField(requestID, "-"),
			op,
			loggedKey,
			requestLine,
			statusCode,
			errorCode,
			responseBytes,
			objectSize,
			"0",
			"0",
			referrer,
			userAgent,
			"-",
			defaultLogField(hostID, "-"),
			sigVersion,
			"-",
			authType,
			defaultLogField(r.Host, "-"),
			"-",
			"-",
			aclRequired,
		)
		batch.Entries = append(batch.Entries, serverAccessLogEntry{
			SourceBucket: bucketName,
			Line:         logLine,
		})
	}
}

func (h *Handler) flushServerAccessLogsIfDue(sourceBucketName string) error {
	now := time.Now().UTC()

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()

	for key, batch := range h.pendingLogBatches {
		if now.Sub(batch.FirstEventAt) < serverAccessLogRollInterval {
			continue
		}
		matchesSource := false
		for _, entry := range batch.Entries {
			if entry.SourceBucket == sourceBucketName {
				matchesSource = true
				break
			}
		}
		if !matchesSource {
			continue
		}
		if err := h.flushServerAccessLogBatch(batch, now); err != nil {
			return err
		}
		delete(h.pendingLogBatches, key)
	}
	return nil
}

func (h *Handler) flushServerAccessLogBatch(batch *serverAccessLogBatch, now time.Time) error {
	if batch == nil || len(batch.Entries) == 0 {
		return nil
	}
	seenSource := make(map[string]struct{})
	for _, entry := range batch.Entries {
		if entry.SourceBucket == "" {
			continue
		}
		if _, exists := seenSource[entry.SourceBucket]; exists {
			continue
		}
		seenSource[entry.SourceBucket] = struct{}{}
		allowed, _ := h.bucketLoggingTargetAllowed(
			entry.SourceBucket,
			batch.TargetBucket,
			batch.TargetPrefix,
		)
		if !allowed {
			return fmt.Errorf("access denied")
		}
	}

	sourceBucketName := batch.Entries[0].SourceBucket
	sourceBucket, ok := h.backend.GetBucket(sourceBucketName)
	if !ok {
		return backend.ErrBucketNotFound
	}
	sourceAccount := ""
	if owner := backend.OwnerForAccessKey(sourceBucket.OwnerAccessKey); owner != nil {
		sourceAccount = owner.ID
	}

	suffix := fmt.Sprintf(
		"%s-%s-%d",
		now.Format("2006-01-02-15-04-05"),
		generateRequestId(),
		now.UnixNano(),
	)
	logKey := batch.TargetPrefix + suffix
	if batch.ObjectKeyFormat != nil && batch.ObjectKeyFormat.PartitionedPrefix != nil {
		logKey = fmt.Sprintf(
			"%s%s/default/%s/%04d/%02d/%02d/%s",
			batch.TargetPrefix,
			sourceAccount,
			displayBucketName(sourceBucketName),
			now.Year(),
			now.Month(),
			now.Day(),
			suffix,
		)
	}

	var body strings.Builder
	for _, entry := range batch.Entries {
		body.WriteString(entry.Line)
		body.WriteByte('\n')
	}
	_, err := h.backend.PutObject(
		batch.TargetBucket,
		logKey,
		[]byte(body.String()),
		backend.PutObjectOptions{
			ContentType: "text/plain",
			Owner:       h.bucketOwner(batch.TargetBucket),
		},
	)
	return err
}

func mapRequestToLoggingOperation(r *http.Request, key string) string {
	if key == "" {
		switch {
		case r.Method == http.MethodPut && r.URL.Query().Has("logging"):
			return "REST.PUT.BUCKET_LOGGING"
		case r.Method == http.MethodGet && r.URL.Query().Has("logging"):
			return "REST.GET.BUCKET_LOGGING"
		case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
			return "REST.POST.DELETE_MULTI_OBJECT"
		case r.Method == http.MethodPut:
			return "REST.PUT.BUCKET"
		case r.Method == http.MethodGet:
			return "REST.GET.BUCKET"
		default:
			return "REST.BUCKET"
		}
	}
	switch {
	case r.Method == http.MethodPut && r.URL.Query().Has("uploadId"):
		return "REST.PUT.PART"
	case r.Method == http.MethodPost && r.URL.Query().Has("uploadId"):
		return "REST.POST.UPLOAD"
	case r.Method == http.MethodPost && r.URL.Query().Has("uploads"):
		return "REST.POST.UPLOADS"
	case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		return "REST.POST.DELETE_MULTI_OBJECT"
	case r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "":
		return "REST.PUT.OBJECT_COPY"
	case r.Method == http.MethodPut:
		return "REST.PUT.OBJECT"
	case r.Method == http.MethodGet:
		return "REST.GET.OBJECT"
	case r.Method == http.MethodHead:
		return "REST.HEAD.OBJECT"
	case r.Method == http.MethodDelete:
		return "REST.DELETE.OBJECT"
	default:
		return "REST.OBJECT"
	}
}

func loggingAuthType(r *http.Request) string {
	if isPresignedURL(r) {
		return "QueryString"
	}
	if r.Header.Get("Authorization") != "" {
		return "AuthHeader"
	}
	return "-"
}

func loggingActionFromRequest(r *http.Request, key string) string {
	if key == "" {
		switch r.Method {
		case http.MethodGet:
			return "s3:ListBucket"
		case http.MethodPut:
			return "s3:PutBucketLogging"
		default:
			return ""
		}
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return "s3:GetObject"
	case http.MethodPut:
		return "s3:PutObject"
	default:
		return ""
	}
}

func (h *Handler) loggingACLRequired(r *http.Request, bucketName, key string) string {
	action := loggingActionFromRequest(r, key)
	if action == "" {
		return "-"
	}
	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		return "-"
	}
	accessKey := extractAccessKey(r)
	isAnonymous := isAnonymousRequest(r)
	if accessKey == bucket.OwnerAccessKey {
		return "-"
	}

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
	if effect == backend.PolicyEffectAllow {
		return "-"
	}
	requesterCanonicalID := ""
	if !isAnonymous {
		requesterCanonicalID = backend.OwnerForAccessKey(accessKey).ID
	}

	switch action {
	case "s3:ListBucket":
		acl, err := h.backend.GetBucketACL(bucketName)
		if err == nil && aclAllowsRead(acl, requesterCanonicalID, isAnonymous) {
			return "Yes"
		}
	case "s3:GetObject":
		acl, err := h.backend.GetObjectACL(bucketName, key, "")
		if err == nil && aclAllowsRead(acl, requesterCanonicalID, isAnonymous) {
			return "Yes"
		}
	}
	return "-"
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

	// When ACLs are disabled (BucketOwnerEnforced), only owner/policy can grant access.
	if strings.EqualFold(bucket.ObjectOwnership, backend.ObjectOwnershipBucketOwnerEnforced) {
		return false
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
	case "s3:GetBucketOwnershipControls", "s3:GetBucketLogging", "s3:GetBucketRequestPayment":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutBucketOwnershipControls", "s3:DeleteBucketOwnershipControls", "s3:PutBucketLogging", "s3:PutBucketRequestPayment":
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
	return ownerForAccessKeyFn(extractAccessKey(r))
}

func (h *Handler) bucketOwner(bucketName string) *backend.Owner {
	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		return backend.DefaultOwner()
	}
	return ownerForAccessKeyFn(bucket.OwnerAccessKey)
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
