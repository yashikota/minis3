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

var errLogFlushAccessDenied = errors.New("bucket logging access denied")

type requestContextKey string

const deleteLogKeysContextKey requestContextKey = "deleteLogKeys"

type serverAccessLogEntry struct {
	SourceBucket  string
	SourceAccount string
	Line          string
}

type serverAccessLogBatch struct {
	TargetBucket     string
	TargetPrefix     string
	LoggingType      string
	RollInterval     time.Duration
	RecordsBatchSize int
	Filter           *backend.LoggingFilter
	ObjectKeyFormat  *backend.TargetObjectKeyFormat
	FirstEventAt     time.Time
	Entries          []serverAccessLogEntry
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
	getObjectVersionForLoggingFn = func(
		h *Handler,
		bucketName, key, versionID string,
	) (*backend.Object, error) {
		return h.backend.GetObjectVersion(bucketName, key, versionID)
	}
)

// New creates a new Handler with the given backend.
func New(b *backend.Backend) *Handler {
	// Wire up credential lookup to include dynamic IAM credentials.
	credentialLookupFn = func(accessKey string) (string, bool) {
		if secret, ok := DefaultCredentials()[accessKey]; ok {
			return secret, true
		}
		return b.LookupCredential(accessKey)
	}

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
		accessKey := extractAccessKey(r)
		bucketName = normalizeBucketNameForRequestAccessKey(bucketName, accessKey)
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

	// Admin endpoints (no S3 auth required)
	if strings.HasPrefix(r.URL.Path, "/_minis3/") {
		h.handleAdmin(w, r)
		return
	}

	// Health endpoint (no S3 auth required)
	if r.URL.Path == "/health" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("ok\n"))
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

// handleAdmin handles non-S3 admin endpoints for test server management.
func (h *Handler) handleAdmin(w http.ResponseWriter, r *http.Request) {
	const bucketPrefix = "/_minis3/buckets/"
	if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, bucketPrefix) {
		name := strings.TrimPrefix(r.URL.Path, bucketPrefix)
		if name == "" {
			http.NotFound(w, r)
			return
		}
		if err := h.backend.ForceDeleteBucket(name); err != nil {
			backend.WriteError(w, http.StatusNotFound, "NoSuchBucket",
				"The specified bucket does not exist.")
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.NotFound(w, r)
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
	if bucketName == "" {
		return bucketName
	}
	// Path-style tenant override for accessing global buckets from tenant-scoped clients.
	// e.g. ":bucket" should resolve to "bucket".
	if strings.HasPrefix(bucketName, ":") {
		return strings.TrimPrefix(bucketName, ":")
	}
	if strings.Contains(bucketName, ":") {
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

func queryHasInsensitive(r *http.Request, key string) bool {
	if r == nil {
		return false
	}
	for k := range r.URL.Query() {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}

func queryValueInsensitive(r *http.Request, key string) string {
	if r == nil {
		return ""
	}
	for k, values := range r.URL.Query() {
		if !strings.EqualFold(k, key) || len(values) == 0 {
			continue
		}
		return values[0]
	}
	return ""
}

func normalizeLoggingType(loggingType string) string {
	if strings.EqualFold(loggingType, backend.BucketLoggingTypeJournal) {
		return backend.BucketLoggingTypeJournal
	}
	return backend.BucketLoggingTypeStandard
}

func loggingRollInterval(logging *backend.LoggingEnabled) time.Duration {
	if logging == nil || logging.ObjectRollTime <= 0 {
		return serverAccessLogRollInterval
	}
	return time.Duration(logging.ObjectRollTime) * time.Second
}

func loggingFilterSignature(filter *backend.LoggingFilter) string {
	if filter == nil || filter.Key == nil || len(filter.Key.FilterRules) == 0 {
		return "nofilter"
	}
	var b strings.Builder
	for _, rule := range filter.Key.FilterRules {
		if b.Len() > 0 {
			b.WriteByte('|')
		}
		b.WriteString(strings.ToLower(strings.TrimSpace(rule.Name)))
		b.WriteByte('=')
		b.WriteString(rule.Value)
	}
	return b.String()
}

func matchesLoggingFilter(key string, filter *backend.LoggingFilter) bool {
	if key == "-" || filter == nil || filter.Key == nil {
		return true
	}
	for _, rule := range filter.Key.FilterRules {
		name := strings.ToLower(strings.TrimSpace(rule.Name))
		switch name {
		case "prefix":
			if !strings.HasPrefix(key, rule.Value) {
				return false
			}
		case "suffix":
			if !strings.HasSuffix(key, rule.Value) {
				return false
			}
		}
	}
	return true
}

func shouldLogJournalOperation(op string) bool {
	switch op {
	case "REST.PUT.ACL",
		"REST.PUT.LEGAL_HOLD",
		"REST.PUT.RETENTION",
		"REST.PUT.OBJECT_TAGGING",
		"REST.DELETE.OBJECT_TAGGING":
		return true
	}
	return strings.Contains(op, ".OBJECT")
}

func (h *Handler) loggingJournalMetadata(
	bucketName, key string,
	r *http.Request,
) (string, string, string) {
	versionID := queryValueInsensitive(r, "versionId")
	obj, err := getObjectVersionForLoggingFn(h, bucketName, key, versionID)
	if err != nil && versionID != "" {
		obj, err = getObjectVersionForLoggingFn(h, bucketName, key, "")
	}
	if err != nil || obj == nil {
		return "-", "-", "-"
	}
	size := strconv.FormatInt(obj.Size, 10)
	etag := obj.ETag
	if etag == "" {
		etag = "-"
	}
	if obj.VersionId == "" || obj.VersionId == "null" {
		return size, "-", etag
	}
	return size, obj.VersionId, etag
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
	loggingType := normalizeLoggingType(logging.LoggingEnabled.LoggingType)
	now := time.Now().UTC()

	bucketOwnerID := "-"
	if owner := backend.OwnerForAccessKey(sourceBucket.OwnerAccessKey); owner != nil &&
		owner.ID != "" {
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
	if loggingType == backend.BucketLoggingTypeJournal && !shouldLogJournalOperation(op) {
		return
	}
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
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") ||
		queryHasInsensitive(r, "X-Amz-Signature") {
		sigVersion = "SigV4"
	} else if strings.HasPrefix(r.Header.Get("Authorization"), "AWS ") ||
		queryHasInsensitive(r, "Signature") {
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
	if r.Method == http.MethodPost && queryHasInsensitive(r, "delete") {
		if deleteKeys, ok := r.Context().Value(deleteLogKeysContextKey).([]string); ok &&
			len(deleteKeys) > 0 {
			keysToLog = deleteKeys
		}
	}
	if loggingType == backend.BucketLoggingTypeJournal {
		filtered := make([]string, 0, len(keysToLog))
		for _, loggedKey := range keysToLog {
			if matchesLoggingFilter(loggedKey, logging.LoggingEnabled.Filter) {
				filtered = append(filtered, loggedKey)
			}
		}
		if len(filtered) == 0 {
			return
		}
		keysToLog = filtered
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
	batchKey := strings.Join(
		[]string{
			targetBucket,
			prefix,
			formatKey,
			loggingType,
			strconv.Itoa(int(loggingRollInterval(logging.LoggingEnabled) / time.Second)),
			strconv.Itoa(logging.LoggingEnabled.RecordsBatchSize),
			loggingFilterSignature(logging.LoggingEnabled.Filter),
		},
		"|",
	)

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()
	batch, ok := h.pendingLogBatches[batchKey]
	if !ok {
		batch = &serverAccessLogBatch{
			TargetBucket:     targetBucket,
			TargetPrefix:     prefix,
			LoggingType:      loggingType,
			RollInterval:     loggingRollInterval(logging.LoggingEnabled),
			RecordsBatchSize: logging.LoggingEnabled.RecordsBatchSize,
			Filter:           logging.LoggingEnabled.Filter,
			ObjectKeyFormat:  objectKeyFormat,
			FirstEventAt:     now,
		}
		h.pendingLogBatches[batchKey] = batch
	}
	sourceAccount := sourceAccountIDForLogging(sourceBucket.OwnerAccessKey)
	for _, loggedKey := range keysToLog {
		logLine := ""
		if loggingType == backend.BucketLoggingTypeJournal {
			journalSize, journalVersionID, journalETag := h.loggingJournalMetadata(
				bucketName,
				loggedKey,
				r,
			)
			logLine = fmt.Sprintf(
				"%s %s [%s] %s %s %s %s %s",
				bucketOwnerID,
				recordBucketName,
				now.Format("02/Jan/2006:15:04:05 +0000"),
				op,
				loggedKey,
				journalSize,
				journalVersionID,
				journalETag,
			)
		} else {
			logLine = fmt.Sprintf(
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
		}
		batch.Entries = append(batch.Entries, serverAccessLogEntry{
			SourceBucket:  bucketName,
			SourceAccount: sourceAccount,
			Line:          logLine,
		})
	}
}

func (h *Handler) flushServerAccessLogsIfDue(sourceBucketName string) error {
	now := time.Now().UTC()

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()

	for key, batch := range h.pendingLogBatches {
		interval := batch.RollInterval
		if interval <= 0 {
			interval = serverAccessLogRollInterval
		}
		if now.Sub(batch.FirstEventAt) < interval {
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
		if _, err := h.flushServerAccessLogBatch(batch, now); err != nil {
			return err
		}
		delete(h.pendingLogBatches, key)
	}
	return nil
}

func (h *Handler) flushServerAccessLogBatch(
	batch *serverAccessLogBatch,
	now time.Time,
) (string, error) {
	if batch == nil || len(batch.Entries) == 0 {
		return "", nil
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
		sourceAccount := entry.SourceAccount
		if sourceAccount == "" {
			if sourceBucket, ok := h.backend.GetBucket(entry.SourceBucket); ok {
				sourceAccount = sourceAccountIDForLogging(sourceBucket.OwnerAccessKey)
			}
		}
		allowed, denyCode := h.bucketLoggingTargetPolicyAllowed(
			entry.SourceBucket,
			sourceAccount,
			batch.TargetBucket,
			batch.TargetPrefix,
		)
		if !allowed {
			if denyCode == "NoSuchKey" || denyCode == "NoSuchBucket" {
				return "", nil
			}
			return "", errLogFlushAccessDenied
		}
	}

	sourceBucketName := batch.Entries[0].SourceBucket
	sourceAccount := batch.Entries[0].SourceAccount
	if sourceAccount == "" {
		if sourceBucket, ok := h.backend.GetBucket(sourceBucketName); ok {
			sourceAccount = sourceAccountIDForLogging(sourceBucket.OwnerAccessKey)
		}
	}

	suffix := fmt.Sprintf(
		"%s-%019d-%s",
		now.Format("2006-01-02-15-04-05"),
		now.UnixNano(),
		generateRequestId(),
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
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			return "", nil
		}
		return "", err
	}
	return logKey, nil
}

// forceFlushServerAccessLogs flushes all pending log batches for the given
// source bucket unconditionally (ignoring the roll interval).
func (h *Handler) forceFlushServerAccessLogs(sourceBucketName string) (string, error) {
	now := time.Now().UTC()

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()

	var flushedKey string
	for key, batch := range h.pendingLogBatches {
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
		logKey, err := h.flushServerAccessLogBatch(batch, now)
		if err != nil {
			return "", err
		}
		if logKey != "" {
			flushedKey = logKey
		}
		delete(h.pendingLogBatches, key)
	}
	return flushedKey, nil
}

func mapRequestToLoggingOperation(r *http.Request, key string) string {
	if key == "" {
		switch {
		case r.Method == http.MethodPut && queryHasInsensitive(r, "logging"):
			return "REST.PUT.BUCKET_LOGGING"
		case r.Method == http.MethodGet && queryHasInsensitive(r, "logging"):
			return "REST.GET.BUCKET_LOGGING"
		case r.Method == http.MethodPost && queryHasInsensitive(r, "delete"):
			return "REST.POST.DELETE_MULTI_OBJECT"
		case r.Method == http.MethodDelete:
			return "REST.DELETE.BUCKET"
		case r.Method == http.MethodPut:
			return "REST.PUT.BUCKET"
		case r.Method == http.MethodGet:
			return "REST.GET.BUCKET"
		default:
			return "REST.BUCKET"
		}
	}
	switch {
	case r.Method == http.MethodPut && queryHasInsensitive(r, "uploadId"):
		return "REST.PUT.PART"
	case r.Method == http.MethodPost && queryHasInsensitive(r, "uploadId"):
		return "REST.POST.UPLOAD"
	case r.Method == http.MethodPost && queryHasInsensitive(r, "uploads"):
		return "REST.POST.UPLOADS"
	case r.Method == http.MethodPost && queryHasInsensitive(r, "restore"):
		return "REST.POST.OBJECT_RESTORE"
	case r.Method == http.MethodPost && queryHasInsensitive(r, "delete"):
		return "REST.POST.DELETE_MULTI_OBJECT"
	case r.Method == http.MethodPut && queryHasInsensitive(r, "acl"):
		return "REST.PUT.ACL"
	case r.Method == http.MethodPut && queryHasInsensitive(r, "tagging"):
		return "REST.PUT.OBJECT_TAGGING"
	case r.Method == http.MethodDelete && queryHasInsensitive(r, "tagging"):
		return "REST.DELETE.OBJECT_TAGGING"
	case r.Method == http.MethodPut && queryHasInsensitive(r, "legal-hold"):
		return "REST.PUT.LEGAL_HOLD"
	case r.Method == http.MethodPut && queryHasInsensitive(r, "retention"):
		return "REST.PUT.RETENTION"
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
	if isPresignedURL(r) || queryHasInsensitive(r, "X-Amz-Credential") ||
		(queryHasInsensitive(r, "AWSAccessKeyId") && queryHasInsensitive(r, "Signature")) {
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
		resource = fmt.Sprintf("arn:aws:s3:::%s/%s", displayBucketName(bucketName), key)
	} else {
		resource = fmt.Sprintf("arn:aws:s3:::%s", displayBucketName(bucketName))
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
	ownerImplicit := bucket.OwnerAccessKey == "" && isAnonymous
	requesterCanonicalID := ""
	if !isAnonymous {
		requesterCanonicalID = backend.OwnerForAccessKey(accessKey).ID
	}

	resource := policyResourceARN(bucketName, key)

	ctx := backend.PolicyEvalContext{
		Action:      action,
		Resource:    resource,
		Headers:     extractPolicyHeaders(r),
		AccessKey:   accessKey,
		IsAnonymous: isAnonymous,
	}

	effect := backend.EvaluateBucketPolicyAccess(bucket.Policy, ctx)

	// Explicit Deny overrides everything, even for owner —
	// UNLESS the owner is managing bucket policy operations and the policy
	// was NOT set with ConfirmRemoveSelfBucketAccess.
	if effect == backend.PolicyEffectDeny {
		if isOwner && !bucket.PolicyDenySelfAccess && isBucketPolicyAction(action) {
			// Owner exempt from deny for bucket policy management
		} else {
			return false
		}
	}

	publicBlock := h.getBucketPublicAccessBlock(bucketName)
	ignorePublicACLs := publicBlock != nil && publicBlock.IgnorePublicAcls
	restrictPublicBuckets := publicBlock != nil && publicBlock.RestrictPublicBuckets
	hasPublicPolicy := backend.IsPolicyPublic(bucket.Policy)

	// RestrictPublicBuckets blocks non-owner access granted by public policy.
	if restrictPublicBuckets && hasPublicPolicy && !isOwner && !ownerImplicit {
		return false
	}

	// Non-owner can be allowed by explicit policy allow.
	if effect == backend.PolicyEffectAllow {
		return true
	}
	// Bucket owner access is preserved unless explicitly denied.
	if isOwner && (key == "" || ownerImplicit || ownerBypassesObjectACL(action)) {
		return true
	}
	// If there is a matching Allow statement but conditions did not match,
	// the request is denied rather than falling back to ACLs.
	if backend.HasAllowStatementForRequest(bucket.Policy, ctx) {
		return false
	}

	// When ACLs are disabled (BucketOwnerEnforced), only owner/policy can grant access.
	if strings.EqualFold(bucket.ObjectOwnership, backend.ObjectOwnershipBucketOwnerEnforced) {
		return false
	}

	switch action {
	case "s3:ListBucket", "s3:ListBucketVersions":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsRead(acl, requesterCanonicalID, isAnonymous)
	case "s3:PutObject":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsWrite(acl, requesterCanonicalID, isAnonymous)
	case "s3:GetBucketAcl":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutBucketAcl":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionWriteACP)
	case "s3:GetBucketOwnershipControls", "s3:GetBucketLogging", "s3:GetBucketRequestPayment",
		"s3:GetBucketPolicy":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutBucketOwnershipControls",
		"s3:DeleteBucketOwnershipControls",
		"s3:PutBucketLogging",
		"s3:PutBucketRequestPayment",
		"s3:DeleteBucketPolicy":
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionWriteACP)
	case "s3:GetObjectAcl":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err != nil {
			if errors.Is(err, backend.ErrObjectNotFound) ||
				errors.Is(err, backend.ErrVersionNotFound) {
				bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
				if bucketErr != nil {
					return false
				}
				bucketACL = effectiveACLForResponse(bucketACL, ignorePublicACLs)
				return aclAllowsACP(
					bucketACL,
					requesterCanonicalID,
					isAnonymous,
					backend.PermissionReadACP,
				)
			}
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionReadACP)
	case "s3:PutObjectAcl":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err != nil {
			if errors.Is(err, backend.ErrObjectNotFound) ||
				errors.Is(err, backend.ErrVersionNotFound) {
				bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
				if bucketErr != nil {
					return false
				}
				bucketACL = effectiveACLForResponse(bucketACL, ignorePublicACLs)
				return aclAllowsACP(
					bucketACL,
					requesterCanonicalID,
					isAnonymous,
					backend.PermissionWriteACP,
				)
			}
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsACP(acl, requesterCanonicalID, isAnonymous, backend.PermissionWriteACP)
	case "s3:GetObject", "s3:GetObjectVersion":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err == nil {
			acl = effectiveACLForResponse(acl, ignorePublicACLs)
			return aclAllowsRead(acl, requesterCanonicalID, isAnonymous)
		}
		// Missing objects (including latest delete marker) should be authorized
		// by bucket read ACL so the caller gets 404 instead of 403.
		if errors.Is(err, backend.ErrObjectNotFound) || errors.Is(err, backend.ErrVersionNotFound) {
			bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
			if bucketErr != nil {
				return false
			}
			bucketACL = effectiveACLForResponse(bucketACL, ignorePublicACLs)
			return aclAllowsRead(bucketACL, requesterCanonicalID, isAnonymous)
		}
		return false
	case "s3:GetObjectTagging":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err == nil {
			acl = effectiveACLForResponse(acl, ignorePublicACLs)
			return aclAllowsRead(acl, requesterCanonicalID, isAnonymous)
		}
		if errors.Is(err, backend.ErrObjectNotFound) || errors.Is(err, backend.ErrVersionNotFound) {
			bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
			if bucketErr != nil {
				return false
			}
			bucketACL = effectiveACLForResponse(bucketACL, ignorePublicACLs)
			return aclAllowsRead(bucketACL, requesterCanonicalID, isAnonymous)
		}
		return false
	case "s3:RestoreObject":
		if key == "" {
			return false
		}
		acl, err := getBucketACLForAccessCheckFn(h, bucketName)
		if err != nil {
			return false
		}
		acl = effectiveACLForResponse(acl, ignorePublicACLs)
		return aclAllowsWrite(acl, requesterCanonicalID, isAnonymous)
	case "s3:PutObjectTagging",
		"s3:DeleteObjectTagging",
		"s3:DeleteObject",
		"s3:DeleteObjectVersion":
		if key == "" {
			return false
		}
		acl, err := getObjectACLForAccessCheckFn(h, bucketName, key, "")
		if err == nil {
			acl = effectiveACLForResponse(acl, ignorePublicACLs)
			return aclAllowsWrite(acl, requesterCanonicalID, isAnonymous)
		}
		if errors.Is(err, backend.ErrObjectNotFound) || errors.Is(err, backend.ErrVersionNotFound) {
			bucketACL, bucketErr := getBucketACLForAccessCheckFn(h, bucketName)
			if bucketErr != nil {
				return false
			}
			bucketACL = effectiveACLForResponse(bucketACL, ignorePublicACLs)
			return aclAllowsWrite(bucketACL, requesterCanonicalID, isAnonymous)
		}
		return false
	default:
		return false
	}
}

func policyResourceARN(bucketName, key string) string {
	bucketForPolicy := displayBucketName(bucketName)
	if key != "" {
		return fmt.Sprintf("arn:aws:s3:::%s/%s", bucketForPolicy, key)
	}
	return fmt.Sprintf("arn:aws:s3:::%s", bucketForPolicy)
}

func ownerBypassesObjectACL(action string) bool {
	switch action {
	case "s3:GetObjectAcl", "s3:PutObjectAcl":
		return false
	default:
		return true
	}
}

// isBucketPolicyAction returns true for bucket policy management actions.
// The bucket owner is exempt from Deny for these actions unless
// ConfirmRemoveSelfBucketAccess was set.
func isBucketPolicyAction(action string) bool {
	switch action {
	case "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy":
		return true
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
	ownerImplicit := bucket.OwnerAccessKey == "" && isAnonymousRequest(r)

	// Build resource ARN if not already set
	if ctx.Resource == "" {
		ctx.Resource = policyResourceARN(bucketName, key)
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
		if isOwner && !bucket.PolicyDenySelfAccess && isBucketPolicyAction(action) {
			// Owner exempt from deny for bucket policy management
		} else {
			return false
		}
	}

	publicBlock := h.getBucketPublicAccessBlock(bucketName)
	restrictPublicBuckets := publicBlock != nil && publicBlock.RestrictPublicBuckets
	hasPublicPolicy := backend.IsPolicyPublic(bucket.Policy)
	if restrictPublicBuckets && hasPublicPolicy && !isOwner && !ownerImplicit {
		return false
	}

	if effect == backend.PolicyEffectAllow {
		return true
	}
	// Bucket owner access is preserved unless explicitly denied.
	if isOwner && (key == "" || ownerImplicit || ownerBypassesObjectACL(action)) {
		return true
	}
	if backend.HasAllowStatementForRequest(bucket.Policy, ctx) {
		return false
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
	// Object and bucket owners retain ACP privileges even when explicit
	// owner grants are omitted from the ACL.
	if !isAnonymous &&
		requesterCanonicalID != "" &&
		acl.Owner != nil &&
		acl.Owner.ID == requesterCanonicalID {
		return true
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
	if owner == nil {
		owner = backend.DefaultOwner()
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
		"x-amz-tagging",
		"x-amz-tagging-directive",
		"x-amz-grant-full-control",
		"x-amz-grant-read",
		"x-amz-grant-write",
		"x-amz-grant-read-acp",
		"x-amz-grant-write-acp",
	} {
		if v := headerValueAnyCase(r.Header, h); v != "" {
			headers[h] = v
		}
	}
	// Also capture Referer for aws:Referer conditions
	if v := headerValueAnyCase(r.Header, "Referer"); v != "" {
		headers["referer"] = v
	}
	return headers
}

func headerValueAnyCase(hdr http.Header, name string) string {
	if v := hdr.Get(name); v != "" {
		return v
	}
	for k, values := range hdr {
		if !strings.EqualFold(k, name) || len(values) == 0 {
			continue
		}
		return values[0]
	}
	return ""
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
