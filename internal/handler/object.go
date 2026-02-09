package handler

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/yashikota/minis3/internal/backend"
)

var (
	putObjectFn = func(
		h *Handler,
		bucketName, key string,
		data []byte,
		opts backend.PutObjectOptions,
	) (*backend.Object, error) {
		return h.backend.PutObject(bucketName, key, data, opts)
	}
	putObjectACLFn = func(
		h *Handler,
		bucketName, key, versionID string,
		acl *backend.AccessControlPolicy,
	) error {
		return h.backend.PutObjectACL(bucketName, key, versionID, acl)
	}
	copyObjectFn = func(
		h *Handler,
		srcBucket, srcKey, srcVersionID, dstBucket, dstKey string,
		opts backend.CopyObjectOptions,
	) (*backend.Object, string, error) {
		return h.backend.CopyObject(srcBucket, srcKey, srcVersionID, dstBucket, dstKey, opts)
	}
	getObjectACLFn = func(
		h *Handler,
		bucketName, key, versionID string,
	) (*backend.AccessControlPolicy, error) {
		return h.backend.GetObjectACL(bucketName, key, versionID)
	}
)

// Inverted NVME polynomial value used by Go's crc64 implementation.
const crc64NVME = 0x9a6c9329ac4bc9b5

// extractMetadata extracts x-amz-meta-* headers from the request.
// AWS S3 lowercases all metadata keys, so we do the same for compatibility.
// Non-ASCII values may be URL-encoded by AWS SDK, so we decode them.
func extractMetadata(r *http.Request) map[string]string {
	metadata := make(map[string]string)
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if strings.HasPrefix(lowerKey, "x-amz-meta-") && len(values) > 0 {
			// Extract the key portion after "x-amz-meta-" and lowercase it
			// This matches AWS S3 behavior which lowercases all metadata keys
			metaKey := strings.ToLower(key[len("X-Amz-Meta-"):])
			value := values[0]
			// Decode only percent-encoded values to avoid converting literal '+' into spaces.
			// AWS SDKs may encode non-ASCII metadata values like "Hello+World%C3%A9".
			if strings.Contains(value, "%") {
				if decoded, err := url.QueryUnescape(value); err == nil {
					value = decoded
				}
			}
			metadata[metaKey] = value
		}
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

// setMetadataHeaders sets x-amz-meta-* response headers without Go's canonicalization.
// This preserves lowercase keys as required by S3 API compatibility.
func setMetadataHeaders(w http.ResponseWriter, metadata map[string]string) {
	for k, v := range metadata {
		// Use direct map access to avoid Go's header canonicalization
		// This ensures "x-amz-meta-foo" stays lowercase, not "X-Amz-Meta-Foo"
		w.Header()["x-amz-meta-"+k] = []string{encodeHeaderMetadataValue(v)}
	}
}

// encodeHeaderMetadataValue encodes metadata values to Latin-1 bytes when possible.
// boto3/botocore decodes response header bytes as Latin-1, so returning UTF-8 bytes
// for non-ASCII characters causes mojibake (e.g., "é" -> "Ã©").
func encodeHeaderMetadataValue(v string) string {
	needsNonASCII := false
	for _, r := range v {
		if r > 127 {
			needsNonASCII = true
			break
		}
	}
	if !needsNonASCII {
		return v
	}

	buf := make([]byte, 0, len(v))
	for _, r := range v {
		if r > 255 {
			// Fallback: keep the original UTF-8 value for characters outside Latin-1.
			return v
		}
		buf = append(buf, byte(r))
	}
	return string(buf)
}

// parseTaggingHeader parses the x-amz-tagging header value.
// Format: key1=value1&key2=value2 (URL-encoded)
func parseTaggingHeader(header string) map[string]string {
	if header == "" {
		return nil
	}
	values, err := url.ParseQuery(header)
	if err != nil {
		return nil
	}
	tags := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			tags[k] = v[0]
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

const (
	maxTagsPerObject = 10
	maxTagKeyLength  = 128
	maxTagValLength  = 256
)

// validateTags checks that tags meet S3 limits: max 10 tags, key <=128 chars, value <=256 chars.
func validateTags(tags map[string]string) (string, string) {
	if len(tags) > maxTagsPerObject {
		return "InvalidTag", "Object tags cannot be greater than 10"
	}
	for k, v := range tags {
		if len(k) > maxTagKeyLength {
			return "InvalidTag", "The TagKey you have provided is too long"
		}
		if len(v) > maxTagValLength {
			return "InvalidTag", "The TagValue you have provided is too long"
		}
	}
	return "", ""
}

// validateTagSet checks a TagSet (from XML) for S3 limits.
func validateTagSet(tagSet []backend.Tag) (string, string) {
	if len(tagSet) > maxTagsPerObject {
		return "InvalidTag", "Object tags cannot be greater than 10"
	}
	for _, tag := range tagSet {
		if len(tag.Key) > maxTagKeyLength {
			return "InvalidTag", "The TagKey you have provided is too long"
		}
		if len(tag.Value) > maxTagValLength {
			return "InvalidTag", "The TagValue you have provided is too long"
		}
	}
	return "", ""
}

// setObjectLockHeaders sets Object Lock response headers if present on the object.
func setObjectLockHeaders(w http.ResponseWriter, obj *backend.Object) {
	if obj.RetentionMode != "" {
		w.Header().Set("x-amz-object-lock-mode", obj.RetentionMode)
	}
	if obj.RetainUntilDate != nil {
		w.Header().
			Set("x-amz-object-lock-retain-until-date", obj.RetainUntilDate.Format(time.RFC3339))
	}
	if obj.LegalHoldStatus != "" {
		w.Header().Set("x-amz-object-lock-legal-hold", obj.LegalHoldStatus)
	}
}

// setStorageAndEncryptionHeaders sets StorageClass and SSE response headers.
func setStorageAndEncryptionHeaders(w http.ResponseWriter, obj *backend.Object) {
	if obj.StorageClass != "" && obj.StorageClass != "STANDARD" {
		w.Header().Set("x-amz-storage-class", obj.StorageClass)
	}
	if obj.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", obj.ServerSideEncryption)
	}
	if obj.SSEKMSKeyId != "" {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", obj.SSEKMSKeyId)
	}
	if obj.SSECustomerAlgorithm != "" {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", obj.SSECustomerAlgorithm)
	}
	if obj.SSECustomerKeyMD5 != "" {
		w.Header().Set("x-amz-server-side-encryption-customer-key-md5", obj.SSECustomerKeyMD5)
	}
}

// isArchivedStorageClass returns true for storage classes that require restore before access.
func isArchivedStorageClass(sc string) bool {
	return sc == "GLACIER" || sc == "DEEP_ARCHIVE"
}

// isObjectRestored returns true if the object has been restored and the restore has not expired.
func isObjectRestored(obj *backend.Object) bool {
	return obj.RestoreExpiryDate != nil && obj.RestoreExpiryDate.After(time.Now().UTC())
}

// setRestoreHeader sets the x-amz-restore header for objects with restore information.
func setRestoreHeader(w http.ResponseWriter, obj *backend.Object) {
	if obj.RestoreExpiryDate != nil {
		if obj.RestoreOngoing {
			w.Header().Set("x-amz-restore", `ongoing-request="true"`)
		} else {
			expiry := obj.RestoreExpiryDate.Format(http.TimeFormat)
			w.Header().Set("x-amz-restore", fmt.Sprintf(`ongoing-request="false", expiry-date="%s"`, expiry))
		}
	}
}

func (h *Handler) setLifecycleExpirationHeader(
	w http.ResponseWriter,
	bucketName, key string,
	obj *backend.Object,
) {
	if obj == nil {
		return
	}
	config, err := h.backend.GetBucketLifecycleConfiguration(bucketName)
	if err != nil || config == nil {
		return
	}

	ruleID, expiryDate, ok := findLifecycleExpirationForObject(config, key, obj)
	if !ok || ruleID == "" {
		return
	}
	w.Header().Set(
		"x-amz-expiration",
		fmt.Sprintf(
			`expiry-date="%s", rule-id="%s"`,
			expiryDate.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"),
			ruleID,
		),
	)
}

func findLifecycleExpirationForObject(
	config *backend.LifecycleConfiguration,
	key string,
	obj *backend.Object,
) (string, time.Time, bool) {
	if config == nil || obj == nil {
		return "", time.Time{}, false
	}
	for _, rule := range config.Rules {
		if rule.Status != backend.LifecycleStatusEnabled || rule.Expiration == nil {
			continue
		}
		if !lifecycleRuleMatchesObjectForHeader(rule, key, obj) {
			continue
		}
		expiryDate, ok := lifecycleExpiryDate(rule.Expiration, obj.LastModified)
		if !ok {
			continue
		}
		return rule.ID, expiryDate, true
	}
	return "", time.Time{}, false
}

func lifecycleRuleMatchesObjectForHeader(
	rule backend.LifecycleRule,
	key string,
	obj *backend.Object,
) bool {
	if obj == nil {
		return false
	}
	if rule.Prefix != "" && !strings.HasPrefix(key, rule.Prefix) {
		return false
	}
	if rule.Filter == nil {
		return true
	}
	if rule.Filter.Prefix != "" && !strings.HasPrefix(key, rule.Filter.Prefix) {
		return false
	}
	if !lifecycleObjectSizeMatchForHeader(
		obj.Size,
		rule.Filter.ObjectSizeGreaterThan,
		rule.Filter.ObjectSizeLessThan,
	) {
		return false
	}
	if rule.Filter.Tag != nil && !lifecycleObjectHasTagForHeader(obj, *rule.Filter.Tag) {
		return false
	}
	if rule.Filter.And != nil {
		if rule.Filter.And.Prefix != "" && !strings.HasPrefix(key, rule.Filter.And.Prefix) {
			return false
		}
		if !lifecycleObjectSizeMatchForHeader(
			obj.Size,
			rule.Filter.And.ObjectSizeGreaterThan,
			rule.Filter.And.ObjectSizeLessThan,
		) {
			return false
		}
		for _, tag := range rule.Filter.And.Tags {
			if !lifecycleObjectHasTagForHeader(obj, tag) {
				return false
			}
		}
	}
	return true
}

func lifecycleObjectHasTagForHeader(obj *backend.Object, tag backend.Tag) bool {
	if obj == nil || obj.Tags == nil || tag.Key == "" {
		return false
	}
	value, ok := obj.Tags[tag.Key]
	return ok && value == tag.Value
}

func lifecycleObjectSizeMatchForHeader(size int64, greaterThan, lessThan int64) bool {
	if greaterThan > 0 && size <= greaterThan {
		return false
	}
	if lessThan > 0 && size >= lessThan {
		return false
	}
	return true
}

func lifecycleExpiryDate(
	expiration *backend.LifecycleExpiration,
	base time.Time,
) (time.Time, bool) {
	if expiration == nil {
		return time.Time{}, false
	}
	if expiration.Days > 0 {
		// Add one second so second-level header formatting still yields
		// at least N full days from caller timestamps with sub-second precision.
		return base.UTC().AddDate(0, 0, expiration.Days).Add(time.Second), true
	}
	if expiration.Date != "" {
		d, err := parseLifecycleExpirationDate(expiration.Date)
		if err != nil {
			return time.Time{}, false
		}
		return d.UTC(), true
	}
	return time.Time{}, false
}

// validateSSEHeaders validates server-side encryption headers on a write request (PutObject, CreateMultipartUpload).
// Returns (errorCode, errorMessage) or ("", "") if valid.
func validateSSEHeaders(r *http.Request) (string, string) {
	sse := r.Header.Get("x-amz-server-side-encryption")
	sseKmsKeyId := r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id")
	sseCA := r.Header.Get("x-amz-server-side-encryption-customer-algorithm")
	sseCKey := r.Header.Get("x-amz-server-side-encryption-customer-key")
	sseCKeyMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5")

	// Validate SSE algorithm value
	if sse != "" && sse != "AES256" && sse != "aws:kms" && sse != "aws:kms:dsse" {
		return "InvalidArgument", "Invalid x-amz-server-side-encryption header value."
	}

	// SSE-C and SSE-S3/SSE-KMS are mutually exclusive
	if sseCA != "" && sse != "" {
		return "InvalidArgument", "Server Side Encryption with Customer provided key and target encryption are mutually exclusive."
	}

	// KMS key ID without aws:kms declaration
	if sseKmsKeyId != "" && sse != "aws:kms" && sse != "aws:kms:dsse" {
		return "InvalidArgument", "SSE-KMS key ID is not applicable without aws:kms encryption."
	}
	if (sse == "aws:kms" || sse == "aws:kms:dsse") && sseKmsKeyId == "" {
		return "InvalidArgument", "SSE-KMS key ID must be specified."
	}

	// SSE-C header completeness: all or none
	hasAlgo := sseCA != ""
	hasKey := sseCKey != ""
	hasMD5 := sseCKeyMD5 != ""
	if hasAlgo || hasKey || hasMD5 {
		if !hasAlgo || !hasKey || !hasMD5 {
			return "InvalidArgument", "All SSE-C headers must be provided together."
		}

		// Validate SSE-C key MD5
		keyBytes, err := base64.StdEncoding.DecodeString(sseCKey)
		if err != nil {
			return "InvalidArgument", "The SSE-C key is not valid base64."
		}
		computedMD5 := md5.Sum(keyBytes)
		expectedMD5 := base64.StdEncoding.EncodeToString(computedMD5[:])
		if expectedMD5 != sseCKeyMD5 {
			return "InvalidArgument", "The calculated MD5 hash of the key did not match the hash that was provided."
		}
	}

	return "", ""
}

// validateSSECAccess checks if the request provides correct SSE-C headers to access an SSE-C encrypted object.
// Returns true if access should be denied (caller should return 400).
func validateSSECAccess(w http.ResponseWriter, r *http.Request, obj *backend.Object) bool {
	if obj.SSECustomerAlgorithm == "" {
		return false // not SSE-C encrypted
	}
	// Object was encrypted with SSE-C - require SSE-C headers on access
	reqAlgo := r.Header.Get("x-amz-server-side-encryption-customer-algorithm")
	reqKeyMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5")
	if reqAlgo == "" {
		backend.WriteError(w, http.StatusBadRequest, "InvalidRequest",
			"The object was stored using a form of Server Side Encryption. "+
				"The correct parameters must be provided to retrieve the object.")
		return true
	}
	// Verify key MD5 matches
	if reqKeyMD5 != obj.SSECustomerKeyMD5 {
		backend.WriteError(w, http.StatusBadRequest, "InvalidRequest",
			"The provided encryption parameters did not match the ones used originally.")
		return true
	}
	return false
}

// setChecksumResponseHeaders sets checksum-related response headers based on object's checksum data.
func setChecksumResponseHeaders(w http.ResponseWriter, obj *backend.Object) {
	if obj.ChecksumAlgorithm != "" {
		w.Header().Set("x-amz-checksum-algorithm", obj.ChecksumAlgorithm)
	}
	if obj.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", obj.ChecksumType)
	}
	if obj.ChecksumCRC32C != "" {
		w.Header().Set("x-amz-checksum-crc32c", obj.ChecksumCRC32C)
	}
	if obj.ChecksumCRC64NVME != "" {
		w.Header().Set("x-amz-checksum-crc64nvme", obj.ChecksumCRC64NVME)
	}
	if obj.ChecksumSHA1 != "" {
		w.Header().Set("x-amz-checksum-sha1", obj.ChecksumSHA1)
	}
	if obj.ChecksumSHA256 != "" {
		w.Header().Set("x-amz-checksum-sha256", obj.ChecksumSHA256)
	}
	if obj.ChecksumCRC32 != "" {
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
	}
}

func setPartChecksumResponseHeaders(
	w http.ResponseWriter,
	checksumType string,
	part *backend.ObjectPart,
) {
	if part == nil {
		return
	}
	if checksumType != "" {
		w.Header().Set("x-amz-checksum-type", checksumType)
	}
	if part.ChecksumCRC32 != "" {
		w.Header().Set("x-amz-checksum-crc32", part.ChecksumCRC32)
	}
	if part.ChecksumCRC32C != "" {
		w.Header().Set("x-amz-checksum-crc32c", part.ChecksumCRC32C)
	}
	if part.ChecksumCRC64NVME != "" {
		w.Header().Set("x-amz-checksum-crc64nvme", part.ChecksumCRC64NVME)
	}
	if part.ChecksumSHA1 != "" {
		w.Header().Set("x-amz-checksum-sha1", part.ChecksumSHA1)
	}
	if part.ChecksumSHA256 != "" {
		w.Header().Set("x-amz-checksum-sha256", part.ChecksumSHA256)
	}
}

// inferChecksumAlgorithmFromTrailer infers the checksum algorithm from the x-amz-trailer header value.
// The trailer header contains the name of the trailing header, e.g. "x-amz-checksum-crc32c".
func inferChecksumAlgorithmFromTrailer(trailer string) string {
	trailer = strings.ToLower(strings.TrimSpace(trailer))
	switch {
	case strings.Contains(trailer, "checksum-crc32c"):
		return "CRC32C"
	case strings.Contains(trailer, "checksum-crc32"):
		return "CRC32"
	case strings.Contains(trailer, "checksum-crc64nvme"):
		return "CRC64NVME"
	case strings.Contains(trailer, "checksum-sha1"):
		return "SHA1"
	case strings.Contains(trailer, "checksum-sha256"):
		return "SHA256"
	default:
		return ""
	}
}

// getPartData returns the data slice and size for a specific part number of a multipart object.
// Returns (data, size, partInfo, found). If the object has no parts or the part number is invalid, found is false.
func getPartData(
	obj *backend.Object,
	partNumber int,
) ([]byte, int64, *backend.ObjectPart, bool) {
	if len(obj.Parts) == 0 {
		// Non-multipart object: PartNumber=1 returns entire object
		if partNumber == 1 {
			return obj.Data, obj.Size, nil, true
		}
		return nil, 0, nil, false
	}

	var offset int64
	for _, p := range obj.Parts {
		if p.PartNumber == partNumber {
			end := offset + p.Size
			if end > int64(len(obj.Data)) {
				end = int64(len(obj.Data))
			}
			partCopy := p
			return obj.Data[offset:end], p.Size, &partCopy, true
		}
		offset += p.Size
	}
	return nil, 0, nil, false
}

// parseExpires parses the Expires header value.
func parseExpires(value string) *time.Time {
	if value == "" {
		return nil
	}
	// Try RFC1123 format first (standard HTTP date)
	t, err := time.Parse(http.TimeFormat, value)
	if err == nil {
		return &t
	}
	// Try RFC3339 format
	t, err = time.Parse(time.RFC3339, value)
	if err == nil {
		return &t
	}
	return nil
}

func stripAWSChunkedContentEncoding(contentEncoding string) string {
	parts := strings.Split(contentEncoding, ",")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" || token == "aws-chunked" {
			continue
		}
		filtered = append(filtered, token)
	}
	return strings.Join(filtered, ", ")
}

// ConditionalResult represents the result of evaluating conditional headers.
type ConditionalResult struct {
	ShouldReturn bool
	StatusCode   int
}

// evaluateConditionalHeaders evaluates conditional request headers against an object.
// Returns whether the request should return early and with what status code.
// Evaluation order follows S3 spec: If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since.
func evaluateConditionalHeaders(r *http.Request, obj *backend.Object) ConditionalResult {
	// 1. If-Match: return 412 if ETag doesn't match
	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" {
		if !matchesETag(ifMatch, obj.ETag) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	// 2. If-Unmodified-Since: return 412 if modified after the given date
	ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since")
	if ifUnmodifiedSince != "" {
		t, err := time.Parse(http.TimeFormat, ifUnmodifiedSince)
		if err == nil && obj.LastModified.After(t) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	// 3. If-None-Match: return 304 if ETag matches
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		if matchesETag(ifNoneMatch, obj.ETag) {
			return ConditionalResult{true, http.StatusNotModified}
		}
	}

	// 4. If-Modified-Since: return 304 if not modified after the given date
	ifModifiedSince := r.Header.Get("If-Modified-Since")
	if ifModifiedSince != "" {
		t, err := time.Parse(http.TimeFormat, ifModifiedSince)
		if err == nil && !obj.LastModified.After(t) {
			return ConditionalResult{true, http.StatusNotModified}
		}
	}

	return ConditionalResult{false, 0}
}

// evaluateCopySourceConditionals evaluates copy source conditional headers.
// Unlike GET/HEAD, CopyObject returns 412 Precondition Failed for all failures (never 304).
func evaluateCopySourceConditionals(r *http.Request, srcObj *backend.Object) ConditionalResult {
	// x-amz-copy-source-if-match: 412 if ETag doesn't match
	ifMatch := r.Header.Get("x-amz-copy-source-if-match")
	if ifMatch != "" {
		if !matchesETag(ifMatch, srcObj.ETag) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	// x-amz-copy-source-if-unmodified-since: 412 if modified after the given date
	ifUnmodifiedSince := r.Header.Get("x-amz-copy-source-if-unmodified-since")
	if ifUnmodifiedSince != "" {
		t, err := time.Parse(http.TimeFormat, ifUnmodifiedSince)
		if err == nil && srcObj.LastModified.After(t) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	// x-amz-copy-source-if-none-match: 412 if ETag matches (not 304 for CopyObject)
	ifNoneMatch := r.Header.Get("x-amz-copy-source-if-none-match")
	if ifNoneMatch != "" {
		if matchesETag(ifNoneMatch, srcObj.ETag) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	// x-amz-copy-source-if-modified-since: 412 if not modified (not 304 for CopyObject)
	ifModifiedSince := r.Header.Get("x-amz-copy-source-if-modified-since")
	if ifModifiedSince != "" {
		t, err := time.Parse(http.TimeFormat, ifModifiedSince)
		if err == nil && !srcObj.LastModified.After(t) {
			return ConditionalResult{true, http.StatusPreconditionFailed}
		}
	}

	return ConditionalResult{false, 0}
}

func parseTimestampFlexible(value string) (*time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, http.TimeFormat} {
		if t, err := time.Parse(layout, value); err == nil {
			return &t, nil
		}
	}
	return nil, fmt.Errorf("invalid timestamp")
}

func evaluateDeletePreconditions(
	r *http.Request,
	obj *backend.Object,
) (int, string, string) {
	// DeleteObject is idempotent when the target does not exist, so preconditions
	// are ignored in that case.
	if obj == nil {
		return 0, "", ""
	}

	ifMatch := r.Header.Get("If-Match")
	if ifMatch != "" {
		if strings.TrimSpace(ifMatch) != "*" {
			if obj.IsDeleteMarker || !matchesETag(ifMatch, obj.ETag) {
				return http.StatusPreconditionFailed, "PreconditionFailed",
					"At least one of the pre-conditions you specified did not hold."
			}
		}
	}
	if v := strings.TrimSpace(r.Header.Get("x-amz-if-match-last-modified-time")); v != "" {
		t, err := parseTimestampFlexible(v)
		if err != nil {
			return http.StatusBadRequest, "InvalidArgument", "Invalid last-modified-time value."
		}
		if !obj.LastModified.UTC().Truncate(time.Second).Equal(t.UTC().Truncate(time.Second)) {
			return http.StatusPreconditionFailed, "PreconditionFailed",
				"At least one of the pre-conditions you specified did not hold."
		}
	}
	if v := strings.TrimSpace(r.Header.Get("x-amz-if-match-size")); v != "" {
		size, err := strconv.ParseInt(v, 10, 64)
		if err != nil || size < 0 {
			return http.StatusBadRequest, "InvalidArgument", "Invalid size value."
		}
		if obj.Size != size {
			return http.StatusPreconditionFailed, "PreconditionFailed",
				"At least one of the pre-conditions you specified did not hold."
		}
	}
	return 0, "", ""
}

func computePartChecksums(data []byte, algorithm string) backend.GetObjectAttributesPartItem {
	item := backend.GetObjectAttributesPartItem{}
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		h := crc32.NewIEEE()
		_, _ = h.Write(data)
		item.ChecksumCRC32 = base64.StdEncoding.EncodeToString(h.Sum(nil))
	case "CRC32C":
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		_, _ = h.Write(data)
		item.ChecksumCRC32C = base64.StdEncoding.EncodeToString(h.Sum(nil))
	case "CRC64NVME":
		table := crc64.MakeTable(crc64NVME)
		sum := crc64.Checksum(data, table)
		buf := []byte{
			byte(sum >> 56), byte(sum >> 48), byte(sum >> 40), byte(sum >> 32),
			byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
		}
		item.ChecksumCRC64NVME = base64.StdEncoding.EncodeToString(buf)
	case "SHA1":
		sum := sha1.Sum(data)
		item.ChecksumSHA1 = base64.StdEncoding.EncodeToString(sum[:])
	case "SHA256":
		sum := sha256.Sum256(data)
		item.ChecksumSHA256 = base64.StdEncoding.EncodeToString(sum[:])
	}
	return item
}

// matchesETag checks if the given header value matches the object's ETag.
// Supports wildcard "*" and comma-separated ETags.
func matchesETag(header, etag string) bool {
	// Handle wildcard
	if header == "*" {
		return true
	}

	// Normalize the object's ETag (ensure it has quotes)
	normalizedETag := etag
	if !strings.HasPrefix(etag, "\"") {
		normalizedETag = "\"" + etag + "\""
	}

	// Handle comma-separated ETags
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		// Remove quotes for comparison if present, then compare
		candidateNormalized := candidate
		if !strings.HasPrefix(candidate, "\"") {
			candidateNormalized = "\"" + candidate + "\""
		}
		if candidateNormalized == normalizedETag || candidate == etag {
			return true
		}
	}

	return false
}

// applyResponseOverrides applies response header overrides from query parameters.
// Supported: response-content-type, response-content-disposition, response-content-language,
// response-expires, response-cache-control, response-content-encoding.
func applyResponseOverrides(w http.ResponseWriter, r *http.Request) {
	overrides := map[string]string{
		"response-content-type":        "Content-Type",
		"response-content-disposition": "Content-Disposition",
		"response-content-language":    "Content-Language",
		"response-expires":             "Expires",
		"response-cache-control":       "Cache-Control",
		"response-content-encoding":    "Content-Encoding",
	}
	for param, header := range overrides {
		if val := r.URL.Query().Get(param); val != "" {
			w.Header().Set(header, val)
		}
	}
}

// parseRangeHeader parses a Range header value and returns start and end positions.
// Supported formats: "bytes=start-end", "bytes=start-", "bytes=-suffix"
// Returns start, end (inclusive), and error if invalid.
func parseRangeHeader(rangeHeader string, size int64) (int64, int64, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, backend.ErrInvalidRange
	}

	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")

	// Handle suffix range: bytes=-N (last N bytes)
	if strings.HasPrefix(rangeSpec, "-") {
		suffix, err := strconv.ParseInt(rangeSpec[1:], 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, backend.ErrInvalidRange
		}
		if suffix >= size {
			// Return entire object
			return 0, size - 1, nil
		}
		return size - suffix, size - 1, nil
	}

	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, backend.ErrInvalidRange
	}

	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, backend.ErrInvalidRange
	}

	// Handle open-ended range: bytes=N-
	if parts[1] == "" {
		if start >= size {
			return 0, 0, backend.ErrInvalidRange
		}
		return start, size - 1, nil
	}

	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, backend.ErrInvalidRange
	}

	// Validate range
	if start > end || start >= size {
		return 0, 0, backend.ErrInvalidRange
	}

	// Clamp end to object size
	if end >= size {
		end = size - 1
	}

	return start, end, nil
}

// handleObject handles object-level operations.
func (h *Handler) handleObject(w http.ResponseWriter, r *http.Request, bucketName, key string) {
	if containsUnreadableURIKeyRune(key) {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidURI",
			"Couldn't parse the specified URI.",
		)
		return
	}

	if r.URL.Query().Has("torrent") && r.Method == http.MethodGet {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchKey",
			"The specified key does not exist.",
		)
		return
	}
	// Handle Object Tagging operations
	if r.URL.Query().Has("tagging") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectTagging(w, r, bucketName, key)
		case http.MethodPut:
			h.handlePutObjectTagging(w, r, bucketName, key)
		case http.MethodDelete:
			h.handleDeleteObjectTagging(w, r, bucketName, key)
		default:
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
		}
		return
	}

	// Handle GetObjectAttributes operations
	if r.URL.Query().Has("attributes") && r.Method == http.MethodGet {
		h.handleGetObjectAttributes(w, r, bucketName, key)
		return
	}

	// Handle ACL operations
	if r.URL.Query().Has("acl") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectACL(w, r, bucketName, key)
		case http.MethodPut:
			h.handlePutObjectACL(w, r, bucketName, key)
		default:
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
		}
		return
	}

	// Handle Object Lock Retention operations
	if r.URL.Query().Has("retention") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectRetention(w, r, bucketName, key)
		case http.MethodPut:
			h.handlePutObjectRetention(w, r, bucketName, key)
		default:
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
		}
		return
	}

	// Handle Object Lock Legal Hold operations
	if r.URL.Query().Has("legal-hold") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectLegalHold(w, r, bucketName, key)
		case http.MethodPut:
			h.handlePutObjectLegalHold(w, r, bucketName, key)
		default:
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
		}
		return
	}

	// Handle multipart upload operations
	query := r.URL.Query()
	if query.Has("uploadId") {
		uploadId := query.Get("uploadId")
		switch r.Method {
		case http.MethodPut:
			if query.Has("partNumber") {
				// Check for copy source header (UploadPartCopy)
				if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
					h.handleUploadPartCopy(w, r, bucketName, key, copySource)
					return
				}
				h.handleUploadPart(w, r, bucketName, key)
				return
			}
		case http.MethodPost:
			h.handleCompleteMultipartUpload(w, r, bucketName, key)
			return
		case http.MethodDelete:
			h.handleAbortMultipartUpload(w, r, bucketName, key)
			return
		case http.MethodGet:
			if uploadId != "" {
				h.handleListParts(w, r, bucketName, key)
				return
			}
		}
	}

	// Handle CreateMultipartUpload (POST with ?uploads)
	if r.Method == http.MethodPost && query.Has("uploads") {
		h.handleCreateMultipartUpload(w, r, bucketName, key)
		return
	}

	// Handle RestoreObject (POST with ?restore)
	if r.Method == http.MethodPost && query.Has("restore") {
		h.handleRestoreObject(w, r, bucketName, key)
		return
	}

	switch r.Method {
	case http.MethodPut:
		if err := h.flushServerAccessLogsIfDue(bucketName); err != nil {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		copySource := r.Header.Get("x-amz-copy-source")
		if copySource != "" {
			h.handleCopyObject(w, r, bucketName, key, copySource)
			return
		}

		inlineTags := parseTaggingHeader(r.Header.Get("x-amz-tagging"))

		// Evaluate access before reading body to avoid emitting 100-continue
		// for unauthorized requests.
		if !h.checkAccessWithContext(r, bucketName, "s3:PutObject", key, backend.PolicyEvalContext{
			RequestObjectTags: inlineTags,
		}) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		var data []byte
		var err error

		// Check for AWS chunked encoding
		contentEncoding := r.Header.Get("Content-Encoding")
		if isAWSChunkedEncoding(contentEncoding) {
			data, err = decodeAWSChunkedBody(r.Body)
		} else {
			data, err = readAllFn(r.Body)
		}
		if err != nil {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = r.Body.Close() }()

		// Strip aws-chunked from content encoding (it's a transfer encoding, not content encoding)
		storedContentEncoding := contentEncoding
		if isAWSChunkedEncoding(contentEncoding) {
			storedContentEncoding = stripAWSChunkedContentEncoding(contentEncoding)
		}

		existingObj, getObjErr := h.backend.GetObject(bucketName, key)
		bucketExists := !errors.Is(getObjErr, backend.ErrBucketNotFound)
		objectExists := getObjErr == nil && existingObj != nil && !existingObj.IsDeleteMarker
		if ifMatch := r.Header.Get("If-Match"); ifMatch != "" && bucketExists {
			if !objectExists {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchKey",
					"The specified key does not exist.",
				)
				return
			}
			if !matchesETag(ifMatch, existingObj.ETag) {
				backend.WriteError(
					w,
					http.StatusPreconditionFailed,
					"PreconditionFailed",
					"At least one of the pre-conditions you specified did not hold.",
				)
				return
			}
		}
		if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" && bucketExists {
			if objectExists && matchesETag(ifNoneMatch, existingObj.ETag) {
				backend.WriteError(
					w,
					http.StatusPreconditionFailed,
					"PreconditionFailed",
					"At least one of the pre-conditions you specified did not hold.",
				)
				return
			}
		}

		if errCode, errMsg := validateTags(inlineTags); errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}

		opts := backend.PutObjectOptions{
			ContentType:        r.Header.Get("Content-Type"),
			Metadata:           extractMetadata(r),
			CacheControl:       r.Header.Get("Cache-Control"),
			Expires:            parseExpires(r.Header.Get("Expires")),
			ContentEncoding:    storedContentEncoding,
			ContentLanguage:    r.Header.Get("Content-Language"),
			ContentDisposition: r.Header.Get("Content-Disposition"),
			Tags:               inlineTags,
		}

		// Extract Object Lock headers
		if lockMode := r.Header.Get("x-amz-object-lock-mode"); lockMode != "" {
			opts.RetentionMode = lockMode
		}
		if retainUntil := r.Header.Get("x-amz-object-lock-retain-until-date"); retainUntil != "" {
			t, err := time.Parse(time.RFC3339, retainUntil)
			if err == nil {
				t = t.UTC().Truncate(time.Second)
				opts.RetainUntilDate = &t
			}
		}
		if legalHold := r.Header.Get("x-amz-object-lock-legal-hold"); legalHold != "" {
			opts.LegalHoldStatus = legalHold
		}

		// Extract Storage Class header
		if storageClass := r.Header.Get("x-amz-storage-class"); storageClass != "" {
			opts.StorageClass = storageClass
		}

		// Validate Server-Side Encryption headers
		if errCode, errMsg := validateSSEHeaders(r); errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}

		// Extract Server-Side Encryption headers
		if sse := r.Header.Get("x-amz-server-side-encryption"); sse != "" {
			opts.ServerSideEncryption = sse
		}
		if sseKmsKeyId := r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"); sseKmsKeyId != "" {
			opts.SSEKMSKeyId = sseKmsKeyId
		}
		// SSE-C headers
		if sseCA := r.Header.Get("x-amz-server-side-encryption-customer-algorithm"); sseCA != "" {
			opts.SSECustomerAlgorithm = sseCA
		}
		if sseCKMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5"); sseCKMD5 != "" {
			opts.SSECustomerKeyMD5 = sseCKMD5
		}

		// Extract Website Redirect Location header
		if redirect := r.Header.Get("x-amz-website-redirect-location"); redirect != "" {
			opts.WebsiteRedirectLocation = redirect
		}

		// Extract Checksum Algorithm and checksum values
		// AWS SDK v2 sends x-amz-sdk-checksum-algorithm (with "sdk"), S3 API uses x-amz-checksum-algorithm
		checksumAlgo := r.Header.Get("x-amz-checksum-algorithm")
		if checksumAlgo == "" {
			checksumAlgo = r.Header.Get("x-amz-sdk-checksum-algorithm")
		}
		// Also infer from x-amz-trailer header (e.g. "x-amz-checksum-crc32c")
		if checksumAlgo == "" {
			if trailer := r.Header.Get("x-amz-trailer"); trailer != "" {
				checksumAlgo = inferChecksumAlgorithmFromTrailer(trailer)
			}
		}
		if checksumAlgo != "" {
			opts.ChecksumAlgorithm = checksumAlgo
		}
		if v := r.Header.Get("x-amz-checksum-crc32"); v != "" {
			opts.ChecksumCRC32 = v
		}
		if v := r.Header.Get("x-amz-checksum-crc32c"); v != "" {
			opts.ChecksumCRC32C = v
		}
		if v := r.Header.Get("x-amz-checksum-crc64nvme"); v != "" {
			opts.ChecksumCRC64NVME = v
		}
		if v := r.Header.Get("x-amz-checksum-sha1"); v != "" {
			opts.ChecksumSHA1 = v
		}
		if v := r.Header.Get("x-amz-checksum-sha256"); v != "" {
			opts.ChecksumSHA256 = v
		}

		requestOwner := requesterOwner(r)
		bucketOwner := h.bucketOwner(bucketName)
		bucketOwnership := backend.ObjectOwnershipObjectWriter
		if bucket, ok := h.backend.GetBucket(bucketName); ok && bucket.ObjectOwnership != "" {
			bucketOwnership = bucket.ObjectOwnership
		}
		grantHeadersPresent := r.Header.Get("x-amz-grant-full-control") != "" ||
			r.Header.Get("x-amz-grant-read") != "" ||
			r.Header.Get("x-amz-grant-write") != "" ||
			r.Header.Get("x-amz-grant-read-acp") != "" ||
			r.Header.Get("x-amz-grant-write-acp") != ""
		if strings.EqualFold(bucketOwnership, backend.ObjectOwnershipBucketOwnerEnforced) &&
			(grantHeadersPresent ||
				(r.Header.Get("x-amz-acl") != "" &&
					!strings.EqualFold(r.Header.Get("x-amz-acl"), string(backend.ACLBucketOwnerFull)))) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"AccessControlListNotSupported",
				"The bucket does not allow ACLs",
			)
			return
		}
		switch bucketOwnership {
		case backend.ObjectOwnershipBucketOwnerEnforced:
			opts.Owner = bucketOwner
		case backend.ObjectOwnershipBucketOwnerPreferred:
			if strings.EqualFold(r.Header.Get("x-amz-acl"), string(backend.ACLBucketOwnerFull)) {
				opts.Owner = bucketOwner
			} else {
				opts.Owner = requestOwner
			}
		default:
			opts.Owner = requestOwner
		}
		aclOwner := opts.Owner
		if aclOwner == nil {
			aclOwner = requestOwner
		}
		requestedACL := backend.NewDefaultACLForOwner(aclOwner)
		headerACL, aclErr := aclFromGrantHeaders(r, requestOwner)
		if aclErr != nil {
			backend.WriteError(w, http.StatusBadRequest, aclErr.code, aclErr.message)
			return
		}
		if headerACL != nil {
			requestedACL = headerACL
		} else if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
			requestedACL = backend.CannedACLToPolicyForOwner(cannedACL, aclOwner, bucketOwner)
		}
		config := h.getBucketPublicAccessBlock(bucketName)
		if config != nil && config.BlockPublicAcls && isPublicACL(requestedACL) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		obj, err := putObjectFn(h, bucketName, key, data, opts)
		if err != nil {
			if errors.Is(err, backend.ErrInvalidRequest) {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"InvalidRequest",
					"Bucket is missing Object Lock Configuration",
				)
				return
			}
			if errors.Is(err, backend.ErrBadDigest) {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"BadDigest",
					"The Content-MD5 you specified did not match what we received.",
				)
				return
			}
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		}
		if !strings.EqualFold(bucketOwnership, backend.ObjectOwnershipBucketOwnerEnforced) {
			if err := putObjectACLFn(h, bucketName, key, obj.VersionId, requestedACL); err != nil {
				if errors.Is(err, backend.ErrAccessControlListNotSupported) {
					backend.WriteError(
						w,
						http.StatusBadRequest,
						"AccessControlListNotSupported",
						"The bucket does not allow ACLs",
					)
				} else {
					backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
				}
				return
			}
		}
		w.Header().Set("ETag", obj.ETag)
		// Add version ID header if versioning is enabled
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		// Return SSE headers
		if obj.ServerSideEncryption != "" {
			w.Header().Set("x-amz-server-side-encryption", obj.ServerSideEncryption)
		}
		if obj.SSEKMSKeyId != "" {
			w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", obj.SSEKMSKeyId)
		}
		h.setLifecycleExpirationHeader(w, bucketName, key, obj)
		// Return checksum headers for PutObject response
		setChecksumResponseHeaders(w, obj)
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		versionId := r.URL.Query().Get("versionId")

		// Check bucket policy for GetObject
		if !h.checkAccessWithContext(r, bucketName, "s3:GetObject", key, backend.PolicyEvalContext{
			ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionId),
		}) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		// Reject SSE write-headers on read operations
		if r.Header.Get("x-amz-server-side-encryption") != "" {
			backend.WriteError(w, http.StatusBadRequest, "InvalidArgument",
				"x-amz-server-side-encryption header is not applicable to GET requests.")
			return
		}

		var obj *backend.Object
		var err error

		if versionId != "" {
			obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			obj, err = h.backend.GetObject(bucketName, key)
		}

		if err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else if errors.Is(err, backend.ErrVersionNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchVersion",
					"The specified version does not exist.",
				)
			} else {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchKey",
					"The specified key does not exist.",
				)
			}
			return
		}

		// Check if this is a DeleteMarker
		if obj.IsDeleteMarker {
			w.Header().Set("x-amz-delete-marker", "true")
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			// Return 404 NoSuchKey when latest version is a delete marker
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
			return
		}
		// Auto-restore un-restored GLACIER/DEEP_ARCHIVE objects (read-through support)
		if isArchivedStorageClass(obj.StorageClass) && !isObjectRestored(obj) {
			_, _ = h.backend.RestoreObject(bucketName, key, r.URL.Query().Get("versionId"), readThroughRestoreDays())
		}

		// Check PartNumber validity before SSE-C access (invalid part takes priority)
		if partNumberStr := r.URL.Query().Get("partNumber"); partNumberStr != "" {
			partNumber, parseErr := strconv.Atoi(partNumberStr)
			if parseErr != nil || partNumber < 1 {
				backend.WriteError(w, http.StatusBadRequest, "InvalidArgument",
					"Part number must be a positive integer.")
				return
			}
			_, _, _, found := getPartData(obj, partNumber)
			if !found {
				backend.WriteError(w, http.StatusBadRequest, "InvalidPart",
					"The requested part number is not valid.")
				return
			}
		}

		// Validate SSE-C access
		if validateSSECAccess(w, r, obj) {
			return
		}

		// Evaluate conditional headers before returning content
		condResult := evaluateConditionalHeaders(r, obj)
		if condResult.ShouldReturn {
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			if condResult.StatusCode == http.StatusPreconditionFailed {
				backend.WriteError(
					w,
					http.StatusPreconditionFailed,
					"PreconditionFailed",
					"At least one of the pre-conditions you specified did not hold.",
				)
				return
			}
			w.WriteHeader(condResult.StatusCode)
			return
		}

		// Set common headers
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("Accept-Ranges", "bytes")
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		// Return checksum headers only when ChecksumMode is ENABLED and not a Range request.
		// S3 does not return object-level checksums for range (partial) responses.
		checksumMode := r.Header.Get("x-amz-checksum-mode")
		if strings.EqualFold(checksumMode, "ENABLED") && r.Header.Get("Range") == "" {
			setChecksumResponseHeaders(w, obj)
		}
		// Set optional headers if present
		if obj.CacheControl != "" {
			w.Header().Set("Cache-Control", obj.CacheControl)
		}
		if obj.Expires != nil {
			w.Header().Set("Expires", obj.Expires.Format(http.TimeFormat))
		}
		if obj.ContentEncoding != "" {
			w.Header().Set("Content-Encoding", obj.ContentEncoding)
		}
		if obj.ContentLanguage != "" {
			w.Header().Set("Content-Language", obj.ContentLanguage)
		}
		if obj.ContentDisposition != "" {
			w.Header().Set("Content-Disposition", obj.ContentDisposition)
		}
		// Set custom metadata headers
		setMetadataHeaders(w, obj.Metadata)
		// Set Object Lock headers
		setObjectLockHeaders(w, obj)
		// Set StorageClass and SSE headers
		setStorageAndEncryptionHeaders(w, obj)
		// Set x-amz-restore header for archived objects
		setRestoreHeader(w, obj)
		h.setLifecycleExpirationHeader(w, bucketName, key, obj)
		// Set Website Redirect Location header
		if obj.WebsiteRedirectLocation != "" {
			w.Header().Set("x-amz-website-redirect-location", obj.WebsiteRedirectLocation)
		}

		// Apply response header overrides from query parameters
		applyResponseOverrides(w, r)

		// Set tagging count header
		if len(obj.Tags) > 0 {
			w.Header().Set("x-amz-tagging-count", fmt.Sprintf("%d", len(obj.Tags)))
		}

		// Set parts count header for multipart objects
		if len(obj.Parts) > 0 {
			w.Header().Set("x-amz-mp-parts-count", fmt.Sprintf("%d", len(obj.Parts)))
		}

		// Handle PartNumber query parameter
		if partNumberStr := r.URL.Query().Get("partNumber"); partNumberStr != "" {
			partNumber, _ := strconv.Atoi(partNumberStr)
			partData, partSize, partInfo, _ := getPartData(obj, partNumber)
			setPartChecksumResponseHeaders(w, obj.ChecksumType, partInfo)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", partSize))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(partData)
			return
		}

		// Handle Range request
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			start, end, err := parseRangeHeader(rangeHeader, obj.Size)
			if err != nil {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", obj.Size))
				backend.WriteError(
					w,
					http.StatusRequestedRangeNotSatisfiable,
					"InvalidRange",
					"The requested range is not satisfiable.",
				)
				return
			}

			contentLength := end - start + 1
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, obj.Size))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLength))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(obj.Data[start : end+1])
			return
		}

		// Normal full object response
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		_, _ = w.Write(obj.Data)

	case http.MethodDelete:
		// Check bucket policy for DeleteObject
		if !h.checkAccess(r, bucketName, "s3:DeleteObject", key) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		versionId := r.URL.Query().Get("versionId")
		var conditionalObj *backend.Object
		if versionId != "" {
			conditionalObj, _ = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			conditionalObj, _ = h.backend.GetObject(bucketName, key)
			if conditionalObj != nil && conditionalObj.IsDeleteMarker {
				if bucket, ok := h.backend.GetBucket(bucketName); ok {
					if versions, exists := bucket.Objects[key]; exists {
						hasLiveVersion := false
						for i, version := range versions.Versions {
							if i == 0 {
								continue
							}
							if !version.IsDeleteMarker {
								hasLiveVersion = true
								break
							}
						}
						if !hasLiveVersion {
							conditionalObj = nil
						}
					}
				}
			}
		}
		if status, code, msg := evaluateDeletePreconditions(r, conditionalObj); status != 0 {
			backend.WriteError(w, status, code, msg)
			return
		}
		bypassGovernance := strings.EqualFold(
			r.Header.Get("x-amz-bypass-governance-retention"),
			"true",
		)
		var result *backend.DeleteObjectVersionResult
		var err error

		if versionId != "" {
			result, err = h.backend.DeleteObjectVersion(
				bucketName,
				key,
				versionId,
				bypassGovernance,
			)
		} else {
			result, err = h.backend.DeleteObject(bucketName, key, bypassGovernance)
		}

		if err != nil {
			if errors.Is(err, backend.ErrObjectLocked) {
				backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
				return
			}
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
				return
			}
			if errors.Is(err, backend.ErrVersionNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchVersion",
					"The specified version does not exist.",
				)
				return
			}
		}

		// Set response headers based on result
		if result != nil {
			if result.VersionId != "" && result.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", result.VersionId)
			}
			if result.IsDeleteMarker {
				w.Header().Set("x-amz-delete-marker", "true")
			}
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodHead:
		versionId := r.URL.Query().Get("versionId")

		// Check bucket policy for HeadObject
		if !h.checkAccessWithContext(r, bucketName, "s3:GetObject", key, backend.PolicyEvalContext{
			ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionId),
		}) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}

		// Reject SSE write-headers on read operations
		if r.Header.Get("x-amz-server-side-encryption") != "" {
			backend.WriteError(w, http.StatusBadRequest, "InvalidArgument",
				"x-amz-server-side-encryption header is not applicable to HEAD requests.")
			return
		}

		var obj *backend.Object
		var err error

		if versionId != "" {
			obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			obj, err = h.backend.GetObject(bucketName, key)
		}

		if err != nil {
			if errors.Is(err, backend.ErrObjectNotFound) {
				w.Header().Set("x-amz-delete-marker", "false")
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Check if this is a DeleteMarker
		if obj.IsDeleteMarker {
			w.Header().Set("x-amz-delete-marker", "true")
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			// Return 404 when latest version is a delete marker
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Auto-restore un-restored GLACIER/DEEP_ARCHIVE objects (read-through support)
		if isArchivedStorageClass(obj.StorageClass) && !isObjectRestored(obj) {
			_, _ = h.backend.RestoreObject(bucketName, key, r.URL.Query().Get("versionId"), readThroughRestoreDays())
		}

		// Validate SSE-C access
		if validateSSECAccess(w, r, obj) {
			return
		}

		// Evaluate conditional headers before returning metadata
		condResult := evaluateConditionalHeaders(r, obj)
		if condResult.ShouldReturn {
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			if condResult.StatusCode == http.StatusPreconditionFailed {
				backend.WriteError(
					w,
					http.StatusPreconditionFailed,
					"PreconditionFailed",
					"At least one of the pre-conditions you specified did not hold.",
				)
				return
			}
			w.WriteHeader(condResult.StatusCode)
			return
		}

		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("Accept-Ranges", "bytes")
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		// Return checksum headers only when ChecksumMode is ENABLED
		checksumMode := r.Header.Get("x-amz-checksum-mode")
		if strings.EqualFold(checksumMode, "ENABLED") {
			setChecksumResponseHeaders(w, obj)
		}
		// Set optional headers if present
		if obj.CacheControl != "" {
			w.Header().Set("Cache-Control", obj.CacheControl)
		}
		if obj.Expires != nil {
			w.Header().Set("Expires", obj.Expires.Format(http.TimeFormat))
		}
		if obj.ContentEncoding != "" {
			w.Header().Set("Content-Encoding", obj.ContentEncoding)
		}
		if obj.ContentLanguage != "" {
			w.Header().Set("Content-Language", obj.ContentLanguage)
		}
		if obj.ContentDisposition != "" {
			w.Header().Set("Content-Disposition", obj.ContentDisposition)
		}
		// Set custom metadata headers
		setMetadataHeaders(w, obj.Metadata)
		// Set Object Lock headers
		setObjectLockHeaders(w, obj)
		// Set StorageClass and SSE headers
		setStorageAndEncryptionHeaders(w, obj)
		// Set x-amz-restore header for archived objects
		setRestoreHeader(w, obj)
		h.setLifecycleExpirationHeader(w, bucketName, key, obj)
		// Set Website Redirect Location header
		if obj.WebsiteRedirectLocation != "" {
			w.Header().Set("x-amz-website-redirect-location", obj.WebsiteRedirectLocation)
		}

		// Set tagging count header
		if len(obj.Tags) > 0 {
			w.Header().Set("x-amz-tagging-count", fmt.Sprintf("%d", len(obj.Tags)))
		}

		// Set parts count header for multipart objects
		if len(obj.Parts) > 0 {
			w.Header().Set("x-amz-mp-parts-count", fmt.Sprintf("%d", len(obj.Parts)))
		}

		// Handle PartNumber query parameter
		if partNumberStr := r.URL.Query().Get("partNumber"); partNumberStr != "" {
			partNumber, err := strconv.Atoi(partNumberStr)
			if err != nil || partNumber < 1 {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"InvalidArgument",
					"Part number must be a positive integer.",
				)
				return
			}
			_, partSize, partInfo, found := getPartData(obj, partNumber)
			if !found {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"InvalidPart",
					"The requested part number is not valid.",
				)
				return
			}
			setPartChecksumResponseHeaders(w, obj.ChecksumType, partInfo)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", partSize))
			w.WriteHeader(http.StatusPartialContent)
			return
		}

		// Apply response header overrides from query parameters
		applyResponseOverrides(w, r)
		w.WriteHeader(http.StatusOK)

	default:
		backend.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	}
}

func containsUnreadableURIKeyRune(key string) bool {
	for _, r := range key {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func (h *Handler) existingObjectTagsForPolicy(
	bucketName, key, versionID string,
) map[string]string {
	var (
		obj *backend.Object
		err error
	)
	if versionID != "" {
		obj, err = h.backend.GetObjectVersion(bucketName, key, versionID)
	} else {
		obj, err = h.backend.GetObject(bucketName, key)
	}
	if err != nil || obj == nil || obj.IsDeleteMarker || len(obj.Tags) == 0 {
		return nil
	}
	tags := make(map[string]string, len(obj.Tags))
	for k, v := range obj.Tags {
		tags[k] = v
	}
	return tags
}

// handleDeleteObjects handles batch delete operations.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucketName string) {
	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body",
		)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var deleteReq backend.DeleteRequest
	if err := xml.Unmarshal(body, &deleteReq); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema",
		)
		return
	}

	if len(deleteReq.Objects) == 0 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema",
		)
		return
	}
	if len(deleteReq.Objects) > 1000 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema",
		)
		return
	}
	loggedKeys := make([]string, 0, len(deleteReq.Objects))
	for _, obj := range deleteReq.Objects {
		if obj.Key == "" {
			continue
		}
		loggedKeys = append(loggedKeys, obj.Key)
	}
	if len(loggedKeys) > 0 {
		ctx := context.WithValue(r.Context(), deleteLogKeysContextKey, loggedKeys)
		*r = *r.WithContext(ctx)
	}

	bypassGovernance := strings.EqualFold(r.Header.Get("x-amz-bypass-governance-retention"), "true")
	results, err := h.backend.DeleteObjects(bucketName, deleteReq.Objects, bypassGovernance)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.DeleteResult{
		Xmlns: backend.S3Xmlns,
	}

	for _, result := range results {
		if result.Error != nil {
			errCode := "InternalError"
			errMsg := result.Error.Error()
			if errors.Is(result.Error, backend.ErrObjectLocked) {
				errCode = "AccessDenied"
				errMsg = "Access Denied"
			} else if errors.Is(result.Error, backend.ErrPreconditionFailed) {
				errCode = "PreconditionFailed"
				errMsg = "At least one of the pre-conditions you specified did not hold."
			}
			resp.Errors = append(resp.Errors, backend.DeleteError{
				Key:       result.Key,
				VersionId: result.VersionId,
				Code:      errCode,
				Message:   errMsg,
			})
		} else if !deleteReq.Quiet {
			deleted := backend.DeletedObject{
				Key: result.Key,
			}
			if result.VersionId != "" {
				deleted.VersionId = result.VersionId
			}
			if result.DeleteMarker {
				deleted.DeleteMarker = true
				if result.DeleteMarkerVersionId != "" {
					deleted.DeleteMarkerVersionId = result.DeleteMarkerVersionId
				}
			}
			resp.Deleted = append(resp.Deleted, deleted)
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusInternalServerError,
			"InternalError",
			"Failed to marshal XML response",
		)
		return
	}
	_, _ = w.Write(output)
}

// handleCopyObject handles copy object operations.
func (h *Handler) handleCopyObject(
	w http.ResponseWriter,
	r *http.Request,
	dstBucket, dstKey, copySource string,
) {
	// Parse versionId from copy source BEFORE URL-decoding
	// (format: /bucket/key?versionId=xxx or /bucket/key%3Fencoded?versionId=xxx)
	var srcVersionId string
	pathPart := copySource
	if idx := strings.Index(copySource, "?"); idx != -1 {
		queryStr := copySource[idx+1:]
		pathPart = copySource[:idx]
		if values, err := url.ParseQuery(queryStr); err == nil {
			srcVersionId = values.Get("versionId")
		}
	}

	decodedCopySource, err := url.PathUnescape(pathPart)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header: malformed URL encoding",
		)
		return
	}

	srcBucket, srcKey := extractBucketAndKey(decodedCopySource)
	if srcBucket == "" || srcKey == "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header",
		)
		return
	}

	// Check bucket policy on source bucket (GetObject)
	if !h.checkAccess(r, srcBucket, "s3:GetObject", srcKey) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}
	// Check bucket policy on destination bucket (PutObject)
	if !h.checkAccess(r, dstBucket, "s3:PutObject", dstKey) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	// Get metadata directive
	metadataDirective := r.Header.Get("x-amz-metadata-directive")
	if metadataDirective == "" {
		metadataDirective = "COPY"
	}

	// Evaluate copy source conditional headers if any are present
	if r.Header.Get("x-amz-copy-source-if-match") != "" ||
		r.Header.Get("x-amz-copy-source-if-none-match") != "" ||
		r.Header.Get("x-amz-copy-source-if-modified-since") != "" ||
		r.Header.Get("x-amz-copy-source-if-unmodified-since") != "" {
		var srcObj *backend.Object
		var err error
		if srcVersionId != "" {
			srcObj, err = h.backend.GetObjectVersion(srcBucket, srcKey, srcVersionId)
		} else {
			srcObj, err = h.backend.GetObject(srcBucket, srcKey)
		}
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else if errors.Is(err, backend.ErrVersionNotFound) {
				backend.WriteError(w, http.StatusNotFound, "NoSuchVersion", "The specified version does not exist.")
			} else {
				backend.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			}
			return
		}
		if srcObj.IsDeleteMarker {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
			return
		}

		condResult := evaluateCopySourceConditionals(r, srcObj)
		if condResult.ShouldReturn {
			backend.WriteError(
				w,
				condResult.StatusCode,
				"PreconditionFailed",
				"At least one of the pre-conditions you specified did not hold",
			)
			return
		}
	}

	// Extract Website Redirect Location header for copy
	websiteRedirect := r.Header.Get("x-amz-website-redirect-location")

	// Check for self-copy without REPLACE
	if srcBucket == dstBucket && srcKey == dstKey && metadataDirective != "REPLACE" &&
		websiteRedirect == "" &&
		r.Header.Get("x-amz-storage-class") == "" &&
		r.Header.Get("x-amz-server-side-encryption") == "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
		)
		return
	}

	// Get tagging directive
	taggingDirective := r.Header.Get("x-amz-tagging-directive")
	if taggingDirective == "" {
		taggingDirective = "COPY"
	}

	// Build copy options
	opts := backend.CopyObjectOptions{
		MetadataDirective: metadataDirective,
		TaggingDirective:  taggingDirective,
	}

	// If REPLACE, extract new metadata from request headers
	if metadataDirective == "REPLACE" {
		opts.ContentType = r.Header.Get("Content-Type")
		opts.Metadata = extractMetadata(r)
		opts.CacheControl = r.Header.Get("Cache-Control")
		opts.Expires = parseExpires(r.Header.Get("Expires"))
		opts.ContentEncoding = r.Header.Get("Content-Encoding")
		opts.ContentLanguage = r.Header.Get("Content-Language")
		opts.ContentDisposition = r.Header.Get("Content-Disposition")
	}

	// If tagging directive is REPLACE, extract new tags from request header
	if taggingDirective == "REPLACE" {
		opts.Tags = parseTaggingHeader(r.Header.Get("x-amz-tagging"))
	}

	// Extract Object Lock headers
	if lockMode := r.Header.Get("x-amz-object-lock-mode"); lockMode != "" {
		opts.RetentionMode = lockMode
	}
	if retainUntil := r.Header.Get("x-amz-object-lock-retain-until-date"); retainUntil != "" {
		t, err := time.Parse(time.RFC3339, retainUntil)
		if err == nil {
			opts.RetainUntilDate = &t
		}
	}
	if legalHold := r.Header.Get("x-amz-object-lock-legal-hold"); legalHold != "" {
		opts.LegalHoldStatus = legalHold
	}

	// Extract Server-Side Encryption headers
	if sse := r.Header.Get("x-amz-server-side-encryption"); sse != "" {
		opts.ServerSideEncryption = sse
	}
	if sseKmsKeyId := r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"); sseKmsKeyId != "" {
		opts.SSEKMSKeyId = sseKmsKeyId
	}
	// SSE-C headers
	if sseCA := r.Header.Get("x-amz-server-side-encryption-customer-algorithm"); sseCA != "" {
		opts.SSECustomerAlgorithm = sseCA
	}
	if sseCKMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5"); sseCKMD5 != "" {
		opts.SSECustomerKeyMD5 = sseCKMD5
	}

	// Extract Storage Class header
	if storageClass := r.Header.Get("x-amz-storage-class"); storageClass != "" {
		opts.StorageClass = storageClass
	}

	// Set Website Redirect Location
	if websiteRedirect != "" {
		opts.WebsiteRedirectLocation = websiteRedirect
	}

	// Extract Checksum Algorithm
	if checksumAlgo := r.Header.Get("x-amz-checksum-algorithm"); checksumAlgo != "" {
		opts.ChecksumAlgorithm = checksumAlgo
	}

	requestOwner := requesterOwner(r)
	bucketOwner := h.bucketOwner(dstBucket)
	dstOwnership := backend.ObjectOwnershipObjectWriter
	if bucket, ok := h.backend.GetBucket(dstBucket); ok && bucket.ObjectOwnership != "" {
		dstOwnership = bucket.ObjectOwnership
	}
	grantHeadersPresent := r.Header.Get("x-amz-grant-full-control") != "" ||
		r.Header.Get("x-amz-grant-read") != "" ||
		r.Header.Get("x-amz-grant-write") != "" ||
		r.Header.Get("x-amz-grant-read-acp") != "" ||
		r.Header.Get("x-amz-grant-write-acp") != ""
	if strings.EqualFold(dstOwnership, backend.ObjectOwnershipBucketOwnerEnforced) &&
		(grantHeadersPresent ||
			(r.Header.Get("x-amz-acl") != "" &&
				!strings.EqualFold(r.Header.Get("x-amz-acl"), string(backend.ACLBucketOwnerFull)))) {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"AccessControlListNotSupported",
			"The bucket does not allow ACLs",
		)
		return
	}
	aclOwner := requestOwner
	switch dstOwnership {
	case backend.ObjectOwnershipBucketOwnerEnforced:
		aclOwner = bucketOwner
	case backend.ObjectOwnershipBucketOwnerPreferred:
		if strings.EqualFold(r.Header.Get("x-amz-acl"), string(backend.ACLBucketOwnerFull)) {
			aclOwner = bucketOwner
		}
	}
	requestedACL := backend.NewDefaultACLForOwner(aclOwner)
	headerACL, aclErr := aclFromGrantHeaders(r, requestOwner)
	if aclErr != nil {
		backend.WriteError(w, http.StatusBadRequest, aclErr.code, aclErr.message)
		return
	}
	if headerACL != nil {
		requestedACL = headerACL
	} else if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
		requestedACL = backend.CannedACLToPolicyForOwner(cannedACL, aclOwner, bucketOwner)
	}
	config := h.getBucketPublicAccessBlock(dstBucket)
	if config != nil && config.BlockPublicAcls && isPublicACL(requestedACL) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	obj, srcVersionIdUsed, err := copyObjectFn(
		h,
		srcBucket,
		srcKey,
		srcVersionId,
		dstBucket,
		dstKey,
		opts,
	)
	if err != nil {
		if errors.Is(err, backend.ErrSourceBucketNotFound) ||
			errors.Is(err, backend.ErrDestinationBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrSourceObjectNotFound) {
			backend.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		} else if errors.Is(err, backend.ErrVersionNotFound) {
			backend.WriteError(w, http.StatusNotFound, "NoSuchVersion", "The specified version does not exist.")
		} else if errors.Is(err, backend.ErrInvalidRequest) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}
	if !strings.EqualFold(dstOwnership, backend.ObjectOwnershipBucketOwnerEnforced) {
		if err := putObjectACLFn(h, dstBucket, dstKey, obj.VersionId, requestedACL); err != nil {
			if errors.Is(err, backend.ErrAccessControlListNotSupported) {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"AccessControlListNotSupported",
					"The bucket does not allow ACLs",
				)
			} else {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}
	}

	// Add source version ID header if specified
	if srcVersionIdUsed != "" && srcVersionIdUsed != backend.NullVersionId {
		w.Header().Set("x-amz-copy-source-version-id", srcVersionIdUsed)
	}

	// Add destination version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}
	// Return SSE headers
	setStorageAndEncryptionHeaders(w, obj)

	resp := backend.CopyObjectResult{
		ETag:         obj.ETag,
		LastModified: obj.LastModified.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleGetObjectACL handles GetObjectAcl requests.
func (h *Handler) handleGetObjectACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	if !h.checkAccessWithContext(r, bucketName, "s3:GetObjectAcl", key, backend.PolicyEvalContext{
		ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionId),
	}) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	acl, err := getObjectACLFn(h, bucketName, key, versionId)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrObjectNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
		} else if errors.Is(err, backend.ErrVersionNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchVersion",
				"The specified version does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config := h.getBucketPublicAccessBlock(bucketName)
	ignorePublicACLs := config != nil && config.IgnorePublicAcls
	acl = effectiveACLForResponse(acl, ignorePublicACLs)

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(acl)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectACL handles PutObjectAcl requests.
func (h *Handler) handlePutObjectACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	if !h.checkAccess(r, bucketName, "s3:PutObjectAcl", key) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	versionId := r.URL.Query().Get("versionId")
	config := h.getBucketPublicAccessBlock(bucketName)

	// Check for canned ACL header first
	cannedACL := r.Header.Get("x-amz-acl")
	if cannedACL != "" {
		requestOwner := requesterOwner(r)
		bucketOwner := h.bucketOwner(bucketName)
		acl := backend.CannedACLToPolicyForOwner(cannedACL, requestOwner, bucketOwner)
		if config != nil && config.BlockPublicAcls && isPublicACL(acl) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		if err := h.backend.PutObjectACL(bucketName, key, versionId, acl); err != nil {
			h.writePutObjectACLError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse ACL from request body
	defer func() { _ = r.Body.Close() }()
	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(body, &acl); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedACLError",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	skipACLValidation := false
	if acl.Owner == nil && len(acl.AccessControlList.Grants) == 0 {
		owner := requesterOwner(r)
		if owner == nil {
			owner = h.bucketOwner(bucketName)
		}
		defaultACL := backend.NewDefaultACLForOwner(owner)
		if defaultACL != nil {
			acl = *defaultACL
			skipACLValidation = true
		}
	} else if acl.Owner == nil || acl.Owner.ID == "" {
		acl.Owner = requesterOwner(r)
	}
	if !skipACLValidation {
		if aclErr := normalizeAndValidateACL(&acl); aclErr != nil {
			backend.WriteError(w, http.StatusBadRequest, aclErr.code, aclErr.message)
			return
		}
	}
	if config != nil && config.BlockPublicAcls && isPublicACL(&acl) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	if err := h.backend.PutObjectACL(bucketName, key, versionId, &acl); err != nil {
		h.writePutObjectACLError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// writePutObjectACLError writes the appropriate error response for PutObjectACL.
func (h *Handler) writePutObjectACLError(w http.ResponseWriter, err error) {
	if errors.Is(err, backend.ErrBucketNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
	} else if errors.Is(err, backend.ErrObjectNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchKey",
			"The specified key does not exist.",
		)
	} else if errors.Is(err, backend.ErrVersionNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchVersion",
			"The specified version does not exist.",
		)
	} else if errors.Is(err, backend.ErrAccessControlListNotSupported) {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"AccessControlListNotSupported",
			"The bucket does not allow ACLs",
		)
	} else {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
	}
}

// handleGetObjectTagging handles GetObjectTagging requests.
func (h *Handler) handleGetObjectTagging(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	if !h.checkAccessWithContext(
		r,
		bucketName,
		"s3:GetObjectTagging",
		key,
		backend.PolicyEvalContext{
			ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionId),
		},
	) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	tags, actualVersionId, err := h.backend.GetObjectTagging(bucketName, key, versionId)
	if err != nil {
		h.writeObjectTaggingError(w, err)
		return
	}

	// Set version ID header if applicable
	if actualVersionId != "" && actualVersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", actualVersionId)
	}

	// Build response (sort keys for deterministic output)
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tagSet := make([]backend.Tag, 0, len(tags))
	for _, k := range keys {
		tagSet = append(tagSet, backend.Tag{Key: k, Value: tags[k]})
	}

	resp := backend.Tagging{
		Xmlns:  backend.S3Xmlns,
		TagSet: tagSet,
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectTagging handles PutObjectTagging requests.
func (h *Handler) handlePutObjectTagging(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")

	defer func() { _ = r.Body.Close() }()
	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}

	var tagging backend.Tagging
	if err := xml.Unmarshal(body, &tagging); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	// Validate tag limits
	if errCode, errMsg := validateTagSet(tagging.TagSet); errCode != "" {
		backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
		return
	}

	// Convert TagSet to map
	tags := make(map[string]string, len(tagging.TagSet))
	for _, tag := range tagging.TagSet {
		tags[tag.Key] = tag.Value
	}

	if !h.checkAccessWithContext(
		r,
		bucketName,
		"s3:PutObjectTagging",
		key,
		backend.PolicyEvalContext{
			ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionId),
			RequestObjectTags:  tags,
		},
	) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	actualVersionId, err := h.backend.PutObjectTagging(bucketName, key, versionId, tags)
	if err != nil {
		h.writeObjectTaggingError(w, err)
		return
	}

	// Set version ID header if applicable
	if actualVersionId != "" && actualVersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", actualVersionId)
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteObjectTagging handles DeleteObjectTagging requests.
func (h *Handler) handleDeleteObjectTagging(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	actualVersionId, err := h.backend.DeleteObjectTagging(bucketName, key, versionId)
	if err != nil {
		h.writeObjectTaggingError(w, err)
		return
	}

	// Set version ID header if applicable
	if actualVersionId != "" && actualVersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", actualVersionId)
	}

	w.WriteHeader(http.StatusNoContent)
}

// writeObjectTaggingError writes the appropriate error response for Object Tagging operations.
func (h *Handler) writeObjectTaggingError(w http.ResponseWriter, err error) {
	if errors.Is(err, backend.ErrBucketNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
	} else if errors.Is(err, backend.ErrObjectNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchKey",
			"The specified key does not exist.",
		)
	} else if errors.Is(err, backend.ErrVersionNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchVersion",
			"The specified version does not exist.",
		)
	} else {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
	}
}

// handleGetObjectAttributes handles GetObjectAttributes requests.
func (h *Handler) handleGetObjectAttributes(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	if !h.checkAccess(r, bucketName, "s3:GetObject", key) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}
	versionId := r.URL.Query().Get("versionId")

	// Get the requested attributes from header
	attributesHeader := r.Header.Get("x-amz-object-attributes")
	if attributesHeader == "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"x-amz-object-attributes header is required.",
		)
		return
	}

	// Parse requested attributes
	requestedAttrs := make(map[string]bool)
	validAttr := map[string]bool{
		"ETag": true, "Checksum": true, "ObjectSize": true, "StorageClass": true, "ObjectParts": true,
	}
	for _, attr := range strings.Split(attributesHeader, ",") {
		trimmed := strings.TrimSpace(attr)
		if trimmed == "" || !validAttr[trimmed] {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"Invalid object attributes value.",
			)
			return
		}
		requestedAttrs[trimmed] = true
	}

	// Get object
	var obj *backend.Object
	var err error

	if versionId != "" {
		obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
	} else {
		obj, err = h.backend.GetObject(bucketName, key)
	}

	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrVersionNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchVersion",
				"The specified version does not exist.",
			)
		} else {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
		}
		return
	}

	// Check if this is a DeleteMarker
	if obj.IsDeleteMarker {
		w.Header().Set("x-amz-delete-marker", "true")
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchKey",
			"The specified key does not exist.",
		)
		return
	}
	if validateSSECAccess(w, r, obj) {
		return
	}
	maxParts := 1000
	if requestedAttrs["ObjectParts"] {
		maxPartsRaw := r.URL.Query().Get("max-parts")
		if maxPartsRaw == "" {
			maxPartsRaw = strings.TrimSpace(r.Header.Get("x-amz-max-parts"))
		}
		if maxPartsRaw != "" {
			parsed, parseErr := strconv.Atoi(maxPartsRaw)
			if parseErr != nil || parsed < 0 {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"InvalidArgument",
					"max-parts must be a non-negative integer.",
				)
				return
			}
			maxParts = parsed
		}
	}
	partNumberMarker := 0
	if requestedAttrs["ObjectParts"] {
		markerRaw := r.URL.Query().Get("part-number-marker")
		if markerRaw == "" {
			markerRaw = strings.TrimSpace(r.Header.Get("x-amz-part-number-marker"))
		}
		if markerRaw != "" {
			parsed, parseErr := strconv.Atoi(markerRaw)
			if parseErr != nil || parsed < 0 {
				backend.WriteError(
					w,
					http.StatusBadRequest,
					"InvalidArgument",
					"part-number-marker must be a non-negative integer.",
				)
				return
			}
			partNumberMarker = parsed
		}
	}

	// Build response based on requested attributes
	resp := backend.GetObjectAttributesResponse{
		Xmlns: backend.S3Xmlns,
	}

	if requestedAttrs["ETag"] {
		resp.ETag = strings.Trim(obj.ETag, "\"")
	}

	if requestedAttrs["Checksum"] {
		resp.Checksum = &backend.GetObjectAttributesChecksum{
			ChecksumType:      obj.ChecksumType,
			ChecksumCRC32:     obj.ChecksumCRC32,
			ChecksumCRC32C:    obj.ChecksumCRC32C,
			ChecksumCRC64NVME: obj.ChecksumCRC64NVME,
			ChecksumSHA1:      obj.ChecksumSHA1,
			ChecksumSHA256:    obj.ChecksumSHA256,
		}
	}

	if requestedAttrs["ObjectSize"] {
		resp.ObjectSize = &obj.Size
	}

	if requestedAttrs["StorageClass"] {
		storageClass := obj.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		resp.StorageClass = storageClass
	}
	if requestedAttrs["ObjectParts"] && len(obj.Parts) > 0 {
		total := len(obj.Parts)
		objectParts := &backend.GetObjectAttributesObjectParts{
			PartNumberMarker: partNumberMarker,
			MaxParts:         maxParts,
			PartsCount:       total,
			TotalPartsCount:  total,
		}
		start := 0
		for start < total && obj.Parts[start].PartNumber <= partNumberMarker {
			start++
		}
		end := start + maxParts
		if maxParts == 0 {
			end = start
		}
		if end > total {
			end = total
		}
		objectParts.IsTruncated = end < total
		if objectParts.IsTruncated && end > start {
			objectParts.NextPartNumberMarker = obj.Parts[end-1].PartNumber
		}

		offset := int64(0)
		for i, p := range obj.Parts {
			if i < start {
				offset += p.Size
				continue
			}
			if i >= end {
				break
			}
			partDataStart := offset
			partDataEnd := offset + p.Size
			if partDataStart < 0 || partDataEnd > int64(len(obj.Data)) {
				partDataStart = 0
				partDataEnd = 0
			}
			checksumItem := computePartChecksums(
				obj.Data[partDataStart:partDataEnd],
				obj.ChecksumAlgorithm,
			)
			checksumItem.PartNumber = p.PartNumber
			checksumItem.Size = p.Size
			if p.ChecksumCRC32 != "" {
				checksumItem.ChecksumCRC32 = p.ChecksumCRC32
			}
			if p.ChecksumCRC32C != "" {
				checksumItem.ChecksumCRC32C = p.ChecksumCRC32C
			}
			if p.ChecksumCRC64NVME != "" {
				checksumItem.ChecksumCRC64NVME = p.ChecksumCRC64NVME
			}
			if p.ChecksumSHA1 != "" {
				checksumItem.ChecksumSHA1 = p.ChecksumSHA1
			}
			if p.ChecksumSHA256 != "" {
				checksumItem.ChecksumSHA256 = p.ChecksumSHA256
			}
			objectParts.Parts = append(objectParts.Parts, checksumItem)
			offset += p.Size
		}
		resp.ObjectParts = objectParts
	}

	// Set version ID header
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleRestoreObject handles POST /{key}?restore requests.
func (h *Handler) handleRestoreObject(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	if !h.checkAccess(r, bucketName, "s3:RestoreObject", key) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	versionId := r.URL.Query().Get("versionId")

	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}

	var restoreReq backend.RestoreRequest
	if len(body) > 0 {
		if xmlErr := xml.Unmarshal(body, &restoreReq); xmlErr != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema.",
			)
			return
		}
	}

	result, err := h.backend.RestoreObject(bucketName, key, versionId, restoreReq.Days)
	if err != nil {
		switch {
		case errors.Is(err, backend.ErrBucketNotFound):
			backend.WriteError(w, http.StatusNotFound, "NoSuchBucket",
				"The specified bucket does not exist.")
		case errors.Is(err, backend.ErrObjectNotFound):
			backend.WriteError(w, http.StatusNotFound, "NoSuchKey",
				"The specified key does not exist.")
		case errors.Is(err, backend.ErrVersionNotFound):
			backend.WriteError(w, http.StatusNotFound, "NoSuchVersion",
				"The specified version does not exist.")
		case errors.Is(err, backend.ErrInvalidObjectState):
			backend.WriteError(w, http.StatusForbidden, "InvalidObjectState",
				"The operation is not valid for the object's storage class.")
		default:
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(result.StatusCode)
}
