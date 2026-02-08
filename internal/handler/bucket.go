package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

var (
	getBucketACLFn = func(
		h *Handler,
		bucketName string,
	) (*backend.AccessControlPolicy, error) {
		return h.backend.GetBucketACL(bucketName)
	}
	createBucketWithObjectLockFn = func(h *Handler, bucketName string) error {
		return h.backend.CreateBucketWithObjectLock(bucketName)
	}
	createBucketFn = func(h *Handler, bucketName string) error {
		return h.backend.CreateBucket(bucketName)
	}
	putBucketACLFn = func(
		h *Handler,
		bucketName string,
		acl *backend.AccessControlPolicy,
	) error {
		return h.backend.PutBucketACL(bucketName, acl)
	}
	deleteBucketFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucket(bucketName)
	}
	getBucketUsageFn = func(h *Handler, bucketName string) (int, int64, error) {
		return h.backend.GetBucketUsage(bucketName)
	}
	postObjectPutFn = func(
		h *Handler,
		bucketName, key string,
		body []byte,
		opts backend.PutObjectOptions,
	) (*backend.Object, error) {
		return h.backend.PutObject(bucketName, key, body, opts)
	}
	postObjectPutACLFn = func(
		h *Handler,
		bucketName, key, versionID string,
		acl *backend.AccessControlPolicy,
	) error {
		return h.backend.PutObjectACL(bucketName, key, versionID, acl)
	}
	setBucketVersioningFn = func(
		h *Handler,
		bucketName string,
		status backend.VersioningStatus,
		mfaDelete backend.MFADeleteStatus,
	) error {
		return h.backend.SetBucketVersioning(bucketName, status, mfaDelete)
	}
	getBucketLocationFn = func(h *Handler, bucketName string) (string, error) {
		return h.backend.GetBucketLocation(bucketName)
	}
	getBucketTaggingFn = func(h *Handler, bucketName string) (map[string]string, error) {
		return h.backend.GetBucketTagging(bucketName)
	}
	putBucketTaggingFn = func(h *Handler, bucketName string, tags map[string]string) error {
		return h.backend.PutBucketTagging(bucketName, tags)
	}
	deleteBucketTaggingFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketTagging(bucketName)
	}
	getBucketPolicyFn = func(h *Handler, bucketName string) (string, error) {
		return h.backend.GetBucketPolicy(bucketName)
	}
	putBucketPolicyFn = func(h *Handler, bucketName, policy string) error {
		return h.backend.PutBucketPolicy(bucketName, policy)
	}
	deleteBucketPolicyFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketPolicy(bucketName)
	}
	getBucketLifecycleConfigurationFn = func(
		h *Handler,
		bucketName string,
	) (*backend.LifecycleConfiguration, error) {
		return h.backend.GetBucketLifecycleConfiguration(bucketName)
	}
	putBucketLifecycleConfigurationFn = func(
		h *Handler,
		bucketName string,
		config *backend.LifecycleConfiguration,
	) error {
		return h.backend.PutBucketLifecycleConfiguration(bucketName, config)
	}
	deleteBucketLifecycleConfigurationFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketLifecycleConfiguration(bucketName)
	}
	getBucketEncryptionFn = func(
		h *Handler,
		bucketName string,
	) (*backend.ServerSideEncryptionConfiguration, error) {
		return h.backend.GetBucketEncryption(bucketName)
	}
	putBucketEncryptionFn = func(
		h *Handler,
		bucketName string,
		config *backend.ServerSideEncryptionConfiguration,
	) error {
		return h.backend.PutBucketEncryption(bucketName, config)
	}
	deleteBucketEncryptionFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketEncryption(bucketName)
	}
	getBucketCORSFn = func(h *Handler, bucketName string) (*backend.CORSConfiguration, error) {
		return h.backend.GetBucketCORS(bucketName)
	}
	putBucketCORSFn = func(
		h *Handler,
		bucketName string,
		config *backend.CORSConfiguration,
	) error {
		return h.backend.PutBucketCORS(bucketName, config)
	}
	deleteBucketCORSFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketCORS(bucketName)
	}
	getBucketWebsiteFn = func(
		h *Handler,
		bucketName string,
	) (*backend.WebsiteConfiguration, error) {
		return h.backend.GetBucketWebsite(bucketName)
	}
	putBucketWebsiteFn = func(
		h *Handler,
		bucketName string,
		config *backend.WebsiteConfiguration,
	) error {
		return h.backend.PutBucketWebsite(bucketName, config)
	}
	deleteBucketWebsiteFn = func(h *Handler, bucketName string) error {
		return h.backend.DeleteBucketWebsite(bucketName)
	}
	getPublicAccessBlockFn = func(
		h *Handler,
		bucketName string,
	) (*backend.PublicAccessBlockConfiguration, error) {
		return h.backend.GetPublicAccessBlock(bucketName)
	}
	putPublicAccessBlockFn = func(
		h *Handler,
		bucketName string,
		config *backend.PublicAccessBlockConfiguration,
	) error {
		return h.backend.PutPublicAccessBlock(bucketName, config)
	}
	deletePublicAccessBlockFn = func(h *Handler, bucketName string) error {
		return h.backend.DeletePublicAccessBlock(bucketName)
	}
)

func isAnonymousRequest(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	query := r.URL.Query()
	if query.Has("X-Amz-Signature") || query.Has("Signature") || query.Has("AWSAccessKeyId") {
		return false
	}
	return true
}

func parseMultipartFormFields(r *http.Request) map[string]string {
	fields := make(map[string]string)
	if r.MultipartForm == nil {
		return fields
	}

	for k, values := range r.MultipartForm.Value {
		if len(values) > 0 {
			fields[strings.ToLower(k)] = values[0]
		}
	}

	for k, files := range r.MultipartForm.File {
		lowerKey := strings.ToLower(k)
		if lowerKey == "file" || len(files) == 0 {
			continue
		}
		if _, exists := fields[lowerKey]; exists {
			continue
		}
		f, err := files[0].Open()
		if err != nil {
			continue
		}
		valueBytes, err := readAllFn(io.LimitReader(f, 1<<20))
		_ = f.Close()
		if err != nil {
			continue
		}
		fields[lowerKey] = string(valueBytes)
	}

	return fields
}

func getMultipartFormValue(fields map[string]string, name string) string {
	return fields[strings.ToLower(name)]
}

func resolvePostObjectFormKey(rawKey, fileName string) (string, bool) {
	if rawKey == "" {
		return "", false
	}
	key := strings.ReplaceAll(rawKey, "${filename}", fileName)
	if key == "" {
		return "", false
	}
	return key, true
}

func parsePolicyInt64(v any) (int64, bool) {
	switch value := v.(type) {
	case float64:
		if value < 0 || value != float64(int64(value)) {
			return 0, false
		}
		return int64(value), true
	case int64:
		if value < 0 {
			return 0, false
		}
		return value, true
	case int:
		if value < 0 {
			return 0, false
		}
		return int64(value), true
	default:
		return 0, false
	}
}

func resolvePostPolicyFieldValue(
	fieldName, bucketName, key, contentType string,
	formFields map[string]string,
) string {
	fieldName = normalizePostPolicyFieldName(fieldName)
	switch fieldName {
	case "bucket":
		return bucketName
	case "key":
		return key
	case "content-type":
		return contentType
	default:
		return formFields[fieldName]
	}
}

func normalizePostPolicyFieldName(fieldName string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(fieldName), "$"))
}

func postPolicyFieldConditionExempt(fieldName string) bool {
	switch fieldName {
	case "", "file", "policy", "x-amz-signature", "signature", "awsaccesskeyid":
		return true
	default:
		return strings.HasPrefix(fieldName, "x-ignore-")
	}
}

func startsWithPostPolicyValue(fieldName, actual, expected string) bool {
	if fieldName == "content-type" && strings.Contains(actual, ",") {
		for _, part := range strings.Split(actual, ",") {
			if !strings.HasPrefix(strings.TrimSpace(part), expected) {
				return false
			}
		}
		return true
	}
	return strings.HasPrefix(actual, expected)
}

func validatePostPolicy(
	policyB64, bucketName, key, contentType string,
	formFields map[string]string,
	objectSize int64,
) (int, bool) {
	policyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(policyB64))
	if err != nil {
		return http.StatusBadRequest, false
	}

	var policy map[string]any
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		return http.StatusBadRequest, false
	}

	expirationRaw, hasExpiration := policy["expiration"]
	conditionsRaw, hasConditions := policy["conditions"]
	if !hasExpiration || !hasConditions {
		return http.StatusBadRequest, false
	}

	expirationStr, ok := expirationRaw.(string)
	if !ok {
		return http.StatusBadRequest, false
	}
	expiration, err := time.Parse("2006-01-02T15:04:05Z", expirationStr)
	if err != nil {
		return http.StatusBadRequest, false
	}
	if time.Now().UTC().After(expiration) {
		return http.StatusForbidden, false
	}

	conditions, ok := conditionsRaw.([]any)
	if !ok || len(conditions) == 0 {
		return http.StatusBadRequest, false
	}

	hasBucketCondition := false
	conditionFields := make(map[string]struct{})
	for _, conditionRaw := range conditions {
		switch condition := conditionRaw.(type) {
		case map[string]any:
			if len(condition) == 0 {
				return http.StatusBadRequest, false
			}
			for condKey, condExpectedRaw := range condition {
				condExpected, ok := condExpectedRaw.(string)
				if !ok {
					return http.StatusBadRequest, false
				}
				fieldName := normalizePostPolicyFieldName(condKey)
				conditionFields[fieldName] = struct{}{}
				actual := resolvePostPolicyFieldValue(
					condKey,
					bucketName,
					key,
					contentType,
					formFields,
				)
				if fieldName == "bucket" {
					hasBucketCondition = true
				}
				if actual != condExpected {
					return http.StatusForbidden, false
				}
			}
		case []any:
			if len(condition) == 0 {
				return http.StatusBadRequest, false
			}
			opRaw, ok := condition[0].(string)
			if !ok {
				return http.StatusBadRequest, false
			}
			switch strings.ToLower(opRaw) {
			case "eq", "starts-with":
				if len(condition) != 3 {
					return http.StatusBadRequest, false
				}
				fieldRaw, ok := condition[1].(string)
				if !ok {
					return http.StatusBadRequest, false
				}
				expected, ok := condition[2].(string)
				if !ok {
					return http.StatusBadRequest, false
				}
				fieldName := normalizePostPolicyFieldName(fieldRaw)
				conditionFields[fieldName] = struct{}{}
				if fieldName == "bucket" {
					hasBucketCondition = true
				}
				actual := resolvePostPolicyFieldValue(
					fieldName,
					bucketName,
					key,
					contentType,
					formFields,
				)
				if strings.EqualFold(opRaw, "eq") {
					if actual != expected {
						return http.StatusForbidden, false
					}
				} else if !startsWithPostPolicyValue(fieldName, actual, expected) {
					return http.StatusForbidden, false
				}
			case "content-length-range":
				if len(condition) != 3 {
					return http.StatusBadRequest, false
				}
				minSize, ok := parsePolicyInt64(condition[1])
				if !ok {
					return http.StatusBadRequest, false
				}
				maxSize, ok := parsePolicyInt64(condition[2])
				if !ok || maxSize < minSize {
					return http.StatusBadRequest, false
				}
				if objectSize < minSize || objectSize > maxSize {
					return http.StatusBadRequest, false
				}
			default:
				return http.StatusBadRequest, false
			}
		default:
			return http.StatusBadRequest, false
		}
	}

	if !hasBucketCondition {
		return http.StatusForbidden, false
	}

	for formField := range formFields {
		fieldName := normalizePostPolicyFieldName(formField)
		if postPolicyFieldConditionExempt(fieldName) {
			continue
		}
		if _, ok := conditionFields[fieldName]; !ok {
			return http.StatusForbidden, false
		}
	}

	return 0, true
}

func extractPostFormMetadata(formFields map[string]string) map[string]string {
	metadata := make(map[string]string)
	for k, v := range formFields {
		if strings.HasPrefix(k, "x-amz-meta-") {
			metaKey := strings.TrimPrefix(k, "x-amz-meta-")
			if metaKey != "" {
				metadata[metaKey] = v
			}
		}
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

func parsePostTaggingXML(taggingXML string) (map[string]string, string, string) {
	var tagging backend.Tagging
	if err := xml.Unmarshal([]byte(taggingXML), &tagging); err != nil {
		return nil, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema."
	}

	if errCode, errMsg := validateTagSet(tagging.TagSet); errCode != "" {
		return nil, errCode, errMsg
	}

	tags := make(map[string]string, len(tagging.TagSet))
	for _, tag := range tagging.TagSet {
		tags[tag.Key] = tag.Value
	}
	if len(tags) == 0 {
		return nil, "", ""
	}
	return tags, "", ""
}

func validatePostObjectChecksums(
	formFields map[string]string,
	body []byte,
	opts *backend.PutObjectOptions,
) bool {
	if checksum := formFields["x-amz-checksum-crc32"]; checksum != "" {
		sum := crc32.ChecksumIEEE(body)
		computed := base64.StdEncoding.EncodeToString([]byte{
			byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
		})
		if computed != checksum {
			return false
		}
		opts.ChecksumAlgorithm = "CRC32"
		opts.ChecksumCRC32 = checksum
	}

	if checksum := formFields["x-amz-checksum-crc32c"]; checksum != "" {
		table := crc32.MakeTable(crc32.Castagnoli)
		sum := crc32.Checksum(body, table)
		computed := base64.StdEncoding.EncodeToString([]byte{
			byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
		})
		if computed != checksum {
			return false
		}
		opts.ChecksumAlgorithm = "CRC32C"
		opts.ChecksumCRC32C = checksum
	}

	if checksum := formFields["x-amz-checksum-sha1"]; checksum != "" {
		sum := sha1.Sum(body)
		computed := base64.StdEncoding.EncodeToString(sum[:])
		if computed != checksum {
			return false
		}
		opts.ChecksumAlgorithm = "SHA1"
		opts.ChecksumSHA1 = checksum
	}

	if checksum := formFields["x-amz-checksum-sha256"]; checksum != "" {
		sum := sha256.Sum256(body)
		computed := base64.StdEncoding.EncodeToString(sum[:])
		if computed != checksum {
			return false
		}
		opts.ChecksumAlgorithm = "SHA256"
		opts.ChecksumSHA256 = checksum
	}

	return true
}

func verifyPostPolicySignature(accessKey, signature, policy string) bool {
	if accessKey == "" {
		return true
	}
	credentials := DefaultCredentials()
	secretKey, ok := credentials[accessKey]
	if !ok {
		return false
	}
	signature = strings.TrimSpace(signature)
	policy = strings.TrimSpace(policy)
	if signature == "" || policy == "" {
		return false
	}

	mac := hmac.New(sha1.New, []byte(secretKey))
	_, _ = mac.Write([]byte(policy))
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSig))
}

// s3URLEncode encodes a string for S3's encoding-type=url responses.
// S3 preserves only unreserved characters (RFC 3986): A-Z a-z 0-9 - . _ ~
// plus '/' which is kept as a path separator. All other characters are percent-encoded.
func s3URLEncode(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' || c == '/' {
			buf.WriteByte(c)
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

// parseOptionalObjectAttributes parses the x-amz-optional-object-attributes header
// and returns a map of requested attribute names.
func parseOptionalObjectAttributes(r *http.Request) map[string]bool {
	attrs := make(map[string]bool)
	header := r.Header.Get("x-amz-optional-object-attributes")
	if header == "" {
		return attrs
	}
	for _, attr := range strings.Split(header, ",") {
		attrs[strings.TrimSpace(attr)] = true
	}
	return attrs
}

// handleBucket handles bucket-level operations.
func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Handle ACL operations
	if r.URL.Query().Has("acl") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetBucketACL(w, r, bucketName)
		case http.MethodPut:
			h.handlePutBucketACL(w, r, bucketName)
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

	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Has("versioning") {
			h.handleGetBucketVersioning(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("versions") {
			h.handleListObjectVersions(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("location") {
			h.handleGetBucketLocation(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("tagging") {
			h.handleGetBucketTagging(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("policy") {
			h.handleGetBucketPolicy(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("policyStatus") {
			h.handleGetBucketPolicyStatus(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("uploads") {
			h.handleListMultipartUploads(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("object-lock") {
			h.handleGetObjectLockConfiguration(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("lifecycle") {
			h.handleGetBucketLifecycleConfiguration(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("encryption") {
			h.handleGetBucketEncryption(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("cors") {
			h.handleGetBucketCORS(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("website") {
			h.handleGetBucketWebsite(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("publicAccessBlock") {
			h.handleGetPublicAccessBlock(w, r, bucketName)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			h.handleListObjectsV2(w, r, bucketName)
			return
		}
		h.handleListObjectsV1(w, r, bucketName)
	case http.MethodPost:
		if r.URL.Query().Has("delete") {
			h.handleDeleteObjects(w, r, bucketName)
			return
		}
		h.handlePostObjectFormUpload(w, r, bucketName)
	case http.MethodPut:
		if r.URL.Query().Has("versioning") {
			h.handlePutBucketVersioning(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("tagging") {
			h.handlePutBucketTagging(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("policy") {
			h.handlePutBucketPolicy(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("object-lock") {
			h.handlePutObjectLockConfiguration(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("lifecycle") {
			h.handlePutBucketLifecycleConfiguration(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("encryption") {
			h.handlePutBucketEncryption(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("cors") {
			h.handlePutBucketCORS(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("website") {
			h.handlePutBucketWebsite(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("publicAccessBlock") {
			h.handlePutPublicAccessBlock(w, r, bucketName)
			return
		}
		locationConstraint := ""

		// Parse CreateBucketConfiguration from request body if present
		if r.Body != nil && r.ContentLength > 0 {
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

			if len(body) > 0 {
				var config backend.CreateBucketConfiguration
				if err := xml.Unmarshal(body, &config); err != nil {
					backend.WriteError(
						w,
						http.StatusBadRequest,
						"MalformedXML",
						"The XML you provided was not well-formed or did not validate against our published schema.",
					)
					return
				}
				locationConstraint = strings.TrimSpace(config.LocationConstraint)
			}
		}

		// Check if Object Lock is requested
		requestAccessKey := extractAccessKey(r)
		if existing, exists := h.backend.GetBucket(bucketName); exists {
			// Same owner: idempotent success.
			if existing.OwnerAccessKey == requestAccessKey {
				// Re-create with ACL intent should fail to avoid ACL overwrite semantics.
				if r.Header.Get("x-amz-acl") != "" {
					backend.WriteError(
						w,
						http.StatusConflict,
						"BucketAlreadyExists",
						"The requested bucket name is not available.",
					)
					return
				}
				if acl, err := getBucketACLFn(h, bucketName); err == nil && isPublicACL(acl) {
					backend.WriteError(
						w,
						http.StatusConflict,
						"BucketAlreadyExists",
						"The requested bucket name is not available.",
					)
					return
				}
				w.Header().Set("Location", "/"+bucketName)
				w.WriteHeader(http.StatusOK)
				return
			}
			backend.WriteError(
				w,
				http.StatusConflict,
				"BucketAlreadyExists",
				"The requested bucket name is not available.",
			)
			return
		}

		var err error
		if r.Header.Get("x-amz-bucket-object-lock-enabled") == "true" {
			err = createBucketWithObjectLockFn(h, bucketName)
		} else {
			err = createBucketFn(h, bucketName)
		}
		if err != nil {
			if errors.Is(err, backend.ErrBucketAlreadyOwnedByYou) {
				// For compatibility with some S3-compatible suites in the default region,
				// treat CreateBucket on an already-owned bucket as idempotent success.
				w.Header().Set("Location", "/"+bucketName)
				w.WriteHeader(http.StatusOK)
			} else if errors.Is(err, backend.ErrBucketAlreadyExists) {
				backend.WriteError(w, http.StatusConflict, "BucketAlreadyExists", err.Error())
			} else if errors.Is(err, backend.ErrInvalidBucketName) {
				backend.WriteError(w, http.StatusBadRequest, "InvalidBucketName", err.Error())
			} else {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}

		if err := h.backend.SetBucketLocation(bucketName, locationConstraint); err != nil {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		// Set the owner access key
		h.backend.SetBucketOwner(bucketName, requestAccessKey)
		owner := backend.OwnerForAccessKey(requestAccessKey)
		requestedACL := backend.NewDefaultACLForOwner(owner)
		headerACL, aclErr := aclFromGrantHeaders(r, owner)
		if aclErr != nil {
			backend.WriteError(w, http.StatusBadRequest, aclErr.code, aclErr.message)
			return
		}
		if headerACL != nil {
			requestedACL = headerACL
		} else if cannedACL := r.Header.Get("x-amz-acl"); cannedACL != "" {
			requestedACL = backend.CannedACLToPolicyForOwner(cannedACL, owner, owner)
		}
		if err := putBucketACLFn(h, bucketName, requestedACL); err != nil {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		w.Header().Set("Location", "/"+bucketName)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if r.URL.Query().Has("tagging") {
			h.handleDeleteBucketTagging(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("policy") {
			h.handleDeleteBucketPolicy(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("lifecycle") {
			h.handleDeleteBucketLifecycleConfiguration(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("encryption") {
			h.handleDeleteBucketEncryption(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("cors") {
			h.handleDeleteBucketCORS(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("website") {
			h.handleDeleteBucketWebsite(w, r, bucketName)
			return
		}
		if r.URL.Query().Has("publicAccessBlock") {
			h.handleDeletePublicAccessBlock(w, r, bucketName)
			return
		}
		err := deleteBucketFn(h, bucketName)
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotEmpty) {
				backend.WriteError(w, http.StatusConflict, "BucketNotEmpty", err.Error())
			} else if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead:
		_, ok := h.backend.GetBucket(bucketName)
		if !ok {
			// S3 returns x-amz-bucket-region header even on 404
			w.Header().Set("x-amz-bucket-region", "us-east-1")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !h.checkAccess(r, bucketName, "s3:ListBucket", "") {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		// HeadBucket response headers per S3 API spec
		w.Header().Set("x-amz-bucket-region", "us-east-1")
		w.Header().Set("x-amz-access-point-alias", "false")
		if r.URL.Query().Get("read-stats") == "true" {
			objectCount, bytesUsed, err := getBucketUsageFn(h, bucketName)
			if err != nil {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
				return
			}
			w.Header().Set("X-RGW-Object-Count", strconv.Itoa(objectCount))
			w.Header().Set("X-RGW-Bytes-Used", strconv.FormatInt(bytesUsed, 10))
			w.Header().Set("X-RGW-Quota-Max-Buckets", "1000")
		}
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

func (h *Handler) handlePostObjectFormUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if _, ok := h.backend.GetBucket(bucketName); !ok {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		backend.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid multipart form")
		return
	}

	formFields := parseMultipartFormFields(r)

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		backend.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Missing file field")
		return
	}
	defer func() { _ = file.Close() }()

	body, err := readAllFn(file)
	if err != nil {
		backend.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Failed to read file")
		return
	}

	key, ok := resolvePostObjectFormKey(
		getMultipartFormValue(formFields, "key"),
		fileHeader.Filename,
	)
	if !ok {
		backend.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Missing key field")
		return
	}

	contentType := getMultipartFormValue(formFields, "Content-Type")
	if contentType == "" {
		contentType = fileHeader.Header.Get("Content-Type")
	}

	accessKey := strings.TrimSpace(getMultipartFormValue(formFields, "AWSAccessKeyId"))
	signature := strings.TrimSpace(getMultipartFormValue(formFields, "signature"))
	policy := strings.TrimSpace(getMultipartFormValue(formFields, "policy"))
	if accessKey != "" || signature != "" || policy != "" {
		if accessKey == "" || signature == "" || policy == "" {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"Missing required POST policy fields",
			)
			return
		}
		if !verifyPostPolicySignature(accessKey, signature, policy) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		statusCode, ok := validatePostPolicy(
			policy,
			bucketName,
			key,
			contentType,
			formFields,
			int64(len(body)),
		)
		if !ok {
			if statusCode == http.StatusForbidden {
				backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			} else {
				backend.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid policy document")
			}
			return
		}
	}

	opts := backend.PutObjectOptions{
		ContentType: contentType,
		Metadata:    extractPostFormMetadata(formFields),
	}
	if taggingXML := getMultipartFormValue(formFields, "tagging"); taggingXML != "" {
		tags, errCode, errMsg := parsePostTaggingXML(taggingXML)
		if errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}
		opts.Tags = tags
	}
	if !validatePostObjectChecksums(formFields, body, &opts) {
		backend.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Checksum validation failed")
		return
	}

	obj, err := postObjectPutFn(h, bucketName, key, body, opts)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		}
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}

	requestOwner := requesterOwner(r)
	objectACL := backend.NewDefaultACLForOwner(requestOwner)
	if acl := getMultipartFormValue(formFields, "acl"); acl != "" {
		objectACL = backend.CannedACLToPolicyForOwner(acl, requestOwner, h.bucketOwner(bucketName))
	}
	if err := postObjectPutACLFn(h, bucketName, key, obj.VersionId, objectACL); err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}

	if redirectURL := getMultipartFormValue(formFields, "success_action_redirect"); redirectURL != "" {
		if parsed, parseErr := url.Parse(redirectURL); parseErr == nil {
			redirectParams := strings.Join([]string{
				"bucket=" + url.QueryEscape(bucketName),
				"key=" + url.QueryEscape(key),
				"etag=" + url.QueryEscape(obj.ETag),
			}, "&")
			if parsed.RawQuery == "" {
				parsed.RawQuery = redirectParams
			} else {
				parsed.RawQuery += "&" + redirectParams
			}
			redirectURL = parsed.String()
		}
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	var status int
	switch getMultipartFormValue(formFields, "success_action_status") {
	case "200":
		status = http.StatusOK
	case "201":
		status = http.StatusCreated
	case "204", "":
		status = http.StatusNoContent
	default:
		// S3-compatible behavior: invalid status is treated as default 204.
		status = http.StatusNoContent
	}

	if status == http.StatusCreated {
		type postResponse struct {
			XMLName  xml.Name `xml:"PostResponse"`
			Location string   `xml:"Location"`
			Bucket   string   `xml:"Bucket"`
			Key      string   `xml:"Key"`
			ETag     string   `xml:"ETag"`
		}
		resp := postResponse{
			Location: "/" + bucketName + "/" + key,
			Bucket:   bucketName,
			Key:      key,
			ETag:     obj.ETag,
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(xml.Header))
		output, marshalErr := xmlMarshalFn(resp)
		if marshalErr == nil {
			_, _ = w.Write(output)
		}
		return
	}

	w.WriteHeader(status)
}

// handleListObjectsV2 handles ListObjectsV2 requests.
func (h *Handler) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Check bucket policy for ListBucket
	if !h.checkAccess(r, bucketName, "s3:ListBucket", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	allowUnordered := query.Get("allow-unordered")
	encodingType := query.Get("encoding-type")
	continuationToken := query.Get("continuation-token")
	startAfter := query.Get("start-after")
	fetchOwner := query.Get("fetch-owner") == "true"
	optionalAttrs := parseOptionalObjectAttributes(r)

	if allowUnordered == "true" && delimiter != "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"allow-unordered cannot be used with delimiter.",
		)
		return
	}
	// Handle RequestPayer - accept and acknowledge
	if r.Header.Get("x-amz-request-payer") == "requester" {
		w.Header().Set("x-amz-request-charged", "requester")
	}

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	result, err := h.backend.ListObjectsV2(
		bucketName,
		prefix,
		delimiter,
		continuationToken,
		startAfter,
		maxKeys,
	)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListBucketV2Result{
		Xmlns:                 backend.S3Xmlns,
		Name:                  bucketName,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		KeyCount:              result.KeyCount,
		IsTruncated:           result.IsTruncated,
		NextContinuationToken: result.NextContinuationToken,
		StartAfter:            startAfter,
	}
	// Include ContinuationToken in response only when the parameter was provided
	if query.Has("continuation-token") {
		ct := continuationToken
		resp.ContinuationToken = &ct
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	var owner *backend.Owner
	if fetchOwner {
		owner = backend.DefaultOwner()
	}
	for _, obj := range result.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = s3URLEncode(obj.Key)
		}
		storageClass := obj.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		info := backend.ObjectInfo{
			Key:          key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: storageClass,
			Owner:        owner,
		}
		if optionalAttrs["ChecksumAlgorithm"] && obj.ChecksumAlgorithm != "" {
			info.ChecksumAlgorithm = []string{obj.ChecksumAlgorithm}
		}
		resp.Contents = append(resp.Contents, info)
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = s3URLEncode(cp)
		}
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cpValue,
		})
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

// handleListObjectsV1 handles ListObjects (v1) requests.
func (h *Handler) handleListObjectsV1(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Check bucket policy for ListBucket
	if !h.checkAccess(r, bucketName, "s3:ListBucket", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	allowUnordered := query.Get("allow-unordered")
	marker := query.Get("marker")
	encodingType := query.Get("encoding-type")
	optionalAttrs := parseOptionalObjectAttributes(r)

	if allowUnordered == "true" && delimiter != "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"allow-unordered cannot be used with delimiter.",
		)
		return
	}
	// Handle RequestPayer - accept and acknowledge
	if r.Header.Get("x-amz-request-payer") == "requester" {
		w.Header().Set("x-amz-request-charged", "requester")
	}

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	result, err := h.backend.ListObjectsV1(bucketName, prefix, delimiter, marker, maxKeys)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListBucketV1Result{
		Xmlns:       backend.S3Xmlns,
		Name:        bucketName,
		Prefix:      prefix,
		Marker:      marker,
		Delimiter:   delimiter,
		MaxKeys:     maxKeys,
		IsTruncated: result.IsTruncated,
		NextMarker:  result.NextMarker,
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	owner := backend.DefaultOwner()
	for _, obj := range result.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = s3URLEncode(obj.Key)
		}
		storageClass := obj.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		info := backend.ObjectInfo{
			Key:          key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: storageClass,
			Owner:        owner,
		}
		if optionalAttrs["ChecksumAlgorithm"] && obj.ChecksumAlgorithm != "" {
			info.ChecksumAlgorithm = []string{obj.ChecksumAlgorithm}
		}
		resp.Contents = append(resp.Contents, info)
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = s3URLEncode(cp)
		}
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cpValue,
		})
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

// handleListObjectVersions handles ListObjectVersions requests.
func (h *Handler) handleListObjectVersions(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	keyMarker := query.Get("key-marker")
	versionIdMarker := query.Get("version-id-marker")
	encodingType := query.Get("encoding-type")

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	result, err := h.backend.ListObjectVersions(
		bucketName,
		prefix,
		delimiter,
		keyMarker,
		versionIdMarker,
		maxKeys,
	)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListVersionsResult{
		Xmlns:               backend.S3Xmlns,
		IsTruncated:         result.IsTruncated,
		KeyMarker:           keyMarker,
		VersionIdMarker:     versionIdMarker,
		NextKeyMarker:       result.NextKeyMarker,
		NextVersionIdMarker: result.NextVersionIdMarker,
		Name:                bucketName,
		Prefix:              prefix,
		Delimiter:           delimiter,
		MaxKeys:             maxKeys,
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	for _, obj := range result.Versions {
		key := obj.Key
		if encodingType == "url" {
			key = s3URLEncode(obj.Key)
		}
		storageClass := obj.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		resp.Versions = append(resp.Versions, backend.VersionInfo{
			Key:          key,
			VersionId:    obj.VersionId,
			IsLatest:     obj.IsLatest,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: storageClass,
			Owner:        backend.DefaultOwner(),
		})
	}

	for _, obj := range result.DeleteMarkers {
		key := obj.Key
		if encodingType == "url" {
			key = s3URLEncode(obj.Key)
		}
		resp.DeleteMarkers = append(resp.DeleteMarkers, backend.DeleteMarker{
			Key:          key,
			VersionId:    obj.VersionId,
			IsLatest:     obj.IsLatest,
			LastModified: obj.LastModified.Format(time.RFC3339),
			Owner:        backend.DefaultOwner(),
		})
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = s3URLEncode(cp)
		}
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cpValue,
		})
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

// handleGetBucketVersioning handles GetBucketVersioning requests.
func (h *Handler) handleGetBucketVersioning(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	status, mfaDelete, err := h.backend.GetBucketVersioning(bucketName)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.VersioningConfiguration{
		Xmlns: backend.S3Xmlns,
	}

	// Only include Status if versioning has been configured
	if status != backend.VersioningUnset {
		resp.Status = status.String()
	}

	// Only include MfaDelete if it's enabled
	if mfaDelete == backend.MFADeleteEnabled {
		resp.MFADelete = mfaDelete.String()
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

// handlePutBucketVersioning handles PutBucketVersioning requests.
func (h *Handler) handlePutBucketVersioning(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.VersioningConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	// Validate Status field
	if config.Status != "" && config.Status != "Enabled" && config.Status != "Suspended" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	status := backend.ParseVersioningStatus(config.Status)
	mfaDelete := backend.ParseMFADeleteStatus(config.MFADelete)

	// Check x-amz-mfa header if MFA Delete is being enabled
	if mfaDelete == backend.MFADeleteEnabled {
		mfaHeader := r.Header.Get("x-amz-mfa")
		if err := validateMFAHeader(mfaHeader); err != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				err.Error(),
			)
			return
		}
	}

	err = setBucketVersioningFn(h, bucketName, status, mfaDelete)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusConflict,
				"InvalidBucketState",
				"Cannot suspend versioning on a bucket with Object Lock enabled.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// validateMFAHeader validates the x-amz-mfa header format.
// Format: "{SerialNumber} {TokenCode}" where:
// - SerialNumber is either an ARN (arn:aws:iam::...:mfa/...) or a hardware device serial number
// - TokenCode is a 6-digit number from the MFA device
// Example: "arn:aws:iam::123456789012:mfa/user 123456" or "20899872 301749"
func validateMFAHeader(header string) error {
	if header == "" {
		return errors.New("x-amz-mfa header is required for MFA Delete operations")
	}

	// Split by space - format is "SerialNumber TokenCode"
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return errors.New("x-amz-mfa header must be in format 'SerialNumber TokenCode'")
	}

	serialNumber := strings.TrimSpace(parts[0])
	tokenCode := strings.TrimSpace(parts[1])

	// Validate SerialNumber is not empty
	if serialNumber == "" {
		return errors.New("MFA serial number cannot be empty")
	}

	// Validate SerialNumber format:
	// - Virtual MFA: arn:aws:iam::ACCOUNT_ID:mfa/DEVICE_NAME
	// - Hardware MFA: numeric serial number
	if strings.HasPrefix(serialNumber, "arn:") {
		// Validate ARN format
		if !strings.Contains(serialNumber, ":mfa/") {
			return errors.New("MFA serial number ARN must contain ':mfa/'")
		}
	}
	// Hardware serial numbers are just numeric strings - no specific validation needed

	// Validate TokenCode is exactly 6 digits
	if len(tokenCode) != 6 {
		return errors.New("MFA token code must be exactly 6 digits")
	}
	for _, c := range tokenCode {
		if c < '0' || c > '9' {
			return errors.New("MFA token code must contain only digits")
		}
	}

	return nil
}

// handleGetBucketLocation handles GetBucketLocation requests.
func (h *Handler) handleGetBucketLocation(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:GetBucketLocation", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	location, err := getBucketLocationFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	resp := backend.LocationConstraint{
		Xmlns:              backend.S3Xmlns,
		LocationConstraint: location,
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

// handleGetBucketTagging handles GetBucketTagging requests.
func (h *Handler) handleGetBucketTagging(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	tags, err := getBucketTaggingFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchTagSet) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchTagSet",
				"The TagSet does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	resp := backend.Tagging{
		Xmlns: backend.S3Xmlns,
	}
	// Sort keys for deterministic output
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		resp.TagSet = append(resp.TagSet, backend.Tag{Key: k, Value: tags[k]})
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

// handlePutBucketTagging handles PutBucketTagging requests.
func (h *Handler) handlePutBucketTagging(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	// Convert to map
	tags := make(map[string]string)
	for _, tag := range tagging.TagSet {
		if tag.Key == "" {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidTag",
				"The tag key cannot be empty.",
			)
			return
		}
		tags[tag.Key] = tag.Value
	}

	err = putBucketTaggingFn(h, bucketName, tags)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteBucketTagging handles DeleteBucketTagging requests.
func (h *Handler) handleDeleteBucketTagging(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketTaggingFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketPolicy handles GetBucketPolicy requests.
func (h *Handler) handleGetBucketPolicy(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	policy, err := getBucketPolicyFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchBucketPolicy) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucketPolicy",
				"The bucket policy does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	// Policy is returned as JSON directly (not XML)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(policy))
}

// handlePutBucketPolicy handles PutBucketPolicy requests.
func (h *Handler) handlePutBucketPolicy(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:PutBucketPolicy", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

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

	config := h.getBucketPublicAccessBlock(bucketName)
	if config != nil && config.BlockPublicPolicy && backend.IsPolicyPublic(string(body)) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	err = putBucketPolicyFn(h, bucketName, string(body))
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrMalformedPolicy) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"MalformedPolicy",
				"This policy contains invalid Json.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketPolicyStatus handles GetBucketPolicyStatus requests.
func (h *Handler) handleGetBucketPolicyStatus(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:GetBucketPolicyStatus", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	bucket, ok := h.backend.GetBucket(bucketName)
	if !ok {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	config := h.getBucketPublicAccessBlock(bucketName)
	ignorePublicACLs := config != nil && config.IgnorePublicAcls

	isPublic := backend.IsPolicyPublic(bucket.Policy)
	if !ignorePublicACLs {
		acl, err := h.backend.GetBucketACL(bucketName)
		if err == nil && isPublicACL(acl) {
			isPublic = true
		}
	}

	resp := backend.PolicyStatus{
		Xmlns:    backend.S3Xmlns,
		IsPublic: isPublic,
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

// handleDeleteBucketPolicy handles DeleteBucketPolicy requests.
func (h *Handler) handleDeleteBucketPolicy(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketPolicyFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketACL handles GetBucketAcl requests.
func (h *Handler) handleGetBucketACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:GetBucketAcl", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	acl, err := getBucketACLFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
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

// handlePutBucketACL handles PutBucketAcl requests.
func (h *Handler) handlePutBucketACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:PutBucketAcl", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	config := h.getBucketPublicAccessBlock(bucketName)

	// Check for canned ACL header first
	cannedACL := r.Header.Get("x-amz-acl")
	if cannedACL != "" {
		bucketOwner := h.bucketOwner(bucketName)
		acl := backend.CannedACLToPolicyForOwner(cannedACL, bucketOwner, bucketOwner)
		if config != nil && config.BlockPublicAcls && isPublicACL(acl) {
			backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
			return
		}
		if err := putBucketACLFn(h, bucketName, acl); err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
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
	if aclErr := normalizeAndValidateACL(&acl); aclErr != nil {
		backend.WriteError(w, http.StatusBadRequest, aclErr.code, aclErr.message)
		return
	}
	if config != nil && config.BlockPublicAcls && isPublicACL(&acl) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	if err := putBucketACLFn(h, bucketName, &acl); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetBucketLifecycleConfiguration handles GetBucketLifecycleConfiguration requests.
func (h *Handler) handleGetBucketLifecycleConfiguration(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	config, err := getBucketLifecycleConfigurationFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchLifecycleConfiguration) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchLifecycleConfiguration",
				"The lifecycle configuration does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutBucketLifecycleConfiguration handles PutBucketLifecycleConfiguration requests.
func (h *Handler) handlePutBucketLifecycleConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.LifecycleConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}
	if code, message, ok := validateLifecycleConfiguration(&config); !ok {
		backend.WriteError(w, http.StatusBadRequest, code, message)
		return
	}

	if err := putBucketLifecycleConfigurationFn(h, bucketName, &config); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

func validateLifecycleConfiguration(config *backend.LifecycleConfiguration) (string, string, bool) {
	if config == nil {
		return "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", false
	}

	seenIDs := make(map[string]struct{}, len(config.Rules))
	for _, rule := range config.Rules {
		if rule.Status != backend.LifecycleStatusEnabled &&
			rule.Status != backend.LifecycleStatusDisabled {
			return "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", false
		}

		if rule.ID != "" {
			if len(rule.ID) > 255 {
				return "InvalidArgument", "Invalid argument", false
			}
			if _, exists := seenIDs[rule.ID]; exists {
				return "InvalidArgument", "Invalid argument", false
			}
			seenIDs[rule.ID] = struct{}{}
		}

		if rule.Expiration != nil {
			if rule.Expiration.Days < 0 {
				return "InvalidArgument", "Invalid argument", false
			}

			hasDate := strings.TrimSpace(rule.Expiration.Date) != ""
			hasDays := rule.Expiration.Days > 0
			hasDeleteMarkerOnly := rule.Expiration.ExpiredObjectDeleteMarker

			if hasDeleteMarkerOnly {
				if hasDays || hasDate {
					return "InvalidArgument", "Invalid argument", false
				}
			} else {
				if !hasDays && !hasDate {
					return "InvalidArgument", "Invalid argument", false
				}
				if hasDays && hasDate {
					return "InvalidArgument", "Invalid argument", false
				}
				if hasDate {
					if _, err := parseLifecycleExpirationDate(rule.Expiration.Date); err != nil {
						return "InvalidArgument", "Invalid argument", false
					}
				}
			}
		}

		for _, transition := range rule.Transition {
			hasDate := strings.TrimSpace(transition.Date) != ""
			hasDays := transition.Days > 0
			if transition.Days < 0 {
				return "InvalidArgument", "Invalid argument", false
			}
			if !hasDate && !hasDays {
				return "InvalidArgument", "Invalid argument", false
			}
			if hasDate && hasDays {
				return "InvalidArgument", "Invalid argument", false
			}
			if strings.TrimSpace(transition.StorageClass) == "" {
				return "InvalidArgument", "Invalid argument", false
			}
			if hasDate {
				if _, err := parseLifecycleExpirationDate(transition.Date); err != nil {
					return "InvalidArgument", "Invalid argument", false
				}
			}
		}

		for _, transition := range rule.NoncurrentVersionTransition {
			if transition.NoncurrentDays <= 0 {
				return "InvalidArgument", "Invalid argument", false
			}
			if strings.TrimSpace(transition.StorageClass) == "" {
				return "InvalidArgument", "Invalid argument", false
			}
			if transition.NewerNoncurrentVersions < 0 {
				return "InvalidArgument", "Invalid argument", false
			}
		}

		if rule.NoncurrentVersionExpiration != nil &&
			rule.NoncurrentVersionExpiration.NoncurrentDays <= 0 {
			return "InvalidArgument", "Invalid argument", false
		}
	}

	return "", "", true
}

func parseLifecycleExpirationDate(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		if t.UTC().Year() < 2000 {
			return time.Time{}, fmt.Errorf("invalid lifecycle expiration date: %q", value)
		}
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		if t.UTC().Year() < 2000 {
			return time.Time{}, fmt.Errorf("invalid lifecycle expiration date: %q", value)
		}
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid lifecycle expiration date: %q", value)
}

// handleDeleteBucketLifecycleConfiguration handles DeleteBucketLifecycleConfiguration requests.
func (h *Handler) handleDeleteBucketLifecycleConfiguration(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketLifecycleConfigurationFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketEncryption handles GetBucketEncryption requests.
func (h *Handler) handleGetBucketEncryption(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	config, err := getBucketEncryptionFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrServerSideEncryptionConfigurationNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"ServerSideEncryptionConfigurationNotFoundError",
				"The server side encryption configuration was not found.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutBucketEncryption handles PutBucketEncryption requests.
func (h *Handler) handlePutBucketEncryption(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.ServerSideEncryptionConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	if err := putBucketEncryptionFn(h, bucketName, &config); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucketEncryption handles DeleteBucketEncryption requests.
func (h *Handler) handleDeleteBucketEncryption(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketEncryptionFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketCORS handles GetBucketCors requests.
func (h *Handler) handleGetBucketCORS(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	config, err := getBucketCORSFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchCORSConfiguration) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchCORSConfiguration",
				"The CORS configuration does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutBucketCORS handles PutBucketCors requests.
func (h *Handler) handlePutBucketCORS(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.CORSConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	if err := putBucketCORSFn(h, bucketName, &config); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucketCORS handles DeleteBucketCors requests.
func (h *Handler) handleDeleteBucketCORS(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketCORSFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetBucketWebsite handles GetBucketWebsite requests.
func (h *Handler) handleGetBucketWebsite(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	config, err := getBucketWebsiteFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchWebsiteConfiguration) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchWebsiteConfiguration",
				"The specified bucket does not have a website configuration.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutBucketWebsite handles PutBucketWebsite requests.
func (h *Handler) handlePutBucketWebsite(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.WebsiteConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	if err := putBucketWebsiteFn(h, bucketName, &config); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucketWebsite handles DeleteBucketWebsite requests.
func (h *Handler) handleDeleteBucketWebsite(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	err := deleteBucketWebsiteFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetPublicAccessBlock handles GetPublicAccessBlock requests.
func (h *Handler) handleGetPublicAccessBlock(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:GetBucketPublicAccessBlock", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	config, err := getPublicAccessBlockFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrNoSuchPublicAccessBlockConfiguration) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchPublicAccessBlockConfiguration",
				"The public access block configuration was not found.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutPublicAccessBlock handles PutPublicAccessBlock requests.
func (h *Handler) handlePutPublicAccessBlock(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:PutBucketPublicAccessBlock", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

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

	var config backend.PublicAccessBlockConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	if err := putPublicAccessBlockFn(h, bucketName, &config); err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeletePublicAccessBlock handles DeletePublicAccessBlock requests.
func (h *Handler) handleDeletePublicAccessBlock(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	if !h.checkAccess(r, bucketName, "s3:DeleteBucketPublicAccessBlock", "") {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	err := deletePublicAccessBlockFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
