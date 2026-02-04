package handler

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

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
			// Try to URL-decode the value (AWS SDK may encode non-ASCII chars)
			if decoded, err := url.QueryUnescape(value); err == nil {
				value = decoded
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
// Non-ASCII values are URL-encoded for HTTP header compatibility.
func setMetadataHeaders(w http.ResponseWriter, metadata map[string]string) {
	for k, v := range metadata {
		// Check if value contains non-ASCII characters
		needsEncoding := false
		for i := 0; i < len(v); i++ {
			if v[i] > 127 {
				needsEncoding = true
				break
			}
		}

		encodedValue := v
		if needsEncoding {
			// URL-encode non-ASCII characters for HTTP header compatibility
			encodedValue = url.QueryEscape(v)
		}

		// Use direct map access to avoid Go's header canonicalization
		// This ensures "x-amz-meta-foo" stays lowercase, not "X-Amz-Meta-Foo"
		w.Header()["x-amz-meta-"+k] = []string{encodedValue}
	}
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

	switch r.Method {
	case http.MethodPut:
		copySource := r.Header.Get("x-amz-copy-source")
		if copySource != "" {
			h.handleCopyObject(w, r, bucketName, key, copySource)
			return
		}

		var data []byte
		var err error

		// Check for AWS chunked encoding
		contentEncoding := r.Header.Get("Content-Encoding")
		if isAWSChunkedEncoding(contentEncoding) {
			data, err = decodeAWSChunkedBody(r.Body)
		} else {
			data, err = io.ReadAll(r.Body)
		}
		if err != nil {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = r.Body.Close() }()

		// Strip aws-chunked from content encoding (it's a transfer encoding, not content encoding)
		storedContentEncoding := contentEncoding
		if isAWSChunkedEncoding(contentEncoding) {
			storedContentEncoding = strings.Replace(contentEncoding, "aws-chunked", "", 1)
			storedContentEncoding = strings.TrimPrefix(storedContentEncoding, ",")
			storedContentEncoding = strings.TrimSuffix(storedContentEncoding, ",")
			storedContentEncoding = strings.TrimSpace(storedContentEncoding)
		}

		opts := backend.PutObjectOptions{
			ContentType:        r.Header.Get("Content-Type"),
			Metadata:           extractMetadata(r),
			CacheControl:       r.Header.Get("Cache-Control"),
			Expires:            parseExpires(r.Header.Get("Expires")),
			ContentEncoding:    storedContentEncoding,
			ContentLanguage:    r.Header.Get("Content-Language"),
			ContentDisposition: r.Header.Get("Content-Disposition"),
		}

		obj, err := h.backend.PutObject(bucketName, key, data, opts)
		if err != nil {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		}
		w.Header().Set("ETag", obj.ETag)
		// Add version ID header if versioning is enabled
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		versionId := r.URL.Query().Get("versionId")
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

		// Evaluate conditional headers before returning content
		condResult := evaluateConditionalHeaders(r, obj)
		if condResult.ShouldReturn {
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			w.WriteHeader(condResult.StatusCode)
			return
		}

		// Set common headers
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		w.Header().Set("Accept-Ranges", "bytes")
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
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
		versionId := r.URL.Query().Get("versionId")
		var result *backend.DeleteObjectVersionResult
		var err error

		if versionId != "" {
			result, err = h.backend.DeleteObjectVersion(bucketName, key, versionId)
		} else {
			result, err = h.backend.DeleteObject(bucketName, key)
		}

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
		var obj *backend.Object
		var err error

		if versionId != "" {
			obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			obj, err = h.backend.GetObject(bucketName, key)
		}

		if err != nil {
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

		// Evaluate conditional headers before returning metadata
		condResult := evaluateConditionalHeaders(r, obj)
		if condResult.ShouldReturn {
			w.Header().Set("ETag", obj.ETag)
			w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			w.WriteHeader(condResult.StatusCode)
			return
		}

		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		w.Header().Set("Accept-Ranges", "bytes")
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
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

// handleDeleteObjects handles batch delete operations.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucketName string) {
	body, err := io.ReadAll(r.Body)
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

	results, err := h.backend.DeleteObjects(bucketName, deleteReq.Objects)
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
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	for _, result := range results {
		if result.Error != nil {
			resp.Errors = append(resp.Errors, backend.DeleteError{
				Key:     result.Key,
				Code:    "InternalError",
				Message: result.Error.Error(),
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
	output, err := xml.Marshal(resp)
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
	decodedCopySource, err := url.PathUnescape(copySource)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header: malformed URL encoding",
		)
		return
	}

	// Parse versionId from copy source (format: /bucket/key?versionId=xxx)
	var srcVersionId string
	if idx := strings.Index(decodedCopySource, "?"); idx != -1 {
		queryStr := decodedCopySource[idx+1:]
		decodedCopySource = decodedCopySource[:idx]
		if values, err := url.ParseQuery(queryStr); err == nil {
			srcVersionId = values.Get("versionId")
		}
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

	// Get metadata directive
	metadataDirective := r.Header.Get("x-amz-metadata-directive")
	if metadataDirective == "" {
		metadataDirective = "COPY"
	}

	// Check for self-copy without REPLACE
	if srcBucket == dstBucket && srcKey == dstKey && metadataDirective != "REPLACE" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
		)
		return
	}

	// Build copy options
	opts := backend.CopyObjectOptions{
		MetadataDirective: metadataDirective,
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

	obj, srcVersionIdUsed, err := h.backend.CopyObject(
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
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	// Add source version ID header if specified
	if srcVersionIdUsed != "" && srcVersionIdUsed != backend.NullVersionId {
		w.Header().Set("x-amz-copy-source-version-id", srcVersionIdUsed)
	}

	// Add destination version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	resp := backend.CopyObjectResult{
		ETag:         obj.ETag,
		LastModified: obj.LastModified.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
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
	acl, err := h.backend.GetObjectACL(bucketName, key, versionId)
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

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(acl)
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
	versionId := r.URL.Query().Get("versionId")

	// Check for canned ACL header first
	cannedACL := r.Header.Get("x-amz-acl")
	if cannedACL != "" {
		acl := backend.CannedACLToPolicy(cannedACL)
		if err := h.backend.PutObjectACL(bucketName, key, versionId, acl); err != nil {
			h.writePutObjectACLError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse ACL from request body
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
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
	tags, actualVersionId, err := h.backend.GetObjectTagging(bucketName, key, versionId)
	if err != nil {
		h.writeObjectTaggingError(w, err)
		return
	}

	// Set version ID header if applicable
	if actualVersionId != "" && actualVersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", actualVersionId)
	}

	// Build response
	tagSet := make([]backend.Tag, 0, len(tags))
	for k, v := range tags {
		tagSet = append(tagSet, backend.Tag{Key: k, Value: v})
	}

	resp := backend.Tagging{
		Xmlns:  "http://s3.amazonaws.com/doc/2006-03-01/",
		TagSet: tagSet,
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
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
	body, err := io.ReadAll(r.Body)
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

	// Convert TagSet to map
	tags := make(map[string]string, len(tagging.TagSet))
	for _, tag := range tagging.TagSet {
		tags[tag.Key] = tag.Value
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
	for _, attr := range strings.Split(attributesHeader, ",") {
		requestedAttrs[strings.TrimSpace(attr)] = true
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

	// Build response based on requested attributes
	resp := backend.GetObjectAttributesResponse{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	if requestedAttrs["ETag"] {
		resp.ETag = obj.ETag
	}

	if requestedAttrs["Checksum"] {
		if obj.ChecksumCRC32 != "" {
			resp.Checksum = &backend.GetObjectAttributesChecksum{
				ChecksumCRC32: obj.ChecksumCRC32,
			}
		}
	}

	if requestedAttrs["ObjectSize"] {
		resp.ObjectSize = &obj.Size
	}

	if requestedAttrs["StorageClass"] {
		resp.StorageClass = "STANDARD"
	}

	// Set version ID header
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}
