package handler

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleCreateMultipartUpload handles CreateMultipartUpload requests.
func (h *Handler) handleCreateMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	// Check bucket policy for PutObject (CreateMultipartUpload is part of PutObject)
	if !h.checkAccess(r, bucketName, "s3:PutObject", key) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	opts := backend.CreateMultipartUploadOptions{
		ContentType:        r.Header.Get("Content-Type"),
		Owner:              requesterOwner(r),
		Metadata:           extractMetadata(r),
		Tags:               parseTaggingHeader(r.Header.Get("x-amz-tagging")),
		CacheControl:       r.Header.Get("Cache-Control"),
		Expires:            parseExpires(r.Header.Get("Expires")),
		ContentEncoding:    r.Header.Get("Content-Encoding"),
		ContentLanguage:    r.Header.Get("Content-Language"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
	}

	// Extract Object Lock headers
	if lockMode := r.Header.Get("x-amz-object-lock-mode"); lockMode != "" {
		opts.RetentionMode = lockMode
	}
	if retainUntil := r.Header.Get("x-amz-object-lock-retain-until-date"); retainUntil != "" {
		t, parseErr := time.Parse(time.RFC3339, retainUntil)
		if parseErr == nil {
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

	upload, err := h.backend.CreateMultipartUpload(bucketName, key, opts)
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

	resp := backend.InitiateMultipartUploadResult{
		Xmlns:    backend.S3Xmlns,
		Bucket:   bucketName,
		Key:      key,
		UploadId: upload.UploadId,
	}

	// Return SSE headers
	if upload.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", upload.ServerSideEncryption)
	}
	if upload.SSEKMSKeyId != "" {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", upload.SSEKMSKeyId)
	}
	if upload.SSECustomerAlgorithm != "" {
		w.Header().
			Set("x-amz-server-side-encryption-customer-algorithm", upload.SSECustomerAlgorithm)
	}
	if upload.SSECustomerKeyMD5 != "" {
		w.Header().Set("x-amz-server-side-encryption-customer-key-md5", upload.SSECustomerKeyMD5)
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

// handleUploadPart handles UploadPart requests.
func (h *Handler) handleUploadPart(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	query := r.URL.Query()
	uploadId := query.Get("uploadId")
	partNumberStr := query.Get("partNumber")

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Part number must be an integer between 1 and 10000.",
		)
		return
	}

	// Validate SSE-C headers against the upload's SSE-C config
	if errCode, errMsg := validateSSEHeaders(r); errCode != "" {
		backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
		return
	}
	if upload, ok := h.backend.GetUpload(uploadId); ok && upload.SSECustomerAlgorithm != "" {
		reqKeyMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5")
		if reqKeyMD5 == "" || reqKeyMD5 != upload.SSECustomerKeyMD5 {
			backend.WriteError(w, http.StatusBadRequest, "InvalidArgument",
				"The SSE-C key provided does not match the key used to initiate the upload.")
			return
		}
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	defer func() { _ = r.Body.Close() }()

	part, err := h.backend.UploadPart(bucketName, key, uploadId, partNumber, data)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.Header().Set("ETag", part.ETag)

	// Return SSE headers from the multipart upload
	if upload, ok := h.backend.GetUpload(uploadId); ok {
		if upload.ServerSideEncryption != "" {
			w.Header().Set("x-amz-server-side-encryption", upload.ServerSideEncryption)
		}
		if upload.SSEKMSKeyId != "" {
			w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", upload.SSEKMSKeyId)
		}
		if upload.SSECustomerAlgorithm != "" {
			w.Header().
				Set("x-amz-server-side-encryption-customer-algorithm", upload.SSECustomerAlgorithm)
		}
		if upload.SSECustomerKeyMD5 != "" {
			w.Header().
				Set("x-amz-server-side-encryption-customer-key-md5", upload.SSECustomerKeyMD5)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload handles CompleteMultipartUpload requests.
func (h *Handler) handleCompleteMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	uploadId := r.URL.Query().Get("uploadId")

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

	var completeReq backend.CompleteMultipartUploadRequest
	if err := xml.Unmarshal(body, &completeReq); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed.",
		)
		return
	}

	obj, err := h.backend.CompleteMultipartUpload(bucketName, key, uploadId, completeReq.Parts)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			// S3 treats repeated completion of the same upload as idempotent success
			// if the completed object already exists at the destination key.
			existingObj, getErr := h.backend.GetObject(bucketName, key)
			if getErr == nil && existingObj != nil {
				obj = existingObj
			} else {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchUpload",
					"The specified upload does not exist.",
				)
				return
			}
		} else if errors.Is(err, backend.ErrInvalidPart) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidPart",
				"One or more of the specified parts could not be found.",
			)
			return
		} else if errors.Is(err, backend.ErrInvalidPartOrder) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidPartOrder",
				"The list of parts was not in ascending order.",
			)
			return
		} else if errors.Is(err, backend.ErrEntityTooSmall) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"EntityTooSmall",
				"Your proposed upload is smaller than the minimum allowed size.",
			)
			return
		} else if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		} else if errors.Is(err, backend.ErrInvalidRequest) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration",
			)
			return
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
	}

	// Build location URL
	location := "http://" + r.Host + "/" + bucketName + "/" + key

	resp := backend.CompleteMultipartUploadResult{
		Xmlns:    backend.S3Xmlns,
		Location: location,
		Bucket:   bucketName,
		Key:      key,
		ETag:     obj.ETag,
	}

	// Add version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	// Return SSE headers
	setStorageAndEncryptionHeaders(w, obj)

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleAbortMultipartUpload handles AbortMultipartUpload requests.
func (h *Handler) handleAbortMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	uploadId := r.URL.Query().Get("uploadId")

	err := h.backend.AbortMultipartUpload(bucketName, key, uploadId)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListMultipartUploads handles ListMultipartUploads requests.
func (h *Handler) handleListMultipartUploads(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	query := r.URL.Query()

	maxUploads := 1000
	if maxUploadsStr := query.Get("max-uploads"); maxUploadsStr != "" {
		parsed, err := strconv.Atoi(maxUploadsStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-uploads must be a non-negative integer.",
			)
			return
		}
		maxUploads = parsed
	}

	opts := backend.ListMultipartUploadsOptions{
		Prefix:         query.Get("prefix"),
		Delimiter:      query.Get("delimiter"),
		KeyMarker:      query.Get("key-marker"),
		UploadIdMarker: query.Get("upload-id-marker"),
		MaxUploads:     maxUploads,
	}

	result, err := h.backend.ListMultipartUploads(bucketName, opts)
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

	resp := backend.ListMultipartUploadsResult{
		Xmlns:              backend.S3Xmlns,
		Bucket:             bucketName,
		KeyMarker:          opts.KeyMarker,
		UploadIdMarker:     opts.UploadIdMarker,
		NextKeyMarker:      result.NextKeyMarker,
		NextUploadIdMarker: result.NextUploadIdMarker,
		MaxUploads:         maxUploads,
		IsTruncated:        result.IsTruncated,
		Prefix:             opts.Prefix,
		Delimiter:          opts.Delimiter,
	}

	for _, upload := range result.Uploads {
		initiator := upload.Initiator
		if initiator == nil {
			initiator = backend.DefaultOwner()
		}
		owner := upload.Owner
		if owner == nil {
			owner = backend.DefaultOwner()
		}
		storageClass := upload.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		resp.Uploads = append(resp.Uploads, backend.UploadInfo{
			Key:          upload.Key,
			UploadId:     upload.UploadId,
			Initiator:    initiator,
			Owner:        owner,
			StorageClass: storageClass,
			Initiated:    upload.Initiated,
		})
	}

	for _, cp := range result.CommonPrefixes {
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cp,
		})
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

// handleListParts handles ListParts requests.
func (h *Handler) handleListParts(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	query := r.URL.Query()
	uploadId := query.Get("uploadId")

	partNumberMarker := 0
	if markerStr := query.Get("part-number-marker"); markerStr != "" {
		parsed, err := strconv.Atoi(markerStr)
		if err != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"part-number-marker must be an integer.",
			)
			return
		}
		partNumberMarker = parsed
	}

	maxParts := 1000
	if maxPartsStr := query.Get("max-parts"); maxPartsStr != "" {
		parsed, err := strconv.Atoi(maxPartsStr)
		if err != nil || parsed < 0 {
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

	opts := backend.ListPartsOptions{
		PartNumberMarker: partNumberMarker,
		MaxParts:         maxParts,
	}

	result, upload, err := h.backend.ListParts(bucketName, key, uploadId, opts)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	initiator := upload.Initiator
	if initiator == nil {
		initiator = backend.DefaultOwner()
	}
	owner := upload.Owner
	if owner == nil {
		owner = backend.DefaultOwner()
	}
	storageClass := upload.StorageClass
	if storageClass == "" {
		storageClass = "STANDARD"
	}
	resp := backend.ListPartsResult{
		Xmlns:                backend.S3Xmlns,
		Bucket:               bucketName,
		Key:                  key,
		UploadId:             uploadId,
		Initiator:            initiator,
		Owner:                owner,
		StorageClass:         storageClass,
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: result.NextPartNumberMarker,
		MaxParts:             maxParts,
		IsTruncated:          result.IsTruncated,
	}

	for _, part := range result.Parts {
		resp.Parts = append(resp.Parts, backend.PartItem{
			PartNumber:   part.PartNumber,
			LastModified: part.LastModified,
			ETag:         part.ETag,
			Size:         part.Size,
		})
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

// handleUploadPartCopy handles UploadPartCopy requests.
func (h *Handler) handleUploadPartCopy(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key, copySource string,
) {
	query := r.URL.Query()
	uploadId := query.Get("uploadId")
	partNumberStr := query.Get("partNumber")

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Part number must be an integer between 1 and 10000.",
		)
		return
	}

	// Decode copy source
	decodedCopySource, err := decodeAndParseCopySource(copySource)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header: "+err.Error(),
		)
		return
	}

	// Check bucket policy on source bucket (GetObject)
	if !h.checkAccess(r, decodedCopySource.bucket, "s3:GetObject", decodedCopySource.key) {
		backend.WriteError(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return
	}

	// Parse byte range header
	rangeStart, rangeEnd := int64(-1), int64(-1)
	if rangeHeader := r.Header.Get("x-amz-copy-source-range"); rangeHeader != "" {
		var parseErr error
		rangeStart, rangeEnd, parseErr = parseByteRange(rangeHeader)
		if parseErr != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"Invalid x-amz-copy-source-range header: "+parseErr.Error(),
			)
			return
		}
	}

	part, err := h.backend.CopyPart(
		decodedCopySource.bucket,
		decodedCopySource.key,
		decodedCopySource.versionId,
		bucketName,
		key,
		uploadId,
		partNumber,
		rangeStart,
		rangeEnd,
	)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else if errors.Is(err, backend.ErrSourceBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified source bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrSourceObjectNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified source key does not exist.",
			)
		} else if errors.Is(err, backend.ErrInvalidRange) {
			backend.WriteError(
				w,
				http.StatusRequestedRangeNotSatisfiable,
				"InvalidRange",
				"The requested range is not satisfiable.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	copyPartResp := backend.CopyPartResult{
		ETag:         part.ETag,
		LastModified: part.LastModified,
	}

	// Return SSE headers from the multipart upload
	if upload, ok := h.backend.GetUpload(uploadId); ok {
		if upload.ServerSideEncryption != "" {
			w.Header().Set("x-amz-server-side-encryption", upload.ServerSideEncryption)
		}
		if upload.SSEKMSKeyId != "" {
			w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", upload.SSEKMSKeyId)
		}
		if upload.SSECustomerAlgorithm != "" {
			w.Header().
				Set("x-amz-server-side-encryption-customer-algorithm", upload.SSECustomerAlgorithm)
		}
		if upload.SSECustomerKeyMD5 != "" {
			w.Header().
				Set("x-amz-server-side-encryption-customer-key-md5", upload.SSECustomerKeyMD5)
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	copyPartOutput, err := xml.Marshal(copyPartResp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(copyPartOutput)
}

// copySourceInfo holds parsed copy source information.
type copySourceInfo struct {
	bucket    string
	key       string
	versionId string
}

// decodeAndParseCopySource decodes and parses x-amz-copy-source header.
func decodeAndParseCopySource(copySource string) (*copySourceInfo, error) {
	// Extract versionId query parameter BEFORE URL-decoding
	var versionId string
	pathPart := copySource
	if qIdx := strings.Index(copySource, "?"); qIdx != -1 {
		queryStr := copySource[qIdx+1:]
		pathPart = copySource[:qIdx]
		if values, parseErr := url.ParseQuery(queryStr); parseErr == nil {
			versionId = values.Get("versionId")
		}
	}

	// URL decode the path part only
	decoded, err := decodeURI(pathPart)
	if err != nil {
		return nil, err
	}

	// Remove leading slash
	decoded = trimLeadingSlash(decoded)

	// Split into bucket and key
	idx := indexByte(decoded, '/')
	if idx < 0 {
		return nil, errors.New("invalid format")
	}

	return &copySourceInfo{
		bucket:    decoded[:idx],
		key:       decoded[idx+1:],
		versionId: versionId,
	}, nil
}

// decodeURI decodes a URI-encoded string.
func decodeURI(s string) (string, error) {
	// Simple URL decode implementation
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				result = append(result, byte(hi<<4|lo))
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result), nil
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

func trimLeadingSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// parseByteRange parses x-amz-copy-source-range header.
// Format: bytes=start-end
func parseByteRange(rangeHeader string) (int64, int64, error) {
	const prefix = "bytes="
	if len(rangeHeader) <= len(prefix) {
		return 0, 0, errors.New("invalid format")
	}
	if rangeHeader[:len(prefix)] != prefix {
		return 0, 0, errors.New("invalid prefix")
	}

	rangeSpec := rangeHeader[len(prefix):]
	dashIdx := indexByte(rangeSpec, '-')
	if dashIdx < 0 {
		return 0, 0, errors.New("missing dash")
	}

	startStr := rangeSpec[:dashIdx]
	endStr := rangeSpec[dashIdx+1:]

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid start")
	}

	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		return 0, 0, errors.New("invalid end")
	}

	if start > end {
		return 0, 0, errors.New("start > end")
	}

	return start, end, nil
}
