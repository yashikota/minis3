package handler

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

var (
	createMultipartUploadFn = func(
		h *Handler,
		bucketName, key string,
		opts backend.CreateMultipartUploadOptions,
	) (*backend.MultipartUpload, error) {
		return h.backend.CreateMultipartUpload(bucketName, key, opts)
	}
	uploadPartFn = func(
		h *Handler,
		bucketName, key, uploadID string,
		partNumber int,
		data []byte,
	) (*backend.PartInfo, error) {
		return h.backend.UploadPart(bucketName, key, uploadID, partNumber, data)
	}
	completeMultipartUploadFn = func(
		h *Handler,
		bucketName, key, uploadID string,
		parts []backend.CompletePart,
	) (*backend.Object, error) {
		return h.backend.CompleteMultipartUpload(bucketName, key, uploadID, parts)
	}
	getObjectForMultipartCompletionFn = func(
		h *Handler,
		bucketName, key string,
	) (*backend.Object, error) {
		return h.backend.GetObject(bucketName, key)
	}
	abortMultipartUploadFn = func(
		h *Handler,
		bucketName, key, uploadID string,
	) error {
		return h.backend.AbortMultipartUpload(bucketName, key, uploadID)
	}
	listMultipartUploadsFn = func(
		h *Handler,
		bucketName string,
		opts backend.ListMultipartUploadsOptions,
	) (*backend.ListMultipartUploadsInternalResult, error) {
		return h.backend.ListMultipartUploads(bucketName, opts)
	}
	listPartsFn = func(
		h *Handler,
		bucketName, key, uploadID string,
		opts backend.ListPartsOptions,
	) (*backend.ListPartsInternalResult, *backend.MultipartUpload, error) {
		return h.backend.ListParts(bucketName, key, uploadID, opts)
	}
	copyPartFn = func(
		h *Handler,
		srcBucket, srcKey, srcVersionID, dstBucket, dstKey, uploadID string,
		partNumber int,
		rangeStart, rangeEnd int64,
	) (*backend.PartInfo, error) {
		return h.backend.CopyPart(
			srcBucket,
			srcKey,
			srcVersionID,
			dstBucket,
			dstKey,
			uploadID,
			partNumber,
			rangeStart,
			rangeEnd,
		)
	}
	decodeURIFn = decodeURI
)

func normalizeChecksumType(algorithm, checksumType string) string {
	algorithm = strings.ToUpper(strings.TrimSpace(algorithm))
	checksumType = strings.ToUpper(strings.TrimSpace(checksumType))
	if checksumType != "" {
		return checksumType
	}
	switch algorithm {
	case "SHA1", "SHA256":
		return "COMPOSITE"
	default:
		return "FULL_OBJECT"
	}
}

func checksumFromCompletePart(algorithm string, p backend.CompletePart) string {
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		return p.ChecksumCRC32
	case "CRC32C":
		return p.ChecksumCRC32C
	case "CRC64NVME":
		return p.ChecksumCRC64NVME
	case "SHA1":
		return p.ChecksumSHA1
	case "SHA256":
		return p.ChecksumSHA256
	default:
		return ""
	}
}

func checksumFromPartInfo(algorithm string, p *backend.PartInfo) string {
	if p == nil {
		return ""
	}
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		return p.ChecksumCRC32
	case "CRC32C":
		return p.ChecksumCRC32C
	case "CRC64NVME":
		return p.ChecksumCRC64NVME
	case "SHA1":
		return p.ChecksumSHA1
	case "SHA256":
		return p.ChecksumSHA256
	default:
		return ""
	}
}

func checksumFromCompleteHeaders(algorithm string, r *http.Request) string {
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		return r.Header.Get("x-amz-checksum-crc32")
	case "CRC32C":
		return r.Header.Get("x-amz-checksum-crc32c")
	case "CRC64NVME":
		return r.Header.Get("x-amz-checksum-crc64nvme")
	case "SHA1":
		return r.Header.Get("x-amz-checksum-sha1")
	case "SHA256":
		return r.Header.Get("x-amz-checksum-sha256")
	default:
		return ""
	}
}

func setUploadFinalChecksum(upload *backend.MultipartUpload, algorithm, value string) {
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		upload.ChecksumCRC32 = value
	case "CRC32C":
		upload.ChecksumCRC32C = value
	case "CRC64NVME":
		upload.ChecksumCRC64NVME = value
	case "SHA1":
		upload.ChecksumSHA1 = value
	case "SHA256":
		upload.ChecksumSHA256 = value
	}
}

func validateMultipartSSECustomerHeaders(
	upload *backend.MultipartUpload,
	r *http.Request,
) (string, string) {
	if upload == nil || upload.SSECustomerAlgorithm == "" {
		return "", ""
	}

	reqAlgo := r.Header.Get("x-amz-server-side-encryption-customer-algorithm")
	reqKeyMD5 := r.Header.Get("x-amz-server-side-encryption-customer-key-md5")
	if reqAlgo == "" || reqKeyMD5 == "" {
		return "InvalidArgument",
			"The SSE-C key provided does not match the key used to initiate the upload."
	}
	if !strings.EqualFold(reqAlgo, upload.SSECustomerAlgorithm) ||
		reqKeyMD5 != upload.SSECustomerKeyMD5 {
		return "InvalidArgument",
			"The SSE-C key provided does not match the key used to initiate the upload."
	}
	return "", ""
}

func validateCopySourceSSECustomerHeaders(
	source *backend.Object,
	r *http.Request,
) (string, string) {
	if source == nil || source.SSECustomerAlgorithm == "" {
		return "", ""
	}

	reqAlgo := r.Header.Get("x-amz-copy-source-server-side-encryption-customer-algorithm")
	reqKeyMD5 := r.Header.Get("x-amz-copy-source-server-side-encryption-customer-key-md5")
	if reqAlgo == "" || reqKeyMD5 == "" {
		return "InvalidArgument",
			"The SSE-C key provided for the copy source is invalid."
	}
	if !strings.EqualFold(reqAlgo, source.SSECustomerAlgorithm) ||
		reqKeyMD5 != source.SSECustomerKeyMD5 {
		return "InvalidArgument",
			"The SSE-C key provided for the copy source is invalid."
	}
	return "", ""
}

func computeCompositeChecksum(algorithm string, partChecksums []string) (string, bool) {
	algorithm = strings.ToUpper(algorithm)
	if len(partChecksums) == 0 {
		return "", false
	}
	if algorithm != "SHA1" && algorithm != "SHA256" {
		return "", false
	}
	decoded := make([]byte, 0, len(partChecksums)*32)
	for _, v := range partChecksums {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "", false
		}
		decoded = append(decoded, b...)
	}
	var sum string
	switch algorithm {
	case "SHA1":
		h := sha1.Sum(decoded)
		sum = base64.StdEncoding.EncodeToString(h[:])
	case "SHA256":
		h := sha256.Sum256(decoded)
		sum = base64.StdEncoding.EncodeToString(h[:])
	}
	return sum + "-" + strconv.Itoa(len(partChecksums)), true
}

func computeFullObjectChecksum(algorithm string, data []byte) (string, bool) {
	switch strings.ToUpper(algorithm) {
	case "CRC32":
		h := crc32.NewIEEE()
		_, _ = h.Write(data)
		return base64.StdEncoding.EncodeToString(h.Sum(nil)), true
	case "CRC32C":
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		_, _ = h.Write(data)
		return base64.StdEncoding.EncodeToString(h.Sum(nil)), true
	case "CRC64NVME":
		sum := crc64.Checksum(data, crc64.MakeTable(crc64NVME))
		buf := []byte{
			byte(sum >> 56), byte(sum >> 48), byte(sum >> 40), byte(sum >> 32),
			byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
		}
		return base64.StdEncoding.EncodeToString(buf), true
	case "SHA1", "SHA256":
		return backend.ComputeChecksumBase64(algorithm, data)
	default:
		return "", false
	}
}

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
	if strings.EqualFold(bucketOwnership, backend.ObjectOwnershipBucketOwnerEnforced) {
		opts.Owner = h.bucketOwner(bucketName)
	} else if strings.EqualFold(bucketOwnership, backend.ObjectOwnershipBucketOwnerPreferred) &&
		strings.EqualFold(r.Header.Get("x-amz-acl"), string(backend.ACLBucketOwnerFull)) {
		opts.Owner = h.bucketOwner(bucketName)
	}
	checksumAlgo := r.Header.Get("x-amz-checksum-algorithm")
	if checksumAlgo == "" {
		checksumAlgo = r.Header.Get("x-amz-sdk-checksum-algorithm")
	}
	if checksumAlgo != "" {
		opts.ChecksumAlgorithm = checksumAlgo
	}
	if checksumType := r.Header.Get("x-amz-checksum-type"); checksumType != "" {
		opts.ChecksumType = checksumType
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

	upload, err := createMultipartUploadFn(h, bucketName, key, opts)
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
		Xmlns:             backend.S3Xmlns,
		Bucket:            bucketName,
		Key:               key,
		UploadId:          upload.UploadId,
		ChecksumAlgorithm: upload.ChecksumAlgorithm,
		ChecksumType:      upload.ChecksumType,
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
	if upload.ChecksumAlgorithm != "" {
		w.Header().Set("x-amz-checksum-algorithm", upload.ChecksumAlgorithm)
	}
	if upload.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", upload.ChecksumType)
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
		if errCode, errMsg := validateMultipartSSECustomerHeaders(upload, r); errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}
	}

	data, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	defer func() { _ = r.Body.Close() }()

	part, err := uploadPartFn(h, bucketName, key, uploadId, partNumber, data)
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
	if upload, ok := h.backend.GetUpload(uploadId); ok && upload.SSECustomerAlgorithm != "" {
		if errCode, errMsg := validateMultipartSSECustomerHeaders(upload, r); errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}
	}

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

	existingObj, getObjErr := getObjectForMultipartCompletionFn(h, bucketName, key)
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

	if upload, ok := h.backend.GetUpload(uploadId); ok && upload != nil {
		algorithm := strings.ToUpper(strings.TrimSpace(upload.ChecksumAlgorithm))
		if algorithm != "" {
			checksumType := normalizeChecksumType(algorithm, upload.ChecksumType)
			upload.ChecksumType = checksumType

			partChecksums := make([]string, 0, len(completeReq.Parts))
			partsData := make([][]byte, 0, len(completeReq.Parts))
			canValidate := true
			for _, p := range completeReq.Parts {
				part, exists := upload.Parts[p.PartNumber]
				if !exists {
					canValidate = false
					break
				}
				expected := checksumFromPartInfo(algorithm, part)
				if expected == "" {
					canValidate = false
					break
				}
				provided := checksumFromCompletePart(algorithm, p)
				if provided != "" && provided != expected {
					backend.WriteError(
						w,
						http.StatusBadRequest,
						"BadDigest",
						"The Content-MD5 you specified did not match what we received.",
					)
					return
				}
				partChecksums = append(partChecksums, expected)
				partsData = append(partsData, part.Data)
			}

			if canValidate {
				combinedData := bytes.Join(partsData, nil)
				finalChecksum := ""
				computed := false
				if checksumType == "COMPOSITE" {
					finalChecksum, computed = computeCompositeChecksum(algorithm, partChecksums)
				}
				if !computed {
					finalChecksum, computed = computeFullObjectChecksum(algorithm, combinedData)
				}
				if computed {
					if provided := checksumFromCompleteHeaders(algorithm, r); provided != "" &&
						provided != finalChecksum {
						backend.WriteError(
							w,
							http.StatusBadRequest,
							"BadDigest",
							"The Content-MD5 you specified did not match what we received.",
						)
						return
					}
					setUploadFinalChecksum(upload, algorithm, finalChecksum)
				}
			}
		}
	}

	obj, err := completeMultipartUploadFn(h, bucketName, key, uploadId, completeReq.Parts)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			// S3 treats repeated completion of the same upload as idempotent success
			// if the completed object already exists at the destination key.
			existingObj, getErr := getObjectForMultipartCompletionFn(h, bucketName, key)
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
		} else if errors.Is(err, backend.ErrBadDigest) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"BadDigest",
				"The Content-MD5 you specified did not match what we received.",
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
		Xmlns:             backend.S3Xmlns,
		Location:          location,
		Bucket:            bucketName,
		Key:               key,
		ETag:              obj.ETag,
		ChecksumCRC32:     obj.ChecksumCRC32,
		ChecksumCRC32C:    obj.ChecksumCRC32C,
		ChecksumCRC64NVME: obj.ChecksumCRC64NVME,
		ChecksumSHA1:      obj.ChecksumSHA1,
		ChecksumSHA256:    obj.ChecksumSHA256,
		ChecksumType:      obj.ChecksumType,
	}

	// Add version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	// Return SSE headers
	setStorageAndEncryptionHeaders(w, obj)
	setChecksumResponseHeaders(w, obj)

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
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

	err := abortMultipartUploadFn(h, bucketName, key, uploadId)
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

	result, err := listMultipartUploadsFn(h, bucketName, opts)
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
	output, err := xmlMarshalFn(resp)
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

	result, upload, err := listPartsFn(h, bucketName, key, uploadId, opts)
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
			PartNumber:        part.PartNumber,
			LastModified:      part.LastModified,
			ETag:              part.ETag,
			Size:              part.Size,
			ChecksumCRC32:     part.ChecksumCRC32,
			ChecksumCRC32C:    part.ChecksumCRC32C,
			ChecksumCRC64NVME: part.ChecksumCRC64NVME,
			ChecksumSHA1:      part.ChecksumSHA1,
			ChecksumSHA256:    part.ChecksumSHA256,
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

	if errCode, errMsg := validateSSEHeaders(r); errCode != "" {
		backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
		return
	}
	if upload, ok := h.backend.GetUpload(uploadId); ok && upload.SSECustomerAlgorithm != "" {
		if errCode, errMsg := validateMultipartSSECustomerHeaders(upload, r); errCode != "" {
			backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
			return
		}
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

	srcObj, errCode, errMsg, statusCode := h.loadCopySourceObjectForUploadPart(decodedCopySource)
	if errCode != "" {
		backend.WriteError(w, statusCode, errCode, errMsg)
		return
	}
	if errCode, errMsg := validateCopySourceSSECustomerHeaders(srcObj, r); errCode != "" {
		backend.WriteError(w, http.StatusBadRequest, errCode, errMsg)
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

	part, err := copyPartFn(
		h,
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
	copyPartOutput, err := xmlMarshalFn(copyPartResp)
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

func (h *Handler) loadCopySourceObjectForUploadPart(
	source *copySourceInfo,
) (*backend.Object, string, string, int) {
	if source == nil {
		return nil, "NoSuchKey", "The specified source key does not exist.", http.StatusNotFound
	}
	if _, ok := h.backend.GetBucket(source.bucket); !ok {
		return nil, "NoSuchBucket", "The specified source bucket does not exist.", http.StatusNotFound
	}
	if source.versionId != "" {
		obj, err := h.backend.GetObjectVersion(source.bucket, source.key, source.versionId)
		if err != nil {
			if errors.Is(err, backend.ErrVersionNotFound) {
				return nil, "NoSuchVersion", "The specified version does not exist.", http.StatusNotFound
			}
			return nil, "NoSuchKey", "The specified source key does not exist.", http.StatusNotFound
		}
		return obj, "", "", 0
	}
	obj, err := h.backend.GetObject(source.bucket, source.key)
	if err != nil {
		return nil, "NoSuchKey", "The specified source key does not exist.", http.StatusNotFound
	}
	return obj, "", "", 0
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
	decoded, err := decodeURIFn(pathPart)
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
