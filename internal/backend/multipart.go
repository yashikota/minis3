package backend

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"time"
)

// CreateMultipartUploadOptions contains options for CreateMultipartUpload.
type CreateMultipartUploadOptions struct {
	ContentType          string
	Owner                *Owner
	Metadata             map[string]string
	Tags                 map[string]string
	CacheControl         string
	Expires              *time.Time
	ContentEncoding      string
	ContentLanguage      string
	ContentDisposition   string
	RetentionMode        string
	RetainUntilDate      *time.Time
	LegalHoldStatus      string
	StorageClass         string
	ServerSideEncryption string
	SSEKMSKeyId          string
	SSECustomerAlgorithm string
	SSECustomerKeyMD5    string
	ChecksumAlgorithm    string
	ChecksumType         string
	ChecksumCRC32        string
	ChecksumCRC32C       string
	ChecksumCRC64NVME    string
	ChecksumSHA1         string
	ChecksumSHA256       string
}

// CreateMultipartUpload initiates a multipart upload and returns an upload ID.
func (b *Backend) CreateMultipartUpload(
	bucketName, key string,
	opts CreateMultipartUploadOptions,
) (*MultipartUpload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	if opts.RetentionMode != "" || opts.LegalHoldStatus != "" {
		if err := validateObjectLockRetention(
			opts.RetentionMode,
			opts.RetainUntilDate,
		); err != nil {
			return nil, err
		}
		if !bucket.ObjectLockEnabled {
			return nil, ErrInvalidRequest
		}
	}

	uploadId := b.generateUploadIdLocked()
	owner := opts.Owner
	if owner == nil {
		owner = DefaultOwner()
	}
	if strings.EqualFold(bucket.ObjectOwnership, ObjectOwnershipBucketOwnerEnforced) {
		owner = OwnerForAccessKey(bucket.OwnerAccessKey)
	}
	upload := &MultipartUpload{
		UploadId:             uploadId,
		Bucket:               bucketName,
		Key:                  key,
		Initiator:            owner,
		Owner:                owner,
		Initiated:            time.Now().UTC().Format(time.RFC3339),
		Parts:                make(map[int]*PartInfo),
		ContentType:          opts.ContentType,
		Metadata:             opts.Metadata,
		Tags:                 opts.Tags,
		CacheControl:         opts.CacheControl,
		Expires:              opts.Expires,
		ContentEncoding:      opts.ContentEncoding,
		ContentLanguage:      opts.ContentLanguage,
		ContentDisposition:   opts.ContentDisposition,
		RetentionMode:        opts.RetentionMode,
		RetainUntilDate:      opts.RetainUntilDate,
		LegalHoldStatus:      opts.LegalHoldStatus,
		StorageClass:         opts.StorageClass,
		ServerSideEncryption: opts.ServerSideEncryption,
		SSEKMSKeyId:          opts.SSEKMSKeyId,
		SSECustomerAlgorithm: opts.SSECustomerAlgorithm,
		SSECustomerKeyMD5:    opts.SSECustomerKeyMD5,
		ChecksumAlgorithm:    strings.ToUpper(strings.TrimSpace(opts.ChecksumAlgorithm)),
		ChecksumType:         strings.ToUpper(strings.TrimSpace(opts.ChecksumType)),
		ChecksumCRC32:        opts.ChecksumCRC32,
		ChecksumCRC32C:       opts.ChecksumCRC32C,
		ChecksumCRC64NVME:    opts.ChecksumCRC64NVME,
		ChecksumSHA1:         opts.ChecksumSHA1,
		ChecksumSHA256:       opts.ChecksumSHA256,
	}

	b.uploads[uploadId] = upload
	return upload, nil
}

// UploadPart uploads a part for a multipart upload.
func (b *Backend) UploadPart(
	bucketName, key, uploadId string,
	partNumber int,
	data []byte,
) (*PartInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	upload, ok := b.uploads[uploadId]
	if !ok {
		return nil, ErrNoSuchUpload
	}

	if upload.Bucket != bucketName || upload.Key != key {
		return nil, ErrNoSuchUpload
	}

	// Validate part number (1-10000)
	if partNumber < 1 || partNumber > 10000 {
		return nil, ErrInvalidRequest
	}

	// Calculate ETag (MD5 hash)
	md5Hash := md5.New()
	_, _ = md5Hash.Write(data)
	etag := fmt.Sprintf("\"%x\"", md5Hash.Sum(nil))

	part := &PartInfo{
		PartNumber:   partNumber,
		ETag:         etag,
		Size:         int64(len(data)),
		Data:         data,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	}
	setPartChecksum(part, upload.ChecksumAlgorithm, data)

	upload.Parts[partNumber] = part
	return part, nil
}

// CompleteMultipartUpload completes a multipart upload by assembling previously uploaded parts.
func (b *Backend) CompleteMultipartUpload(
	bucketName, key, uploadId string,
	parts []CompletePart,
) (*Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// AWS reports a missing bucket before a missing upload.
	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	upload, ok := b.uploads[uploadId]
	if !ok {
		return nil, ErrNoSuchUpload
	}

	if upload.Bucket != bucketName || upload.Key != key {
		return nil, ErrNoSuchUpload
	}

	if len(parts) == 0 {
		return nil, ErrInvalidPart
	}
	// Duplicate part numbers are allowed: the last entry wins, matching AWS
	// behavior (see s3-tests test_multipart_resend_first_finishes_last, where
	// a resent part appears twice in the Complete request).
	normalizedParts := normalizeCompleteParts(parts)

	// Validate parts are in ascending order and exist
	var lastPartNumber int
	var combinedData bytes.Buffer
	var partETags []string

	for _, p := range normalizedParts {
		if p.PartNumber <= lastPartNumber {
			return nil, ErrInvalidPartOrder
		}
		lastPartNumber = p.PartNumber

		uploadedPart, exists := upload.Parts[p.PartNumber]
		if !exists {
			return nil, ErrInvalidPart
		}

		// Normalize ETags for comparison (remove quotes if present)
		requestETag := strings.Trim(p.ETag, "\"")
		uploadedETag := strings.Trim(uploadedPart.ETag, "\"")

		if requestETag != uploadedETag {
			return nil, ErrInvalidPart
		}

		// Check minimum part size (5MB) for all parts except the last one
		if p.PartNumber != normalizedParts[len(normalizedParts)-1].PartNumber &&
			uploadedPart.Size < 5*1024*1024 {
			return nil, ErrEntityTooSmall
		}

		combinedData.Write(uploadedPart.Data)
		partETags = append(partETags, uploadedETag)
	}

	// Calculate final ETag (S3 multipart ETag format: MD5-of-MD5s-numberOfParts)
	md5Hash := md5.New()
	for _, etag := range partETags {
		decoded, err := hex.DecodeString(etag)
		if err != nil {
			return nil, ErrInvalidPart
		}
		md5Hash.Write(decoded)
	}
	finalETag := fmt.Sprintf("\"%x-%d\"", md5Hash.Sum(nil), len(normalizedParts))

	data := combinedData.Bytes()

	// Determine version ID
	var versionId string
	switch bucket.VersioningStatus {
	case VersioningEnabled:
		versionId = GenerateVersionId()
	default:
		versionId = NullVersionId
	}

	// Apply bucket default encryption if no explicit SSE is specified
	if upload.ServerSideEncryption == "" && upload.SSECustomerAlgorithm == "" {
		if bucket.EncryptionConfiguration != nil && len(bucket.EncryptionConfiguration.Rules) > 0 {
			rule := bucket.EncryptionConfiguration.Rules[0]
			if rule.ApplyServerSideEncryptionByDefault != nil {
				upload.ServerSideEncryption = rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				if upload.SSEKMSKeyId == "" {
					upload.SSEKMSKeyId = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
				}
			}
		}
	}

	contentType := upload.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	storageClass := upload.StorageClass
	if storageClass == "" {
		storageClass = "STANDARD"
	}

	obj := &Object{
		Key:                  key,
		VersionId:            versionId,
		IsLatest:             true,
		IsDeleteMarker:       false,
		LastModified:         time.Now().UTC(),
		ETag:                 finalETag,
		Size:                 int64(len(data)),
		ContentType:          contentType,
		Data:                 data,
		Metadata:             upload.Metadata,
		Tags:                 upload.Tags,
		CacheControl:         upload.CacheControl,
		Expires:              upload.Expires,
		ContentEncoding:      upload.ContentEncoding,
		ContentLanguage:      upload.ContentLanguage,
		ContentDisposition:   upload.ContentDisposition,
		StorageClass:         storageClass,
		ServerSideEncryption: upload.ServerSideEncryption,
		SSEKMSKeyId:          upload.SSEKMSKeyId,
		SSECustomerAlgorithm: upload.SSECustomerAlgorithm,
		SSECustomerKeyMD5:    upload.SSECustomerKeyMD5,
		Owner:                upload.Owner,
		ACL:                  NewDefaultACLForOwner(upload.Owner),
	}
	if strings.EqualFold(bucket.ObjectOwnership, ObjectOwnershipBucketOwnerEnforced) {
		obj.Owner = OwnerForAccessKey(bucket.OwnerAccessKey)
		obj.ACL = NewDefaultACLForOwner(obj.Owner)
	}
	obj.ChecksumAlgorithm = upload.ChecksumAlgorithm
	obj.ChecksumType = upload.ChecksumType
	switch strings.ToUpper(upload.ChecksumAlgorithm) {
	case "CRC32":
		if upload.ChecksumCRC32 != "" {
			obj.ChecksumCRC32 = upload.ChecksumCRC32
		} else {
			h := crc32.NewIEEE()
			_, _ = h.Write(data)
			obj.ChecksumCRC32 = base64.StdEncoding.EncodeToString(h.Sum(nil))
		}
	case "CRC32C":
		if upload.ChecksumCRC32C != "" {
			obj.ChecksumCRC32C = upload.ChecksumCRC32C
		} else {
			h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
			_, _ = h.Write(data)
			obj.ChecksumCRC32C = base64.StdEncoding.EncodeToString(h.Sum(nil))
		}
	case "CRC64NVME":
		if upload.ChecksumCRC64NVME != "" {
			obj.ChecksumCRC64NVME = upload.ChecksumCRC64NVME
		} else {
			obj.ChecksumCRC64NVME = checksumCRC64NVMEBase64(data)
		}
	case "SHA1":
		if upload.ChecksumSHA1 != "" {
			obj.ChecksumSHA1 = upload.ChecksumSHA1
		} else {
			sum := sha1.Sum(data)
			obj.ChecksumSHA1 = base64.StdEncoding.EncodeToString(sum[:])
		}
	case "SHA256":
		if upload.ChecksumSHA256 != "" {
			obj.ChecksumSHA256 = upload.ChecksumSHA256
		} else {
			sum := sha256.Sum256(data)
			obj.ChecksumSHA256 = base64.StdEncoding.EncodeToString(sum[:])
		}
	}

	// Save part information for PartNumber support in GetObject/HeadObject
	var objectParts []ObjectPart
	var offset int64
	for _, p := range normalizedParts {
		uploadedPart := upload.Parts[p.PartNumber]
		objectParts = append(objectParts, ObjectPart{
			PartNumber:        p.PartNumber,
			Size:              uploadedPart.Size,
			ETag:              uploadedPart.ETag,
			ChecksumCRC32:     uploadedPart.ChecksumCRC32,
			ChecksumCRC32C:    uploadedPart.ChecksumCRC32C,
			ChecksumCRC64NVME: uploadedPart.ChecksumCRC64NVME,
			ChecksumSHA1:      uploadedPart.ChecksumSHA1,
			ChecksumSHA256:    uploadedPart.ChecksumSHA256,
		})
		offset += uploadedPart.Size
	}
	obj.Parts = objectParts

	// Set Object Lock fields if provided
	if upload.RetentionMode != "" || upload.LegalHoldStatus != "" {
		if err := validateObjectLockRetention(
			upload.RetentionMode,
			upload.RetainUntilDate,
		); err != nil {
			return nil, err
		}
		if !bucket.ObjectLockEnabled {
			return nil, ErrInvalidRequest
		}
		obj.RetentionMode = upload.RetentionMode
		obj.RetainUntilDate = upload.RetainUntilDate
		obj.LegalHoldStatus = upload.LegalHoldStatus
	}

	// Apply bucket default retention when no explicit retention was set
	applyDefaultRetention(bucket, obj)

	addVersionToObject(bucket, key, obj)

	// Clean up the upload
	delete(b.uploads, uploadId)
	b.completedUploads[uploadId] = &completedUpload{
		Bucket:    bucketName,
		Key:       key,
		VersionId: obj.VersionId,
		ETag:      obj.ETag,
	}

	return obj, nil
}

// completedUpload records which object version a completed upload produced.
type completedUpload struct {
	Bucket    string
	Key       string
	VersionId string
	// ETag tells the produced object apart from a later object that
	// reuses its version ID (the "null" version in unversioned buckets).
	ETag string
}

// GetCompletedUploadObject returns the object version produced by an upload
// that was already completed, so a retried CompleteMultipartUpload can be
// answered idempotently. It reports false for unknown upload IDs, for a
// different bucket/key, and when the produced version no longer exists.
func (b *Backend) GetCompletedUploadObject(bucketName, key, uploadId string) (*Object, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	done, ok := b.completedUploads[uploadId]
	if !ok || done.Bucket != bucketName || done.Key != key {
		return nil, false
	}
	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, false
	}
	versions, ok := bucket.Objects[key]
	if !ok {
		return nil, false
	}
	for _, v := range versions.Versions {
		if v.VersionId == done.VersionId && v.ETag == done.ETag {
			return v, true
		}
	}
	return nil, false
}

// UpdateUpload runs fn with exclusive access to an in-progress upload, so
// callers can read parts and record final checksums without racing
// concurrent UploadPart calls.
func (b *Backend) UpdateUpload(uploadId string, fn func(*MultipartUpload) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	upload, ok := b.uploads[uploadId]
	if !ok {
		return ErrNoSuchUpload
	}
	return fn(upload)
}

// setPartChecksum stores the part checksum for the upload's algorithm.
func setPartChecksum(part *PartInfo, algorithm string, data []byte) {
	value, ok := checksumForAlgorithm(algorithm, data)
	if !ok {
		return
	}
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "CRC32":
		part.ChecksumCRC32 = value
	case "CRC32C":
		part.ChecksumCRC32C = value
	case "CRC64NVME":
		part.ChecksumCRC64NVME = value
	case "SHA1":
		part.ChecksumSHA1 = value
	case "SHA256":
		part.ChecksumSHA256 = value
	}
}

// generateUploadIdLocked returns a new upload ID. IDs start with a
// fixed-width hex counter so they sort lexicographically in creation order:
// AWS lists uploads of the same key by ascending initiation time and pages
// them with upload-id-marker using lexicographic comparison, and this keeps
// both rules consistent. Caller must hold b.mu for writing.
func (b *Backend) generateUploadIdLocked() string {
	b.uploadSeq++
	return fmt.Sprintf("%016x", b.uploadSeq) + generateRandomID(12)
}

func normalizeCompleteParts(parts []CompletePart) []CompletePart {
	lastIndexByPartNumber := make(map[int]int, len(parts))
	for idx, part := range parts {
		lastIndexByPartNumber[part.PartNumber] = idx
	}

	normalized := make([]CompletePart, 0, len(lastIndexByPartNumber))
	for idx, part := range parts {
		if lastIndexByPartNumber[part.PartNumber] == idx {
			normalized = append(normalized, part)
		}
	}
	return normalized
}

// AbortMultipartUpload aborts a multipart upload.
func (b *Backend) AbortMultipartUpload(bucketName, key, uploadId string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	upload, ok := b.uploads[uploadId]
	if !ok {
		return ErrNoSuchUpload
	}

	if upload.Bucket != bucketName || upload.Key != key {
		return ErrNoSuchUpload
	}

	delete(b.uploads, uploadId)
	return nil
}

// ListMultipartUploadsOptions contains options for ListMultipartUploads.
type ListMultipartUploadsOptions struct {
	Prefix         string
	Delimiter      string
	KeyMarker      string
	UploadIdMarker string
	MaxUploads     int
}

// ListMultipartUploadsResult contains the result of ListMultipartUploads.
type ListMultipartUploadsInternalResult struct {
	Uploads            []*MultipartUpload
	CommonPrefixes     []string
	IsTruncated        bool
	NextKeyMarker      string
	NextUploadIdMarker string
}

// ListMultipartUploads lists in-progress multipart uploads.
func (b *Backend) ListMultipartUploads(
	bucketName string,
	opts ListMultipartUploadsOptions,
) (*ListMultipartUploadsInternalResult, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.buckets[bucketName]; !ok {
		return nil, ErrBucketNotFound
	}

	// Collect uploads for this bucket
	var uploads []*MultipartUpload
	for _, upload := range b.uploads {
		if upload.Bucket != bucketName {
			continue
		}
		uploads = append(uploads, upload)
	}

	// Sort by key, then by upload ID. Upload IDs are generated in
	// lexicographically increasing order, so for a single key this is also
	// ascending initiation time as AWS documents.
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		return uploads[i].UploadId < uploads[j].UploadId
	})

	// Build one ordered entry stream where each rolled-up common prefix
	// occupies a single slot; AWS counts CommonPrefixes toward MaxUploads.
	type uploadEntry struct {
		key          string
		upload       *MultipartUpload
		commonPrefix bool
	}
	var entries []uploadEntry
	lastPrefix := ""
	for _, upload := range uploads {
		if opts.Prefix != "" && !strings.HasPrefix(upload.Key, opts.Prefix) {
			continue
		}
		if opts.Delimiter != "" {
			subKey := upload.Key[len(opts.Prefix):]
			if idx := strings.Index(subKey, opts.Delimiter); idx != -1 {
				commonPrefix := opts.Prefix + subKey[:idx+len(opts.Delimiter)]
				if commonPrefix != lastPrefix {
					entries = append(entries, uploadEntry{key: commonPrefix, commonPrefix: true})
					lastPrefix = commonPrefix
				}
				continue
			}
		}
		entries = append(entries, uploadEntry{key: upload.Key, upload: upload})
	}

	// Apply markers: key-marker alone skips every upload of that key;
	// with upload-id-marker, uploads of the marker key with a greater
	// upload ID are included.
	startIdx := 0
	if opts.KeyMarker != "" {
		startIdx = len(entries)
		for i, e := range entries {
			if e.key > opts.KeyMarker ||
				(opts.UploadIdMarker != "" && !e.commonPrefix &&
					e.key == opts.KeyMarker && e.upload.UploadId > opts.UploadIdMarker) {
				startIdx = i
				break
			}
		}
	}
	entries = entries[startIdx:]

	// Apply max uploads limit
	maxUploads := opts.MaxUploads
	if maxUploads <= 0 {
		maxUploads = 1000
	}

	result := &ListMultipartUploadsInternalResult{}
	if len(entries) > maxUploads {
		result.IsTruncated = true
		last := entries[maxUploads-1]
		result.NextKeyMarker = last.key
		if !last.commonPrefix {
			result.NextUploadIdMarker = last.upload.UploadId
		}
		entries = entries[:maxUploads]
	}

	for _, e := range entries {
		if e.commonPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, e.key)
		} else {
			result.Uploads = append(result.Uploads, e.upload)
		}
	}

	return result, nil
}

// ListPartsOptions contains options for ListParts.
type ListPartsOptions struct {
	PartNumberMarker int
	MaxParts         int
}

// ListPartsInternalResult contains the result of ListParts.
type ListPartsInternalResult struct {
	Parts                []*PartInfo
	IsTruncated          bool
	NextPartNumberMarker int
}

// ListParts lists parts that have been uploaded for a specific multipart upload.
func (b *Backend) ListParts(
	bucketName, key, uploadId string,
	opts ListPartsOptions,
) (*ListPartsInternalResult, *MultipartUpload, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	upload, ok := b.uploads[uploadId]
	if !ok {
		return nil, nil, ErrNoSuchUpload
	}

	if upload.Bucket != bucketName || upload.Key != key {
		return nil, nil, ErrNoSuchUpload
	}

	// Collect and sort parts
	var parts []*PartInfo
	for _, part := range upload.Parts {
		if part.PartNumber > opts.PartNumberMarker {
			parts = append(parts, part)
		}
	}

	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	result := &ListPartsInternalResult{}

	// Apply max parts limit
	maxParts := opts.MaxParts
	if maxParts <= 0 {
		maxParts = 1000
	}

	if len(parts) > maxParts {
		result.IsTruncated = true
		result.NextPartNumberMarker = parts[maxParts-1].PartNumber
		parts = parts[:maxParts]
	}

	result.Parts = parts
	return result, upload, nil
}

// CopyPart copies a part from an existing object.
func (b *Backend) CopyPart(
	srcBucket, srcKey, srcVersionId, dstBucket, dstKey, uploadId string,
	partNumber int,
	rangeStart, rangeEnd int64, // -1 means not specified
) (*PartInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Verify upload exists
	upload, ok := b.uploads[uploadId]
	if !ok {
		return nil, ErrNoSuchUpload
	}

	if upload.Bucket != dstBucket || upload.Key != dstKey {
		return nil, ErrNoSuchUpload
	}

	// Validate part number (1-10000)
	if partNumber < 1 || partNumber > 10000 {
		return nil, ErrInvalidRequest
	}

	// Get source object
	srcBkt, ok := b.buckets[srcBucket]
	if !ok {
		return nil, ErrSourceBucketNotFound
	}

	srcVersions, ok := srcBkt.Objects[srcKey]
	if !ok || len(srcVersions.Versions) == 0 {
		return nil, ErrSourceObjectNotFound
	}

	var srcObj *Object
	if srcVersionId != "" {
		for _, v := range srcVersions.Versions {
			if v.VersionId == srcVersionId {
				srcObj = v
				break
			}
		}
		if srcObj == nil {
			return nil, ErrVersionNotFound
		}
		if srcObj.IsDeleteMarker {
			return nil, ErrCopySourceDeleteMarker
		}
	} else {
		srcObj = srcVersions.getLatestVersion()
		if srcObj == nil {
			return nil, ErrSourceObjectNotFound
		}
	}

	// Get the data range
	var data []byte
	if rangeStart < 0 {
		data = srcObj.Data
	} else {
		// Validate range
		if rangeStart >= srcObj.Size {
			return nil, ErrInvalidRange
		}
		if rangeEnd >= srcObj.Size {
			return nil, ErrInvalidRange
		}
		if rangeEnd < 0 {
			rangeEnd = srcObj.Size - 1
		}
		if rangeStart > rangeEnd {
			return nil, ErrInvalidRange
		}
		data = srcObj.Data[rangeStart : rangeEnd+1]
	}

	// Calculate ETag
	md5Hash := md5.New()
	_, _ = io.Copy(md5Hash, bytes.NewReader(data))
	etag := fmt.Sprintf("\"%x\"", md5Hash.Sum(nil))

	part := &PartInfo{
		PartNumber:   partNumber,
		ETag:         etag,
		Size:         int64(len(data)),
		Data:         data,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	}
	// Copied parts carry the upload's checksum like uploaded parts do, so
	// ListParts and composite checksums see every part.
	setPartChecksum(part, upload.ChecksumAlgorithm, data)

	upload.Parts[partNumber] = part
	return part, nil
}

// GetUpload returns a multipart upload by its upload ID.
func (b *Backend) GetUpload(uploadId string) (*MultipartUpload, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	upload, ok := b.uploads[uploadId]
	return upload, ok
}
