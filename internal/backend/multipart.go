package backend

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"time"
)

// CreateMultipartUploadOptions contains options for CreateMultipartUpload.
type CreateMultipartUploadOptions struct {
	ContentType string
	Metadata    map[string]string
}

// CreateMultipartUpload initiates a multipart upload and returns an upload ID.
func (b *Backend) CreateMultipartUpload(
	bucketName, key string,
	opts CreateMultipartUploadOptions,
) (*MultipartUpload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.buckets[bucketName]; !ok {
		return nil, ErrBucketNotFound
	}

	uploadId := GenerateVersionId()
	upload := &MultipartUpload{
		UploadId:    uploadId,
		Bucket:      bucketName,
		Key:         key,
		Initiated:   time.Now().UTC().Format(time.RFC3339),
		Parts:       make(map[int]*PartInfo),
		ContentType: opts.ContentType,
		Metadata:    opts.Metadata,
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

	upload, ok := b.uploads[uploadId]
	if !ok {
		return nil, ErrNoSuchUpload
	}

	if upload.Bucket != bucketName || upload.Key != key {
		return nil, ErrNoSuchUpload
	}

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	if len(parts) == 0 {
		return nil, ErrInvalidPart
	}

	// Validate parts are in ascending order and exist
	var lastPartNumber int
	var combinedData bytes.Buffer
	var partETags []string

	for _, p := range parts {
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
		if p.PartNumber != parts[len(parts)-1].PartNumber && uploadedPart.Size < 5*1024*1024 {
			return nil, ErrEntityTooSmall
		}

		combinedData.Write(uploadedPart.Data)
		partETags = append(partETags, uploadedETag)
	}

	// Calculate final ETag (S3 multipart ETag format: MD5-of-MD5s-numberOfParts)
	md5Hash := md5.New()
	for _, etag := range partETags {
		decoded, _ := decodeHex(etag)
		md5Hash.Write(decoded)
	}
	finalETag := fmt.Sprintf("\"%x-%d\"", md5Hash.Sum(nil), len(parts))

	// Calculate checksums
	data := combinedData.Bytes()
	crc32Hash := crc32.NewIEEE()
	_, _ = crc32Hash.Write(data)

	// Determine version ID
	var versionId string
	switch bucket.VersioningStatus {
	case VersioningEnabled:
		versionId = GenerateVersionId()
	default:
		versionId = NullVersionId
	}

	contentType := upload.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	obj := &Object{
		Key:            key,
		VersionId:      versionId,
		IsLatest:       true,
		IsDeleteMarker: false,
		LastModified:   time.Now().UTC(),
		ETag:           finalETag,
		Size:           int64(len(data)),
		ContentType:    contentType,
		Data:           data,
		ChecksumCRC32:  base64.StdEncoding.EncodeToString(crc32Hash.Sum(nil)),
		Metadata:       upload.Metadata,
	}

	addVersionToObject(bucket, key, obj)

	// Clean up the upload
	delete(b.uploads, uploadId)

	return obj, nil
}

// decodeHex decodes a hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")

	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}

	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		result[i/2] = b
	}
	return result, nil
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

	// Sort by key, then by upload ID
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key != uploads[j].Key {
			return uploads[i].Key < uploads[j].Key
		}
		return uploads[i].UploadId < uploads[j].UploadId
	})

	result := &ListMultipartUploadsInternalResult{}
	commonPrefixSet := make(map[string]struct{})

	// Filter by markers
	markerReached := opts.KeyMarker == ""
	var filtered []*MultipartUpload

	for _, upload := range uploads {
		// Apply key marker
		if !markerReached {
			if upload.Key > opts.KeyMarker {
				markerReached = true
			} else if upload.Key == opts.KeyMarker && opts.UploadIdMarker != "" {
				if upload.UploadId > opts.UploadIdMarker {
					markerReached = true
				} else {
					continue
				}
			} else {
				continue
			}
		}

		// Apply prefix filter
		if opts.Prefix != "" && !strings.HasPrefix(upload.Key, opts.Prefix) {
			continue
		}

		// Handle delimiter
		if opts.Delimiter != "" {
			subKey := upload.Key[len(opts.Prefix):]
			if idx := strings.Index(subKey, opts.Delimiter); idx != -1 {
				commonPrefix := opts.Prefix + subKey[:idx+len(opts.Delimiter)]
				commonPrefixSet[commonPrefix] = struct{}{}
				continue
			}
		}

		filtered = append(filtered, upload)
	}

	// Apply max uploads limit
	maxUploads := opts.MaxUploads
	if maxUploads <= 0 {
		maxUploads = 1000
	}

	if len(filtered) > maxUploads {
		result.IsTruncated = true
		result.NextKeyMarker = filtered[maxUploads-1].Key
		result.NextUploadIdMarker = filtered[maxUploads-1].UploadId
		filtered = filtered[:maxUploads]
	}

	result.Uploads = filtered
	for cp := range commonPrefixSet {
		result.CommonPrefixes = append(result.CommonPrefixes, cp)
	}
	sort.Strings(result.CommonPrefixes)

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
	srcBucket, srcKey, dstBucket, dstKey, uploadId string,
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

	// Get source object
	srcBkt, ok := b.buckets[srcBucket]
	if !ok {
		return nil, ErrSourceBucketNotFound
	}

	srcVersions, ok := srcBkt.Objects[srcKey]
	if !ok || len(srcVersions.Versions) == 0 {
		return nil, ErrSourceObjectNotFound
	}

	srcObj := srcVersions.getLatestVersion()
	if srcObj == nil {
		return nil, ErrSourceObjectNotFound
	}

	// Get the data range
	var data []byte
	if rangeStart < 0 {
		data = srcObj.Data
	} else {
		if rangeEnd < 0 || rangeEnd >= srcObj.Size {
			rangeEnd = srcObj.Size - 1
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

	upload.Parts[partNumber] = part
	return part, nil
}
