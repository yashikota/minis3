package backend

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// forceDeleteLockedObjects indicates whether to bypass Object Lock for test purposes.
var (
	forceDeleteLockedObjects     bool
	forceDeleteLockedObjectsOnce sync.Once
)

func isForceDeleteLockedObjectsEnabled() bool {
	forceDeleteLockedObjectsOnce.Do(func() {
		forceDeleteLockedObjects = strings.EqualFold(
			strings.TrimSpace(os.Getenv("MINIS3_FORCE_DELETE_LOCKED_OBJECTS")),
			"true",
		)
	})
	return forceDeleteLockedObjects
}

// Inverted NVME polynomial value used by Go's crc64 implementation.
const crc64NVME = 0x9a6c9329ac4bc9b5

// isObjectLocked checks whether an object is locked and cannot be deleted.
// If MINIS3_FORCE_DELETE_LOCKED_OBJECTS=true, always returns false for test purposes.
func isObjectLocked(obj *Object, bypassGovernance bool) bool {
	if isForceDeleteLockedObjectsEnabled() {
		return false
	}
	if obj.LegalHoldStatus == LegalHoldStatusOn {
		return true
	}
	if obj.RetainUntilDate != nil && obj.RetainUntilDate.After(time.Now().UTC()) {
		if obj.RetentionMode == RetentionModeCompliance {
			return true
		}
		if obj.RetentionMode == RetentionModeGovernance && !bypassGovernance {
			return true
		}
	}
	return false
}

// getLatestVersion returns the latest non-DeleteMarker version of an object.
// Returns nil if no such version exists.
func (ov *ObjectVersions) getLatestVersion() *Object {
	for _, v := range ov.Versions {
		if !v.IsDeleteMarker {
			return v
		}
	}
	return nil
}

// getCurrentVisibleVersion returns the current version only when it is not a delete marker.
// This is used by list APIs where a current delete marker should hide the key.
func (ov *ObjectVersions) getCurrentVisibleVersion() *Object {
	if ov == nil || len(ov.Versions) == 0 {
		return nil
	}
	if ov.Versions[0].IsDeleteMarker {
		return nil
	}
	return ov.Versions[0]
}

// addVersionToObject adds a new version to an object's version list.
// This handles versioning-enabled buckets (prepend new version) and
// unset/suspended buckets (replace null version).
// Caller must hold the lock.
func addVersionToObject(bucket *Bucket, key string, obj *Object) {
	// Get or create ObjectVersions
	versions, exists := bucket.Objects[key]
	if !exists {
		versions = &ObjectVersions{}
		bucket.Objects[key] = versions
	}

	// Update IsLatest for all existing versions
	for _, v := range versions.Versions {
		v.IsLatest = false
	}

	if bucket.VersioningStatus == VersioningEnabled {
		// Versioning enabled: prepend new version
		versions.Versions = append([]*Object{obj}, versions.Versions...)
	} else {
		// Unset or Suspended: replace null version or add if none exists
		newVersions := make([]*Object, 0, len(versions.Versions))
		for _, v := range versions.Versions {
			if v.VersionId != NullVersionId {
				newVersions = append(newVersions, v)
			}
		}
		// Prepend new null version
		versions.Versions = append([]*Object{obj}, newVersions...)
	}
}

func checksumCRC64NVMEBase64(data []byte) string {
	table := crc64.MakeTable(crc64NVME)
	sum := crc64.Checksum(data, table)
	buf := []byte{
		byte(sum >> 56), byte(sum >> 48), byte(sum >> 40), byte(sum >> 32),
		byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func checksumForAlgorithm(algorithm string, data []byte) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "CRC32":
		h := crc32.NewIEEE()
		_, _ = h.Write(data)
		return base64.StdEncoding.EncodeToString(h.Sum(nil)), true
	case "CRC32C":
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		_, _ = h.Write(data)
		return base64.StdEncoding.EncodeToString(h.Sum(nil)), true
	case "CRC64NVME":
		return checksumCRC64NVMEBase64(data), true
	case "SHA1":
		sum := sha1.Sum(data)
		return base64.StdEncoding.EncodeToString(sum[:]), true
	case "SHA256":
		sum := sha256.Sum256(data)
		return base64.StdEncoding.EncodeToString(sum[:]), true
	default:
		return "", false
	}
}

// ComputeChecksumBase64 computes a base64 checksum value for a supported algorithm.
// It returns false when the algorithm is unsupported.
func ComputeChecksumBase64(algorithm string, data []byte) (string, bool) {
	return checksumForAlgorithm(algorithm, data)
}

func providedChecksumForPut(algorithm string, opts PutObjectOptions) string {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "CRC32":
		return opts.ChecksumCRC32
	case "CRC32C":
		return opts.ChecksumCRC32C
	case "CRC64NVME":
		return opts.ChecksumCRC64NVME
	case "SHA1":
		return opts.ChecksumSHA1
	case "SHA256":
		return opts.ChecksumSHA256
	default:
		return ""
	}
}

// createDeleteMarkerUnlocked creates a delete marker based on the bucket's versioning status.
// Returns the result of the delete operation.
// Caller must hold the lock.
func createDeleteMarkerUnlocked(bucket *Bucket, key string) *DeleteObjectVersionResult {
	versions, exists := bucket.Objects[key]

	switch bucket.VersioningStatus {
	case VersioningEnabled:
		// Create DeleteMarker
		if !exists {
			versions = &ObjectVersions{}
			bucket.Objects[key] = versions
		}

		// Update IsLatest for existing versions
		for _, v := range versions.Versions {
			v.IsLatest = false
		}

		deleteMarker := &Object{
			Key:            key,
			VersionId:      GenerateVersionId(),
			IsLatest:       true,
			IsDeleteMarker: true,
			LastModified:   time.Now().UTC(),
		}
		versions.Versions = append([]*Object{deleteMarker}, versions.Versions...)

		return &DeleteObjectVersionResult{
			VersionId:      deleteMarker.VersionId,
			IsDeleteMarker: true,
			DeletedObject:  deleteMarker,
		}

	case VersioningSuspended:
		// Delete null version if exists, create null DeleteMarker
		if !exists {
			versions = &ObjectVersions{}
			bucket.Objects[key] = versions
		}

		// Remove existing null version
		var deletedObj *Object
		newVersions := make([]*Object, 0, len(versions.Versions))
		for _, v := range versions.Versions {
			if v.VersionId == NullVersionId {
				deletedObj = v
			} else {
				v.IsLatest = false
				newVersions = append(newVersions, v)
			}
		}

		// Create null DeleteMarker
		deleteMarker := &Object{
			Key:            key,
			VersionId:      NullVersionId,
			IsLatest:       true,
			IsDeleteMarker: true,
			LastModified:   time.Now().UTC(),
		}
		versions.Versions = append([]*Object{deleteMarker}, newVersions...)

		result := &DeleteObjectVersionResult{
			VersionId:      NullVersionId,
			IsDeleteMarker: true,
			DeletedObject:  deleteMarker,
		}
		if deletedObj != nil {
			result.DeletedObject = deletedObj
		}
		return result

	default:
		// VersioningUnset: physically delete
		if exists {
			delete(bucket.Objects, key)
		}
		return &DeleteObjectVersionResult{}
	}
}

// PutObject stores an object in a bucket.
// Returns the created object with its version ID.
func (b *Backend) PutObject(
	bucketName, key string,
	data []byte,
	opts PutObjectOptions,
) (*Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	md5Hash := md5.New()
	_, _ = md5Hash.Write(data)

	// Determine version ID based on versioning status
	var versionId string
	switch bucket.VersioningStatus {
	case VersioningEnabled:
		versionId = GenerateVersionId()
	default:
		// VersioningUnset or VersioningSuspended: use "null"
		versionId = NullVersionId
	}

	// Apply bucket default encryption if no explicit SSE is specified
	if opts.ServerSideEncryption == "" && opts.SSECustomerAlgorithm == "" {
		if bucket.EncryptionConfiguration != nil && len(bucket.EncryptionConfiguration.Rules) > 0 {
			rule := bucket.EncryptionConfiguration.Rules[0]
			if rule.ApplyServerSideEncryptionByDefault != nil {
				opts.ServerSideEncryption = rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				if opts.SSEKMSKeyId == "" {
					opts.SSEKMSKeyId = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
				}
			}
		}
	}

	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	storageClass := opts.StorageClass
	if storageClass == "" {
		storageClass = "STANDARD"
	}
	owner := opts.Owner
	if owner == nil {
		owner = OwnerForAccessKey(bucket.OwnerAccessKey)
	}
	if owner == nil {
		owner = DefaultOwner()
	}
	if strings.EqualFold(bucket.ObjectOwnership, ObjectOwnershipBucketOwnerEnforced) {
		owner = OwnerForAccessKey(bucket.OwnerAccessKey)
		if owner == nil {
			owner = DefaultOwner()
		}
	}

	obj := &Object{
		Key:                     key,
		VersionId:               versionId,
		IsLatest:                true,
		IsDeleteMarker:          false,
		LastModified:            time.Now().UTC(),
		ETag:                    fmt.Sprintf("\"%x\"", md5Hash.Sum(nil)),
		Size:                    int64(len(data)),
		ContentType:             contentType,
		Data:                    data,
		ChecksumAlgorithm:       strings.ToUpper(strings.TrimSpace(opts.ChecksumAlgorithm)),
		Metadata:                opts.Metadata,
		Owner:                   owner,
		ACL:                     NewDefaultACLForOwner(owner),
		CacheControl:            opts.CacheControl,
		Expires:                 opts.Expires,
		ContentEncoding:         opts.ContentEncoding,
		ContentLanguage:         opts.ContentLanguage,
		ContentDisposition:      opts.ContentDisposition,
		Tags:                    opts.Tags,
		StorageClass:            storageClass,
		ServerSideEncryption:    opts.ServerSideEncryption,
		SSEKMSKeyId:             opts.SSEKMSKeyId,
		SSECustomerAlgorithm:    opts.SSECustomerAlgorithm,
		SSECustomerKeyMD5:       opts.SSECustomerKeyMD5,
		WebsiteRedirectLocation: opts.WebsiteRedirectLocation,
	}

	// Compute checksum and validate client-provided value if present.
	algorithm := obj.ChecksumAlgorithm
	if computed, ok := checksumForAlgorithm(algorithm, data); ok {
		provided := providedChecksumForPut(algorithm, opts)
		if provided != "" && provided != computed {
			return nil, ErrBadDigest
		}
		value := computed
		if provided != "" {
			value = provided
		}
		switch algorithm {
		case "CRC32":
			obj.ChecksumCRC32 = value
		case "CRC32C":
			obj.ChecksumCRC32C = value
		case "CRC64NVME":
			obj.ChecksumCRC64NVME = value
		case "SHA1":
			obj.ChecksumSHA1 = value
		case "SHA256":
			obj.ChecksumSHA256 = value
		}
	}

	// Set Object Lock fields if provided
	if opts.RetentionMode != "" || opts.LegalHoldStatus != "" {
		if !bucket.ObjectLockEnabled {
			return nil, ErrInvalidRequest
		}
		obj.RetentionMode = opts.RetentionMode
		obj.RetainUntilDate = opts.RetainUntilDate
		obj.LegalHoldStatus = opts.LegalHoldStatus
	}

	// Apply bucket default retention when no explicit retention was set
	applyDefaultRetention(bucket, obj)

	addVersionToObject(bucket, key, obj)

	return obj, nil
}

// GetObject retrieves the latest version of an object from a bucket.
func (b *Backend) GetObject(bucketName, key string) (*Object, error) {
	return b.GetObjectVersion(bucketName, key, "")
}

// GetObjectVersion retrieves a specific version of an object.
// If versionId is empty, returns the latest version (which may be a DeleteMarker).
// Callers should check IsDeleteMarker and handle appropriately.
func (b *Backend) GetObjectVersion(bucketName, key, versionId string) (*Object, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return nil, ErrObjectNotFound
	}

	if versionId == "" {
		// Return the latest version (may be a DeleteMarker)
		// Caller should check IsDeleteMarker
		return versions.Versions[0], nil
	}

	// Find specific version
	for _, v := range versions.Versions {
		if v.VersionId == versionId {
			return v, nil
		}
	}

	return nil, ErrVersionNotFound
}

// DeleteObjectResult contains the result of deleting an object or version.
type DeleteObjectVersionResult struct {
	VersionId      string
	IsDeleteMarker bool
	DeletedObject  *Object // The object that was deleted/created
}

// DeleteObject removes an object from a bucket.
// With versioning enabled, creates a DeleteMarker instead of deleting.
// Returns information about the deletion.
func (b *Backend) DeleteObject(
	bucketName, key string,
	bypassGovernance bool,
) (*DeleteObjectVersionResult, error) {
	return b.DeleteObjectVersion(bucketName, key, "", bypassGovernance)
}

// DeleteObjectVersion deletes a specific version or creates a DeleteMarker.
// If versionId is empty and versioning is enabled, creates a DeleteMarker.
// If versionId is specified, physically deletes that version.
// Object Lock is only checked when deleting a specific version (not when creating a delete marker).
func (b *Backend) DeleteObjectVersion(
	bucketName, key, versionId string, bypassGovernance bool,
) (*DeleteObjectVersionResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	versions, exists := bucket.Objects[key]

	if versionId != "" {
		// Delete specific version
		if !exists {
			return nil, ErrObjectNotFound
		}

		// Find and remove the version
		var deletedObj *Object
		var isDeleteMarker bool
		newVersions := make([]*Object, 0, len(versions.Versions))
		for _, v := range versions.Versions {
			if v.VersionId == versionId {
				deletedObj = v
				isDeleteMarker = v.IsDeleteMarker
			} else {
				newVersions = append(newVersions, v)
			}
		}

		if deletedObj == nil {
			return nil, ErrVersionNotFound
		}

		// Check Object Lock before allowing physical deletion of a specific version
		if !deletedObj.IsDeleteMarker && isObjectLocked(deletedObj, bypassGovernance) {
			return nil, ErrObjectLocked
		}

		versions.Versions = newVersions

		// Update IsLatest for remaining versions
		if len(versions.Versions) > 0 {
			versions.Versions[0].IsLatest = true
		}

		// Clean up empty ObjectVersions
		if len(versions.Versions) == 0 {
			delete(bucket.Objects, key)
		}

		return &DeleteObjectVersionResult{
			VersionId:      versionId,
			IsDeleteMarker: isDeleteMarker,
			DeletedObject:  deletedObj,
		}, nil
	}

	// No versionId specified: create delete marker or physically delete
	return createDeleteMarkerUnlocked(bucket, key), nil
}

// CopyObjectOptions contains options for CopyObject operation.
type CopyObjectOptions struct {
	MetadataDirective  string            // "COPY" (default) or "REPLACE"
	Metadata           map[string]string // Used when MetadataDirective is "REPLACE"
	ContentType        string            // Used when MetadataDirective is "REPLACE"
	CacheControl       string
	Expires            *time.Time
	ContentEncoding    string
	ContentLanguage    string
	ContentDisposition string
	TaggingDirective   string            // "COPY" (default) or "REPLACE"
	Tags               map[string]string // Used when TaggingDirective is "REPLACE"
	// Object Lock fields (override source object's lock settings)
	RetentionMode   string
	RetainUntilDate *time.Time
	LegalHoldStatus string
	// Server-Side Encryption fields
	ServerSideEncryption string
	SSEKMSKeyId          string
	SSECustomerAlgorithm string
	SSECustomerKeyMD5    string
	// Storage class
	StorageClass string
	// Website redirect
	WebsiteRedirectLocation string
	// Checksum
	ChecksumAlgorithm string
}

// CopyObject copies an object from source to destination.
// If srcVersionId is specified, copies that specific version.
// Returns the copied object and the source version ID that was used.
func (b *Backend) CopyObject(
	srcBucket, srcKey, srcVersionId, dstBucket, dstKey string,
	opts CopyObjectOptions,
) (*Object, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	srcBkt, ok := b.buckets[srcBucket]
	if !ok {
		return nil, "", ErrSourceBucketNotFound
	}

	srcVersions, ok := srcBkt.Objects[srcKey]
	if !ok || len(srcVersions.Versions) == 0 {
		return nil, "", ErrSourceObjectNotFound
	}

	var srcObj *Object
	var actualVersionId string

	if srcVersionId != "" {
		// Find specific version
		for _, v := range srcVersions.Versions {
			if v.VersionId == srcVersionId {
				srcObj = v
				actualVersionId = v.VersionId
				break
			}
		}
		if srcObj == nil {
			return nil, "", ErrVersionNotFound
		}
		if srcObj.IsDeleteMarker {
			return nil, "", ErrSourceObjectNotFound
		}
	} else {
		// Get latest non-DeleteMarker version
		srcObj = srcVersions.getLatestVersion()
		if srcObj == nil {
			return nil, "", ErrSourceObjectNotFound
		}
		actualVersionId = srcObj.VersionId
	}

	dstBkt, ok := b.buckets[dstBucket]
	if !ok {
		return nil, "", ErrDestinationBucketNotFound
	}

	copiedData := make([]byte, len(srcObj.Data))
	copy(copiedData, srcObj.Data)

	// Determine version ID for destination
	var versionId string
	switch dstBkt.VersioningStatus {
	case VersioningEnabled:
		versionId = GenerateVersionId()
	default:
		versionId = NullVersionId
	}

	obj := &Object{
		Key:               dstKey,
		VersionId:         versionId,
		IsLatest:          true,
		IsDeleteMarker:    false,
		LastModified:      time.Now().UTC(),
		ETag:              srcObj.ETag,
		Size:              srcObj.Size,
		Data:              copiedData,
		ChecksumCRC32:     srcObj.ChecksumCRC32,
		ChecksumCRC32C:    srcObj.ChecksumCRC32C,
		ChecksumCRC64NVME: srcObj.ChecksumCRC64NVME,
		ChecksumSHA1:      srcObj.ChecksumSHA1,
		ChecksumSHA256:    srcObj.ChecksumSHA256,
		ChecksumAlgorithm: srcObj.ChecksumAlgorithm,
		Owner:             srcObj.Owner,
		ACL:               srcObj.ACL,
	}

	// Override ChecksumAlgorithm if specified in opts and recompute
	if opts.ChecksumAlgorithm != "" {
		obj.ChecksumAlgorithm = opts.ChecksumAlgorithm
		obj.ChecksumCRC32 = ""
		obj.ChecksumCRC32C = ""
		obj.ChecksumCRC64NVME = ""
		obj.ChecksumSHA1 = ""
		obj.ChecksumSHA256 = ""
		switch strings.ToUpper(opts.ChecksumAlgorithm) {
		case "CRC32":
			crc32Hash := crc32.NewIEEE()
			_, _ = crc32Hash.Write(copiedData)
			obj.ChecksumCRC32 = base64.StdEncoding.EncodeToString(crc32Hash.Sum(nil))
		case "CRC32C":
			crc32cTable := crc32.MakeTable(crc32.Castagnoli)
			crc32cHash := crc32.New(crc32cTable)
			_, _ = crc32cHash.Write(copiedData)
			obj.ChecksumCRC32C = base64.StdEncoding.EncodeToString(crc32cHash.Sum(nil))
		case "CRC64NVME":
			obj.ChecksumCRC64NVME = checksumCRC64NVMEBase64(copiedData)
		case "SHA1":
			sha1Hash := sha1.Sum(copiedData)
			obj.ChecksumSHA1 = base64.StdEncoding.EncodeToString(sha1Hash[:])
		case "SHA256":
			sha256Hash := sha256.Sum256(copiedData)
			obj.ChecksumSHA256 = base64.StdEncoding.EncodeToString(sha256Hash[:])
		}
	}

	// Handle metadata directive
	if opts.MetadataDirective == "REPLACE" {
		// Use new metadata from options
		contentType := opts.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		obj.ContentType = contentType
		obj.Metadata = opts.Metadata
		obj.CacheControl = opts.CacheControl
		obj.Expires = opts.Expires
		obj.ContentEncoding = opts.ContentEncoding
		obj.ContentLanguage = opts.ContentLanguage
		obj.ContentDisposition = opts.ContentDisposition
	} else {
		// Default: COPY - copy metadata from source
		obj.ContentType = srcObj.ContentType
		obj.CacheControl = srcObj.CacheControl
		obj.ContentEncoding = srcObj.ContentEncoding
		obj.ContentLanguage = srcObj.ContentLanguage
		obj.ContentDisposition = srcObj.ContentDisposition
		if srcObj.Expires != nil {
			expires := *srcObj.Expires
			obj.Expires = &expires
		}
		if srcObj.Metadata != nil {
			obj.Metadata = make(map[string]string, len(srcObj.Metadata))
			for k, v := range srcObj.Metadata {
				obj.Metadata[k] = v
			}
		}
	}

	// Handle tagging directive
	if opts.TaggingDirective == "REPLACE" {
		obj.Tags = opts.Tags
	} else {
		// Default: COPY - copy tags from source
		if srcObj.Tags != nil {
			obj.Tags = make(map[string]string, len(srcObj.Tags))
			for k, v := range srcObj.Tags {
				obj.Tags[k] = v
			}
		}
	}

	// Handle Object Lock fields
	if opts.RetentionMode != "" || opts.LegalHoldStatus != "" {
		// Explicit override: destination bucket must have Object Lock enabled
		if !dstBkt.ObjectLockEnabled {
			return nil, "", ErrInvalidRequest
		}
		obj.RetentionMode = opts.RetentionMode
		obj.RetainUntilDate = opts.RetainUntilDate
		obj.LegalHoldStatus = opts.LegalHoldStatus
	} else if dstBkt.ObjectLockEnabled {
		// Copy from source if destination bucket has Object Lock enabled
		obj.RetentionMode = srcObj.RetentionMode
		if srcObj.RetainUntilDate != nil {
			t := *srcObj.RetainUntilDate
			obj.RetainUntilDate = &t
		}
		obj.LegalHoldStatus = srcObj.LegalHoldStatus
	}

	// Handle WebsiteRedirectLocation
	if opts.WebsiteRedirectLocation != "" {
		obj.WebsiteRedirectLocation = opts.WebsiteRedirectLocation
	} else {
		obj.WebsiteRedirectLocation = srcObj.WebsiteRedirectLocation
	}

	// Handle StorageClass
	if opts.StorageClass != "" {
		obj.StorageClass = opts.StorageClass
	} else if srcObj.StorageClass != "" {
		obj.StorageClass = srcObj.StorageClass
	} else {
		obj.StorageClass = "STANDARD"
	}

	// Handle Server-Side Encryption
	if opts.ServerSideEncryption != "" || opts.SSECustomerAlgorithm != "" {
		// Explicit SSE specified for destination
		obj.ServerSideEncryption = opts.ServerSideEncryption
		obj.SSEKMSKeyId = opts.SSEKMSKeyId
		obj.SSECustomerAlgorithm = opts.SSECustomerAlgorithm
		obj.SSECustomerKeyMD5 = opts.SSECustomerKeyMD5
	} else {
		// Copy SSE-S3/SSE-KMS from source, but NOT SSE-C (SSE-C requires explicit key per request)
		obj.ServerSideEncryption = srcObj.ServerSideEncryption
		obj.SSEKMSKeyId = srcObj.SSEKMSKeyId
	}

	// Apply bucket default encryption if no explicit SSE is specified
	if obj.ServerSideEncryption == "" && obj.SSECustomerAlgorithm == "" {
		if dstBkt.EncryptionConfiguration != nil && len(dstBkt.EncryptionConfiguration.Rules) > 0 {
			rule := dstBkt.EncryptionConfiguration.Rules[0]
			if rule.ApplyServerSideEncryptionByDefault != nil {
				obj.ServerSideEncryption = rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm
				if obj.SSEKMSKeyId == "" {
					obj.SSEKMSKeyId = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
				}
			}
		}
	}
	if strings.EqualFold(dstBkt.ObjectOwnership, ObjectOwnershipBucketOwnerEnforced) {
		obj.Owner = OwnerForAccessKey(dstBkt.OwnerAccessKey)
		obj.ACL = NewDefaultACLForOwner(obj.Owner)
	}

	// Apply bucket default retention when no explicit retention was set
	applyDefaultRetention(dstBkt, obj)

	addVersionToObject(dstBkt, dstKey, obj)

	return obj, actualVersionId, nil
}

// DeleteObjects deletes multiple objects from a bucket.
// If VersionId is specified for an object, that specific version is deleted.
// If VersionId is empty, behavior depends on versioning:
//   - Enabled: creates a delete marker
//   - Suspended: creates a null delete marker
//   - Unset: physically deletes the object
func (b *Backend) DeleteObjects(
	bucketName string,
	objects []ObjectIdentifier,
	bypassGovernance bool,
) ([]DeleteObjectsResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	results := make([]DeleteObjectsResult, 0, len(objects))
	for _, obj := range objects {
		result := DeleteObjectsResult{
			Key:       obj.Key,
			VersionId: obj.VersionId,
		}
		versions, exists := bucket.Objects[obj.Key]
		var targetObj *Object
		if exists && len(versions.Versions) > 0 {
			if obj.VersionId == "" {
				targetObj = versions.Versions[0]
			} else {
				for _, v := range versions.Versions {
					if v.VersionId == obj.VersionId {
						targetObj = v
						break
					}
				}
			}
		}
		if obj.ETag != "" {
			if targetObj != nil {
				if strings.TrimSpace(obj.ETag) != "*" &&
					(targetObj.IsDeleteMarker || !matchesDeleteETag(obj.ETag, targetObj.ETag)) {
					result.Error = ErrPreconditionFailed
					results = append(results, result)
					continue
				}
			}
		}
		if obj.LastModifiedTime != "" {
			t, err := parseDeletePreconditionTime(obj.LastModifiedTime)
			if err != nil {
				result.Error = ErrPreconditionFailed
				results = append(results, result)
				continue
			}
			if targetObj != nil &&
				!targetObj.LastModified.UTC().
					Truncate(time.Second).
					Equal(t.UTC().Truncate(time.Second)) {
				result.Error = ErrPreconditionFailed
				results = append(results, result)
				continue
			}
		}
		if obj.Size != nil {
			if targetObj != nil && targetObj.Size != *obj.Size {
				result.Error = ErrPreconditionFailed
				results = append(results, result)
				continue
			}
		}

		if obj.VersionId != "" {
			// Delete specific version
			if !exists {
				// S3 returns success even if key doesn't exist when VersionId is specified
				results = append(results, result)
				continue
			}

			// Find and remove the version
			found := false
			var foundObj *Object
			newVersions := make([]*Object, 0, len(versions.Versions))
			for _, v := range versions.Versions {
				if v.VersionId == obj.VersionId {
					found = true
					foundObj = v
					result.DeleteMarker = v.IsDeleteMarker
				} else {
					newVersions = append(newVersions, v)
				}
			}

			if !found {
				// Version not found, but S3 returns success
				results = append(results, result)
				continue
			}

			// Check Object Lock before allowing physical deletion
			if foundObj != nil && !foundObj.IsDeleteMarker &&
				isObjectLocked(foundObj, bypassGovernance) {
				result.Error = ErrObjectLocked
				results = append(results, result)
				continue
			}

			versions.Versions = newVersions

			// Update IsLatest for remaining versions
			if len(versions.Versions) > 0 {
				versions.Versions[0].IsLatest = true
			}

			// Clean up empty ObjectVersions
			if len(versions.Versions) == 0 {
				delete(bucket.Objects, obj.Key)
			}
		} else {
			// No VersionId specified: create delete marker or physically delete
			deleteResult := createDeleteMarkerUnlocked(bucket, obj.Key)
			if deleteResult != nil {
				result.DeleteMarker = deleteResult.IsDeleteMarker
				if deleteResult.IsDeleteMarker {
					result.DeleteMarkerVersionId = deleteResult.VersionId
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func matchesDeleteETag(conditionETag, objectETag string) bool {
	if conditionETag == "*" {
		return true
	}
	normalizedObjectETag := objectETag
	if !strings.HasPrefix(normalizedObjectETag, "\"") {
		normalizedObjectETag = "\"" + normalizedObjectETag + "\""
	}
	for _, candidate := range strings.Split(conditionETag, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		normalizedCandidate := candidate
		if !strings.HasPrefix(normalizedCandidate, "\"") {
			normalizedCandidate = "\"" + normalizedCandidate + "\""
		}
		if normalizedCandidate == normalizedObjectETag || candidate == objectETag {
			return true
		}
	}
	return false
}

func parseDeletePreconditionTime(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, http.TimeFormat} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp")
}

// ListObjectsV1 lists objects with support for prefix, delimiter, marker, and max-keys.
func (b *Backend) ListObjectsV1(
	bucketName, prefix, delimiter, marker string,
	maxKeys int,
) (*ListObjectsV1Result, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	// Collect all keys with their current visible version.
	allKeys := make([]string, 0, len(bucket.Objects))
	keyToObj := make(map[string]*Object)
	for key, versions := range bucket.Objects {
		obj := versions.getCurrentVisibleVersion()
		if obj != nil {
			allKeys = append(allKeys, key)
			keyToObj[key] = obj
		}
	}
	sort.Strings(allKeys)

	type listEntry struct {
		key            string
		isCommonPrefix bool
		object         *Object
	}

	var entries []listEntry
	commonPrefixSet := make(map[string]struct{})

	for _, key := range allKeys {
		if marker != "" && key <= marker {
			continue
		}
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}

		if delimiter != "" {
			subKey := key[len(prefix):]
			if idx := strings.Index(subKey, delimiter); idx != -1 {
				commonPrefix := prefix + subKey[:idx+len(delimiter)]
				commonPrefixSet[commonPrefix] = struct{}{}
				continue
			}
		}
		entries = append(entries, listEntry{key: key, object: keyToObj[key]})
	}

	for cp := range commonPrefixSet {
		// Skip common prefixes that were already returned in previous pages.
		if marker != "" && cp <= marker {
			continue
		}
		entries = append(entries, listEntry{key: cp, isCommonPrefix: true})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	result := &ListObjectsV1Result{}
	// Only truncate if maxKeys > 0 and there are more entries than maxKeys
	if maxKeys > 0 && len(entries) > maxKeys {
		result.IsTruncated = true
		if delimiter != "" {
			result.NextMarker = entries[maxKeys-1].key
		}
		entries = entries[:maxKeys]
	} else if maxKeys == 0 {
		// max-keys=0: return no entries, IsTruncated=false
		entries = nil
	}

	for _, entry := range entries {
		if entry.isCommonPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, entry.key)
		} else {
			result.Objects = append(result.Objects, entry.object)
		}
	}

	return result, nil
}

// ListObjectsV2 lists objects with support for prefix, delimiter, continuation token, and max-keys.
func (b *Backend) ListObjectsV2(
	bucketName, prefix, delimiter, continuationToken, startAfter string,
	maxKeys int,
) (*ListObjectsV2Result, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	// Collect all keys with their current visible version.
	keys := make([]string, 0, len(bucket.Objects))
	keyToObj := make(map[string]*Object)
	for key, versions := range bucket.Objects {
		obj := versions.getCurrentVisibleVersion()
		if obj != nil {
			keys = append(keys, key)
			keyToObj[key] = obj
		}
	}
	sort.Strings(keys)

	result := &ListObjectsV2Result{}
	commonPrefixSet := make(map[string]struct{})

	// Determine the start marker (continuationToken takes precedence over startAfter)
	marker := continuationToken
	if marker == "" {
		marker = startAfter
	}

	for _, key := range keys {
		// Apply marker filter
		if marker != "" && key <= marker {
			continue
		}

		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}

		if delimiter != "" {
			afterPrefix := key[len(prefix):]
			delimIdx := strings.Index(afterPrefix, delimiter)
			if delimIdx >= 0 {
				commonPrefix := prefix + afterPrefix[:delimIdx+len(delimiter)]
				commonPrefixSet[commonPrefix] = struct{}{}
				continue
			}
		}

		result.Objects = append(result.Objects, keyToObj[key])
	}

	commonPrefixes := make([]string, 0, len(commonPrefixSet))
	for cp := range commonPrefixSet {
		// Filter out common prefixes that are <= marker (already returned in previous page)
		if marker != "" && cp <= marker {
			continue
		}
		commonPrefixes = append(commonPrefixes, cp)
	}
	sort.Strings(commonPrefixes)

	type listEntry struct {
		key            string
		isCommonPrefix bool
		object         *Object
	}

	entries := make([]listEntry, 0, len(result.Objects)+len(commonPrefixes))
	for _, obj := range result.Objects {
		entries = append(entries, listEntry{key: obj.Key, isCommonPrefix: false, object: obj})
	}
	for _, cp := range commonPrefixes {
		entries = append(entries, listEntry{key: cp, isCommonPrefix: true})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	totalCount := len(entries)
	// Only truncate if maxKeys > 0 and there are more entries than maxKeys
	if maxKeys > 0 && totalCount > maxKeys {
		result.IsTruncated = true
		// Set NextContinuationToken to the last key in the truncated result
		result.NextContinuationToken = entries[maxKeys-1].key
		entries = entries[:maxKeys]
	} else if maxKeys == 0 {
		// max-keys=0: return no entries, IsTruncated=false
		entries = nil
	}

	result.Objects = nil
	result.CommonPrefixes = nil
	for _, entry := range entries {
		if entry.isCommonPrefix {
			result.CommonPrefixes = append(result.CommonPrefixes, entry.key)
		} else {
			result.Objects = append(result.Objects, entry.object)
		}
	}

	result.KeyCount = len(result.Objects) + len(result.CommonPrefixes)
	return result, nil
}

// ListObjectVersions lists all versions of objects in a bucket.
func (b *Backend) ListObjectVersions(
	bucketName, prefix, delimiter, keyMarker, versionIdMarker string,
	maxKeys int,
) (*ListObjectVersionsResult, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	// Collect all keys
	allKeys := make([]string, 0, len(bucket.Objects))
	for key := range bucket.Objects {
		allKeys = append(allKeys, key)
	}
	sort.Strings(allKeys)

	type versionEntry struct {
		key       string
		versionId string
		object    *Object
	}

	var allVersions []versionEntry
	commonPrefixSet := make(map[string]struct{})

	for _, key := range allKeys {
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}

		if delimiter != "" {
			subKey := key[len(prefix):]
			if idx := strings.Index(subKey, delimiter); idx != -1 {
				commonPrefix := prefix + subKey[:idx+len(delimiter)]
				commonPrefixSet[commonPrefix] = struct{}{}
				continue
			}
		}

		versions := bucket.Objects[key]
		for _, v := range versions.Versions {
			allVersions = append(allVersions, versionEntry{
				key:       key,
				versionId: v.VersionId,
				object:    v,
			})
		}
	}

	// Sort by key, then by LastModified descending (newest first)
	sort.Slice(allVersions, func(i, j int) bool {
		if allVersions[i].key != allVersions[j].key {
			return allVersions[i].key < allVersions[j].key
		}
		return allVersions[i].object.LastModified.After(allVersions[j].object.LastModified)
	})

	// Apply key-marker and version-id-marker
	startIdx := 0
	if keyMarker != "" {
		for i, ve := range allVersions {
			if ve.key > keyMarker {
				startIdx = i
				break
			}
			if ve.key == keyMarker && versionIdMarker != "" && ve.versionId == versionIdMarker {
				startIdx = i + 1
				break
			}
			if ve.key == keyMarker && versionIdMarker == "" {
				// Skip all versions of keyMarker
				continue
			}
		}
		// If marker is after all entries
		if startIdx == 0 && len(allVersions) > 0 &&
			allVersions[len(allVersions)-1].key <= keyMarker {
			startIdx = len(allVersions)
		}
	}

	result := &ListObjectVersionsResult{}

	// Collect common prefixes
	for cp := range commonPrefixSet {
		result.CommonPrefixes = append(result.CommonPrefixes, cp)
	}
	sort.Strings(result.CommonPrefixes)

	// Apply maxKeys
	endIdx := startIdx + maxKeys
	if endIdx > len(allVersions) {
		endIdx = len(allVersions)
	} else {
		result.IsTruncated = true
	}

	for i := startIdx; i < endIdx; i++ {
		ve := allVersions[i]
		if ve.object.IsDeleteMarker {
			result.DeleteMarkers = append(result.DeleteMarkers, ve.object)
		} else {
			result.Versions = append(result.Versions, ve.object)
		}
	}

	// Set next markers if truncated
	if result.IsTruncated && endIdx > startIdx {
		lastEntry := allVersions[endIdx-1]
		result.NextKeyMarker = lastEntry.key
		result.NextVersionIdMarker = lastEntry.versionId
	}

	return result, nil
}

// GetObjectTagging retrieves tags for an object.
// If versionId is empty, returns tags for the latest version.
// Returns the tags, the actual versionId used, and any error.
func (b *Backend) GetObjectTagging(
	bucketName, key, versionId string,
) (map[string]string, string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, "", ErrBucketNotFound
	}

	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return nil, "", ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		// Get latest version
		obj = versions.Versions[0]
	} else {
		// Find specific version
		for _, v := range versions.Versions {
			if v.VersionId == versionId {
				obj = v
				break
			}
		}
		if obj == nil {
			return nil, "", ErrVersionNotFound
		}
	}

	// Return empty map if no tags (not an error)
	tags := obj.Tags
	if tags == nil {
		tags = make(map[string]string)
	}

	return tags, obj.VersionId, nil
}

// PutObjectTagging sets tags for an object (replaces existing tags).
// If versionId is empty, sets tags on the latest version.
// Returns the actual versionId used and any error.
func (b *Backend) PutObjectTagging(
	bucketName, key, versionId string,
	tags map[string]string,
) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return "", ErrBucketNotFound
	}

	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return "", ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		// Get latest version
		obj = versions.Versions[0]
	} else {
		// Find specific version
		for _, v := range versions.Versions {
			if v.VersionId == versionId {
				obj = v
				break
			}
		}
		if obj == nil {
			return "", ErrVersionNotFound
		}
	}

	// Cannot set tags on a delete marker
	if obj.IsDeleteMarker {
		return "", ErrObjectNotFound
	}

	obj.Tags = tags
	return obj.VersionId, nil
}

// DeleteObjectTagging removes all tags from an object.
// If versionId is empty, deletes tags from the latest version.
// Returns the actual versionId used and any error.
func (b *Backend) DeleteObjectTagging(bucketName, key, versionId string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return "", ErrBucketNotFound
	}

	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return "", ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		// Get latest version
		obj = versions.Versions[0]
	} else {
		// Find specific version
		for _, v := range versions.Versions {
			if v.VersionId == versionId {
				obj = v
				break
			}
		}
		if obj == nil {
			return "", ErrVersionNotFound
		}
	}

	// Cannot delete tags from a delete marker
	if obj.IsDeleteMarker {
		return "", ErrObjectNotFound
	}

	obj.Tags = nil
	return obj.VersionId, nil
}
