package backend

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"time"
)

// isObjectLocked checks whether an object is locked and cannot be deleted.
func isObjectLocked(obj *Object, bypassGovernance bool) bool {
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
	crc32Hash := crc32.NewIEEE()
	w := io.MultiWriter(md5Hash, crc32Hash)
	_, _ = w.Write(data)

	// Determine version ID based on versioning status
	var versionId string
	switch bucket.VersioningStatus {
	case VersioningEnabled:
		versionId = GenerateVersionId()
	default:
		// VersioningUnset or VersioningSuspended: use "null"
		versionId = NullVersionId
	}

	storageClass := opts.StorageClass
	if storageClass == "" {
		storageClass = "STANDARD"
	}

	obj := &Object{
		Key:                  key,
		VersionId:            versionId,
		IsLatest:             true,
		IsDeleteMarker:       false,
		LastModified:         time.Now().UTC(),
		ETag:                 fmt.Sprintf("\"%x\"", md5Hash.Sum(nil)),
		Size:                 int64(len(data)),
		ContentType:          opts.ContentType,
		Data:                 data,
		ChecksumCRC32:        base64.StdEncoding.EncodeToString(crc32Hash.Sum(nil)),
		Metadata:             opts.Metadata,
		CacheControl:         opts.CacheControl,
		Expires:              opts.Expires,
		ContentEncoding:      opts.ContentEncoding,
		ContentLanguage:      opts.ContentLanguage,
		ContentDisposition:   opts.ContentDisposition,
		Tags:                 opts.Tags,
		StorageClass:         storageClass,
		ServerSideEncryption: opts.ServerSideEncryption,
		SSEKMSKeyId:          opts.SSEKMSKeyId,
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
	// Storage class
	StorageClass string
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
		Key:            dstKey,
		VersionId:      versionId,
		IsLatest:       true,
		IsDeleteMarker: false,
		LastModified:   time.Now().UTC(),
		ETag:           srcObj.ETag,
		Size:           srcObj.Size,
		Data:           copiedData,
		ChecksumCRC32:  srcObj.ChecksumCRC32,
	}

	// Handle metadata directive
	if opts.MetadataDirective == "REPLACE" {
		// Use new metadata from options
		obj.ContentType = opts.ContentType
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

	// Handle StorageClass
	if opts.StorageClass != "" {
		obj.StorageClass = opts.StorageClass
	} else if srcObj.StorageClass != "" {
		obj.StorageClass = srcObj.StorageClass
	} else {
		obj.StorageClass = "STANDARD"
	}

	// Handle Server-Side Encryption
	if opts.ServerSideEncryption != "" {
		obj.ServerSideEncryption = opts.ServerSideEncryption
		obj.SSEKMSKeyId = opts.SSEKMSKeyId
	} else {
		obj.ServerSideEncryption = srcObj.ServerSideEncryption
		obj.SSEKMSKeyId = srcObj.SSEKMSKeyId
	}

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

		if obj.VersionId != "" {
			// Delete specific version
			versions, exists := bucket.Objects[obj.Key]
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

	// Collect all keys with their latest non-DeleteMarker version
	allKeys := make([]string, 0, len(bucket.Objects))
	keyToObj := make(map[string]*Object)
	for key, versions := range bucket.Objects {
		obj := versions.getLatestVersion()
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

	// Collect all keys with their latest non-DeleteMarker version
	keys := make([]string, 0, len(bucket.Objects))
	keyToObj := make(map[string]*Object)
	for key, versions := range bucket.Objects {
		obj := versions.getLatestVersion()
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
