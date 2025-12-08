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

// PutObject stores an object in a bucket
func (b *Backend) PutObject(
	bucketName, key string,
	data []byte,
	contentType string,
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

	obj := &Object{
		Key:           key,
		LastModified:  time.Now().UTC(),
		ETag:          fmt.Sprintf("\"%x\"", md5Hash.Sum(nil)),
		Size:          int64(len(data)),
		ContentType:   contentType,
		Data:          data,
		ChecksumCRC32: base64.StdEncoding.EncodeToString(crc32Hash.Sum(nil)),
	}

	bucket.Objects[key] = obj
	return obj, nil
}

// GetObject retrieves an object from a bucket
func (b *Backend) GetObject(bucketName, key string) (*Object, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}
	obj, ok := bucket.Objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return obj, nil
}

// DeleteObject removes an object from a bucket
func (b *Backend) DeleteObject(bucketName, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return ErrBucketNotFound
	}
	delete(bucket.Objects, key)
	return nil
}

// CopyObject copies an object from source to destination
func (b *Backend) CopyObject(srcBucket, srcKey, dstBucket, dstKey string) (*Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	srcBkt, ok := b.buckets[srcBucket]
	if !ok {
		return nil, ErrSourceBucketNotFound
	}

	srcObj, ok := srcBkt.Objects[srcKey]
	if !ok {
		return nil, ErrSourceObjectNotFound
	}

	dstBkt, ok := b.buckets[dstBucket]
	if !ok {
		return nil, ErrDestinationBucketNotFound
	}

	copiedData := make([]byte, len(srcObj.Data))
	copy(copiedData, srcObj.Data)

	obj := &Object{
		Key:           dstKey,
		LastModified:  time.Now().UTC(),
		ETag:          srcObj.ETag,
		Size:          srcObj.Size,
		ContentType:   srcObj.ContentType,
		Data:          copiedData,
		ChecksumCRC32: srcObj.ChecksumCRC32,
	}

	dstBkt.Objects[dstKey] = obj
	return obj, nil
}

// DeleteObjects deletes multiple objects from a bucket
func (b *Backend) DeleteObjects(bucketName string, keys []string) ([]DeleteObjectResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	results := make([]DeleteObjectResult, 0, len(keys))
	for _, key := range keys {
		delete(bucket.Objects, key)
		results = append(results, DeleteObjectResult{
			Key:     key,
			Deleted: true,
		})
	}

	return results, nil
}

// ListObjectsV1 lists objects with an optional prefix
func (b *Backend) ListObjectsV1(bucketName string, prefix string) ([]*Object, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, false
	}

	var result []*Object
	for _, obj := range bucket.Objects {
		if prefix == "" || len(obj.Key) >= len(prefix) && obj.Key[0:len(prefix)] == prefix {
			result = append(result, obj)
		}
	}
	return result, true
}

// ListObjectsV2 lists objects with support for prefix, delimiter, and max-keys.
func (b *Backend) ListObjectsV2(
	bucketName, prefix, delimiter string,
	maxKeys int,
) (*ListObjectsV2Result, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	keys := make([]string, 0, len(bucket.Objects))
	for key := range bucket.Objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := &ListObjectsV2Result{}
	commonPrefixSet := make(map[string]struct{})

	for _, key := range keys {
		obj := bucket.Objects[key]

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

		result.Objects = append(result.Objects, obj)
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
	if maxKeys >= 0 && totalCount > maxKeys {
		result.IsTruncated = true
		entries = entries[:maxKeys]
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
