package backend

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Backend holds the state of the S3 world.
type Backend struct {
	mu      sync.RWMutex
	buckets map[string]*Bucket
}

func New() *Backend {
	return &Backend{
		buckets: make(map[string]*Bucket),
	}
}

// Backend methods
func (b *Backend) CreateBucket(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.buckets[name]; exists {
		return fmt.Errorf("bucket already exists")
	}

	b.buckets[name] = &Bucket{
		Name:         name,
		CreationDate: time.Now().UTC(),
		Objects:      make(map[string]*Object),
	}
	return nil
}

func (b *Backend) GetBucket(name string) (*Bucket, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	val, ok := b.buckets[name]
	return val, ok
}

func (b *Backend) DeleteBucket(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[name]
	if !exists {
		return fmt.Errorf("bucket not found")
	}

	if len(bucket.Objects) > 0 {
		return fmt.Errorf("bucket not empty")
	}

	delete(b.buckets, name)
	return nil
}

func (b *Backend) ListBuckets() []*Bucket {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]*Bucket, 0, len(b.buckets))
	for _, bkt := range b.buckets {
		res = append(res, bkt)
	}
	return res
}

func (b *Backend) PutObject(
	bucketName, key string,
	data []byte,
	contentType string,
) (*Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, fmt.Errorf("bucket not found")
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

func (b *Backend) GetObject(bucketName, key string) (*Object, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, false
	}
	obj, ok := bucket.Objects[key]
	return obj, ok
}

func (b *Backend) DeleteObject(bucketName, key string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return
	}
	delete(bucket.Objects, key)
}

func (b *Backend) CopyObject(srcBucket, srcKey, dstBucket, dstKey string) (*Object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Get source bucket
	srcBkt, ok := b.buckets[srcBucket]
	if !ok {
		return nil, ErrSourceBucketNotFound
	}

	// Get source object
	srcObj, ok := srcBkt.Objects[srcKey]
	if !ok {
		return nil, ErrSourceObjectNotFound
	}

	// Get destination bucket
	dstBkt, ok := b.buckets[dstBucket]
	if !ok {
		return nil, ErrDestinationBucketNotFound
	}

	// Create copied object
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

func (b *Backend) DeleteObjects(bucketName string, keys []string) ([]DeleteObjectResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, fmt.Errorf("bucket not found")
	}

	results := make([]DeleteObjectResult, 0, len(keys))
	for _, key := range keys {
		// S3 treats deleting non-existent objects as success
		delete(bucket.Objects, key)
		results = append(results, DeleteObjectResult{
			Key:     key,
			Deleted: true,
		})
	}

	return results, nil
}

func (b *Backend) ListObjects(bucketName string, prefix string) ([]*Object, bool) {
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

// ListObjectsV2Result holds the result of ListObjectsV2
type ListObjectsV2Result struct {
	Objects        []*Object
	CommonPrefixes []string
	IsTruncated    bool
	KeyCount       int
}

// ListObjectsV2 lists objects in a bucket with support for prefix, delimiter, and max-keys
func (b *Backend) ListObjectsV2(
	bucketName, prefix, delimiter string,
	maxKeys int,
) (*ListObjectsV2Result, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, fmt.Errorf("bucket not found")
	}

	// Collect all keys and sort them
	keys := make([]string, 0, len(bucket.Objects))
	for key := range bucket.Objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := &ListObjectsV2Result{}
	commonPrefixSet := make(map[string]struct{})

	for _, key := range keys {
		obj := bucket.Objects[key]

		// Check prefix match
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}

		// Handle delimiter
		if delimiter != "" {
			// Find delimiter after prefix
			afterPrefix := key[len(prefix):]
			delimIdx := strings.Index(afterPrefix, delimiter)
			if delimIdx >= 0 {
				// This key has a delimiter after the prefix, add to CommonPrefixes
				commonPrefix := prefix + afterPrefix[:delimIdx+len(delimiter)]
				commonPrefixSet[commonPrefix] = struct{}{}
				continue
			}
		}

		// Add to Contents
		result.Objects = append(result.Objects, obj)
	}

	// Convert CommonPrefixes set to sorted slice
	for cp := range commonPrefixSet {
		result.CommonPrefixes = append(result.CommonPrefixes, cp)
	}
	sort.Strings(result.CommonPrefixes)

	// Calculate total count (objects + common prefixes)
	totalCount := len(result.Objects) + len(result.CommonPrefixes)

	// Apply max-keys limit
	if maxKeys > 0 && totalCount > maxKeys {
		result.IsTruncated = true
		// Truncate objects and common prefixes to fit within maxKeys
		if len(result.Objects) >= maxKeys {
			result.Objects = result.Objects[:maxKeys]
			result.CommonPrefixes = nil
		} else {
			remaining := maxKeys - len(result.Objects)
			if len(result.CommonPrefixes) > remaining {
				result.CommonPrefixes = result.CommonPrefixes[:remaining]
			}
		}
	}

	result.KeyCount = len(result.Objects) + len(result.CommonPrefixes)
	return result, nil
}
