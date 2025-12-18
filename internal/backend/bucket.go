package backend

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Bucket naming rules according to AWS S3 documentation:
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
var (
	// Valid bucket name pattern: lowercase letters, numbers, hyphens, and periods
	bucketNameRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	// IP address pattern to reject
	ipAddressRegex = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	// Prohibited prefixes
	prohibitedPrefixes = []string{"xn--", "sthree-", "sthree-accesspoint-", "amzn-s3-demo-"}
	// Prohibited suffixes
	prohibitedSuffixes = []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"}
)

// ValidateBucketName validates a bucket name according to S3 naming rules.
func ValidateBucketName(name string) error {
	// Length: 3-63 characters
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf(
			"%w: bucket name must be between 3 and 63 characters long",
			ErrInvalidBucketName,
		)
	}

	// Must match pattern (lowercase, numbers, hyphens, periods)
	if !bucketNameRegex.MatchString(name) {
		return fmt.Errorf(
			"%w: bucket name can only contain lowercase letters, numbers, hyphens, and periods",
			ErrInvalidBucketName,
		)
	}

	// Must not contain consecutive periods
	if strings.Contains(name, "..") {
		return fmt.Errorf(
			"%w: bucket name must not contain consecutive periods",
			ErrInvalidBucketName,
		)
	}

	// Must not contain period adjacent to hyphen
	if strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return fmt.Errorf(
			"%w: bucket name must not contain period adjacent to hyphen",
			ErrInvalidBucketName,
		)
	}

	// Must not be formatted as IP address
	if ipAddressRegex.MatchString(name) {
		return fmt.Errorf(
			"%w: bucket name must not be formatted as an IP address",
			ErrInvalidBucketName,
		)
	}

	// Check prohibited prefixes
	for _, prefix := range prohibitedPrefixes {
		if strings.HasPrefix(name, prefix) {
			return fmt.Errorf(
				"%w: bucket name must not start with prohibited prefix '%s'",
				ErrInvalidBucketName,
				prefix,
			)
		}
	}

	// Check prohibited suffixes
	for _, suffix := range prohibitedSuffixes {
		if strings.HasSuffix(name, suffix) {
			return fmt.Errorf(
				"%w: bucket name must not end with prohibited suffix '%s'",
				ErrInvalidBucketName,
				suffix,
			)
		}
	}

	return nil
}

// CreateBucket creates a new bucket
func (b *Backend) CreateBucket(name string) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.buckets[name]; exists {
		return ErrBucketAlreadyExists
	}

	b.buckets[name] = &Bucket{
		Name:         name,
		CreationDate: time.Now().UTC(),
		Objects:      make(map[string]*Object),
	}
	return nil
}

// GetBucket retrieves a bucket by name
func (b *Backend) GetBucket(name string) (*Bucket, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	val, ok := b.buckets[name]
	return val, ok
}

// DeleteBucket deletes a bucket if it is empty
func (b *Backend) DeleteBucket(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[name]
	if !exists {
		return ErrBucketNotFound
	}

	if len(bucket.Objects) > 0 {
		return ErrBucketNotEmpty
	}

	delete(b.buckets, name)
	return nil
}

// ListBuckets returns all buckets.
func (b *Backend) ListBuckets() []*Bucket {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]*Bucket, 0, len(b.buckets))
	for _, bkt := range b.buckets {
		res = append(res, bkt)
	}
	return res
}
