package backend

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
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

// CreateBucket creates a new bucket.
// Returns ErrBucketAlreadyOwnedByYou if the bucket already exists (per S3 behavior for single-owner mock).
func (b *Backend) CreateBucket(name string) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.buckets[name]; exists {
		// In minis3 (single-user mock), existing bucket means "already owned by you"
		return ErrBucketAlreadyOwnedByYou
	}

	b.buckets[name] = &Bucket{
		Name:             name,
		CreationDate:     time.Now().UTC(),
		VersioningStatus: VersioningUnset,
		MFADelete:        MFADeleteDisabled,
		Objects:          make(map[string]*ObjectVersions),
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

// ListBucketsWithOptions returns buckets with pagination and filtering support.
func (b *Backend) ListBucketsWithOptions(opts ListBucketsOptions) *ListBucketsResult {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Collect all matching buckets
	var allBuckets []*Bucket
	for _, bkt := range b.buckets {
		// Apply prefix filter
		if opts.Prefix != "" && !strings.HasPrefix(bkt.Name, opts.Prefix) {
			continue
		}
		allBuckets = append(allBuckets, bkt)
	}

	// Sort by name for consistent ordering
	sortBucketsByName(allBuckets)

	// Apply continuation token (find start position using binary search)
	startIdx := 0
	if opts.ContinuationToken != "" {
		startIdx = sort.Search(len(allBuckets), func(i int) bool {
			return allBuckets[i].Name > opts.ContinuationToken
		})
	}

	// Apply max-buckets limit (default 1000, consistent with S3 ListObjects)
	maxBuckets := opts.MaxBuckets
	if maxBuckets <= 0 {
		maxBuckets = 1000
	}

	result := &ListBucketsResult{}
	endIdx := startIdx + maxBuckets
	if endIdx > len(allBuckets) {
		endIdx = len(allBuckets)
	} else {
		result.IsTruncated = true
	}

	result.Buckets = allBuckets[startIdx:endIdx]

	// Set continuation token if truncated
	if result.IsTruncated && len(result.Buckets) > 0 {
		result.ContinuationToken = result.Buckets[len(result.Buckets)-1].Name
	}

	return result
}

// sortBucketsByName sorts buckets by name in ascending order
func sortBucketsByName(buckets []*Bucket) {
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].Name < buckets[j].Name
	})
}

// SetBucketVersioning sets the versioning configuration for a bucket.
func (b *Backend) SetBucketVersioning(
	bucketName string,
	status VersioningStatus,
	mfaDelete MFADeleteStatus,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.VersioningStatus = status
	bucket.MFADelete = mfaDelete
	return nil
}

// GetBucketVersioning returns the versioning configuration for a bucket.
func (b *Backend) GetBucketVersioning(
	bucketName string,
) (VersioningStatus, MFADeleteStatus, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return VersioningUnset, MFADeleteDisabled, ErrBucketNotFound
	}

	return bucket.VersioningStatus, bucket.MFADelete, nil
}

// GetBucketLocation returns the location constraint of the bucket.
// For us-east-1, it returns an empty string (null in S3 terms).
func (b *Backend) GetBucketLocation(bucketName string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return "", ErrBucketNotFound
	}

	return bucket.Location, nil
}

// GetBucketTagging returns the tag set of a bucket.
func (b *Backend) GetBucketTagging(bucketName string) (map[string]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if len(bucket.Tags) == 0 {
		return nil, ErrNoSuchTagSet
	}

	// Return a copy to prevent external modification
	tags := make(map[string]string, len(bucket.Tags))
	for k, v := range bucket.Tags {
		tags[k] = v
	}
	return tags, nil
}

// PutBucketTagging sets the tag set for a bucket (replaces existing tags).
func (b *Backend) PutBucketTagging(bucketName string, tags map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.Tags = tags
	return nil
}

// DeleteBucketTagging removes all tags from a bucket.
func (b *Backend) DeleteBucketTagging(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.Tags = nil
	return nil
}

// GetBucketPolicy returns the bucket policy.
func (b *Backend) GetBucketPolicy(bucketName string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return "", ErrBucketNotFound
	}

	if bucket.Policy == "" {
		return "", ErrNoSuchBucketPolicy
	}

	return bucket.Policy, nil
}

// PutBucketPolicy sets the bucket policy.
func (b *Backend) PutBucketPolicy(bucketName, policy string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	// Basic JSON validation
	if !isValidJSON(policy) {
		return ErrMalformedPolicy
	}

	bucket.Policy = policy
	return nil
}

// DeleteBucketPolicy removes the bucket policy.
func (b *Backend) DeleteBucketPolicy(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.Policy = ""
	return nil
}

// isValidJSON checks if a string is valid JSON.
func isValidJSON(s string) bool {
	return json.Valid([]byte(s))
}

// DefaultOwner returns the default owner for minis3.
// The ID matches the s3tests.conf user_id for test compatibility.
func DefaultOwner() *Owner {
	return &Owner{
		ID:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DisplayName: "minis3",
	}
}

// NewDefaultACL creates a default private ACL with the owner having full control.
func NewDefaultACL() *AccessControlPolicy {
	owner := DefaultOwner()
	return &AccessControlPolicy{
		Xmlns: S3Xmlns,
		Owner: owner,
		AccessControlList: AccessControlList{
			Grants: []Grant{
				{
					Grantee: &Grantee{
						Xmlns:       "http://www.w3.org/2001/XMLSchema-instance",
						Type:        "CanonicalUser",
						ID:          owner.ID,
						DisplayName: owner.DisplayName,
					},
					Permission: PermissionFullControl,
				},
			},
		},
	}
}

// newGroupGrant creates a Grant for a group URI with the specified permission.
func newGroupGrant(uri, permission string) Grant {
	return Grant{
		Grantee: &Grantee{
			Xmlns: "http://www.w3.org/2001/XMLSchema-instance",
			Type:  "Group",
			URI:   uri,
		},
		Permission: permission,
	}
}

// CannedACLToPolicy converts a canned ACL string to an AccessControlPolicy.
func CannedACLToPolicy(cannedACL string) *AccessControlPolicy {
	owner := DefaultOwner()
	acl := &AccessControlPolicy{
		Xmlns: S3Xmlns,
		Owner: owner,
		AccessControlList: AccessControlList{
			Grants: []Grant{
				{
					Grantee: &Grantee{
						Xmlns:       "http://www.w3.org/2001/XMLSchema-instance",
						Type:        "CanonicalUser",
						ID:          owner.ID,
						DisplayName: owner.DisplayName,
					},
					Permission: PermissionFullControl,
				},
			},
		},
	}

	switch CannedACL(cannedACL) {
	case ACLPublicRead:
		acl.AccessControlList.Grants = append(acl.AccessControlList.Grants,
			newGroupGrant(AllUsersURI, PermissionRead))
	case ACLPublicReadWrite:
		acl.AccessControlList.Grants = append(acl.AccessControlList.Grants,
			newGroupGrant(AllUsersURI, PermissionRead),
			newGroupGrant(AllUsersURI, PermissionWrite))
	case ACLAuthenticatedRead:
		acl.AccessControlList.Grants = append(acl.AccessControlList.Grants,
			newGroupGrant(AuthenticatedUsersURI, PermissionRead))
	}

	return acl
}

// GetBucketACL returns the ACL for a bucket.
func (b *Backend) GetBucketACL(bucketName string) (*AccessControlPolicy, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.ACL == nil {
		return NewDefaultACL(), nil
	}

	return bucket.ACL, nil
}

// PutBucketACL sets the ACL for a bucket.
func (b *Backend) PutBucketACL(bucketName string, acl *AccessControlPolicy) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.ACL = acl
	return nil
}

// GetObjectACL returns the ACL for an object.
// If versionId is empty, returns the ACL for the latest version.
// If versionId is specified, returns the ACL for that specific version.
func (b *Backend) GetObjectACL(bucketName, key, versionId string) (*AccessControlPolicy, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	versions, exists := bucket.Objects[key]
	if !exists || len(versions.Versions) == 0 {
		return nil, ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		// Get the latest (current) version
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
			return nil, ErrVersionNotFound
		}
	}

	if obj.IsDeleteMarker {
		return nil, ErrObjectNotFound
	}

	if obj.ACL == nil {
		return NewDefaultACL(), nil
	}

	return obj.ACL, nil
}

// PutObjectACL sets the ACL for an object.
// If versionId is empty, sets the ACL for the latest version.
// If versionId is specified, sets the ACL for that specific version.
func (b *Backend) PutObjectACL(bucketName, key, versionId string, acl *AccessControlPolicy) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	versions, exists := bucket.Objects[key]
	if !exists || len(versions.Versions) == 0 {
		return ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		// Set ACL on the latest version
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
			return ErrVersionNotFound
		}
	}

	if obj.IsDeleteMarker {
		return ErrObjectNotFound
	}

	obj.ACL = acl
	return nil
}

// IsACLPublicRead checks if the ACL grants public read access.
func IsACLPublicRead(acl *AccessControlPolicy) bool {
	if acl == nil {
		return false
	}
	for _, grant := range acl.AccessControlList.Grants {
		if grant.Grantee != nil &&
			grant.Grantee.URI == AllUsersURI &&
			(grant.Permission == PermissionRead || grant.Permission == PermissionFullControl) {
			return true
		}
	}
	return false
}

// IsObjectPubliclyReadable checks if an object is publicly readable.
func (b *Backend) IsObjectPubliclyReadable(bucketName, key, versionId string) bool {
	acl, err := b.GetObjectACL(bucketName, key, versionId)
	if err != nil {
		return false
	}
	return IsACLPublicRead(acl)
}

// IsBucketPubliclyReadable checks if a bucket is publicly readable.
func (b *Backend) IsBucketPubliclyReadable(bucketName string) bool {
	acl, err := b.GetBucketACL(bucketName)
	if err != nil {
		return false
	}
	return IsACLPublicRead(acl)
}

// GetBucketLifecycleConfiguration returns the lifecycle configuration for a bucket.
func (b *Backend) GetBucketLifecycleConfiguration(
	bucketName string,
) (*LifecycleConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.LifecycleConfiguration == nil {
		return nil, ErrNoSuchLifecycleConfiguration
	}

	return bucket.LifecycleConfiguration, nil
}

// PutBucketLifecycleConfiguration sets the lifecycle configuration for a bucket.
func (b *Backend) PutBucketLifecycleConfiguration(
	bucketName string,
	config *LifecycleConfiguration,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.LifecycleConfiguration = config
	return nil
}

// DeleteBucketLifecycleConfiguration removes the lifecycle configuration for a bucket.
func (b *Backend) DeleteBucketLifecycleConfiguration(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.LifecycleConfiguration = nil
	return nil
}

// GetBucketEncryption returns the encryption configuration for a bucket.
func (b *Backend) GetBucketEncryption(
	bucketName string,
) (*ServerSideEncryptionConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.EncryptionConfiguration == nil {
		return nil, ErrServerSideEncryptionConfigurationNotFound
	}

	return bucket.EncryptionConfiguration, nil
}

// PutBucketEncryption sets the encryption configuration for a bucket.
func (b *Backend) PutBucketEncryption(
	bucketName string,
	config *ServerSideEncryptionConfiguration,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.EncryptionConfiguration = config
	return nil
}

// DeleteBucketEncryption removes the encryption configuration for a bucket.
func (b *Backend) DeleteBucketEncryption(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.EncryptionConfiguration = nil
	return nil
}

// GetBucketCORS returns the CORS configuration for a bucket.
func (b *Backend) GetBucketCORS(bucketName string) (*CORSConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.CORSConfiguration == nil {
		return nil, ErrNoSuchCORSConfiguration
	}

	return bucket.CORSConfiguration, nil
}

// PutBucketCORS sets the CORS configuration for a bucket.
func (b *Backend) PutBucketCORS(bucketName string, config *CORSConfiguration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.CORSConfiguration = config
	return nil
}

// DeleteBucketCORS removes the CORS configuration for a bucket.
func (b *Backend) DeleteBucketCORS(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.CORSConfiguration = nil
	return nil
}

// GetBucketWebsite returns the website configuration for a bucket.
func (b *Backend) GetBucketWebsite(bucketName string) (*WebsiteConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.WebsiteConfiguration == nil {
		return nil, ErrNoSuchWebsiteConfiguration
	}

	return bucket.WebsiteConfiguration, nil
}

// PutBucketWebsite sets the website configuration for a bucket.
func (b *Backend) PutBucketWebsite(bucketName string, config *WebsiteConfiguration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.WebsiteConfiguration = config
	return nil
}

// DeleteBucketWebsite removes the website configuration for a bucket.
func (b *Backend) DeleteBucketWebsite(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.WebsiteConfiguration = nil
	return nil
}

// GetPublicAccessBlock returns the public access block configuration for a bucket.
func (b *Backend) GetPublicAccessBlock(bucketName string) (*PublicAccessBlockConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if bucket.PublicAccessBlock == nil {
		return nil, ErrNoSuchPublicAccessBlockConfiguration
	}

	return bucket.PublicAccessBlock, nil
}

// PutPublicAccessBlock sets the public access block configuration for a bucket.
func (b *Backend) PutPublicAccessBlock(
	bucketName string,
	config *PublicAccessBlockConfiguration,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.PublicAccessBlock = config
	return nil
}

// DeletePublicAccessBlock removes the public access block configuration for a bucket.
func (b *Backend) DeletePublicAccessBlock(bucketName string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	bucket.PublicAccessBlock = nil
	return nil
}
