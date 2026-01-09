package backend

import (
	"time"
)

// GetObjectLockConfiguration returns the Object Lock configuration for a bucket.
func (b *Backend) GetObjectLockConfiguration(bucketName string) (*ObjectLockConfiguration, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if !bucket.ObjectLockEnabled {
		return nil, ErrObjectLockNotEnabled
	}

	if bucket.ObjectLockConfiguration == nil {
		return &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
		}, nil
	}

	return bucket.ObjectLockConfiguration, nil
}

// PutObjectLockConfiguration sets the Object Lock configuration for a bucket.
func (b *Backend) PutObjectLockConfiguration(
	bucketName string,
	config *ObjectLockConfiguration,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	// Enable object lock if not already enabled
	if config.ObjectLockEnabled == "Enabled" {
		bucket.ObjectLockEnabled = true
	}

	bucket.ObjectLockConfiguration = config
	return nil
}

// GetObjectRetention returns the retention settings for an object.
func (b *Backend) GetObjectRetention(
	bucketName, key, versionId string,
) (*ObjectLockRetention, error) {
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
		obj = versions.Versions[0]
	} else {
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

	if obj.RetentionMode == "" {
		return nil, ErrNoSuchObjectLockConfig
	}

	retention := &ObjectLockRetention{
		Mode: obj.RetentionMode,
	}
	if obj.RetainUntilDate != nil {
		retention.RetainUntilDate = obj.RetainUntilDate.Format(time.RFC3339)
	}

	return retention, nil
}

// PutObjectRetention sets the retention settings for an object.
func (b *Backend) PutObjectRetention(
	bucketName, key, versionId string,
	retention *ObjectLockRetention,
	bypassGovernance bool,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	if !bucket.ObjectLockEnabled {
		return ErrObjectLockNotEnabled
	}

	versions, exists := bucket.Objects[key]
	if !exists || len(versions.Versions) == 0 {
		return ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		obj = versions.Versions[0]
	} else {
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

	// Check if object is already locked with COMPLIANCE mode
	if obj.RetentionMode == RetentionModeCompliance && obj.RetainUntilDate != nil {
		if time.Now().Before(*obj.RetainUntilDate) {
			return ErrObjectLocked
		}
	}

	// Check if object is locked with GOVERNANCE mode
	if obj.RetentionMode == RetentionModeGovernance && !bypassGovernance &&
		obj.RetainUntilDate != nil {
		if time.Now().Before(*obj.RetainUntilDate) {
			return ErrObjectLocked
		}
	}

	obj.RetentionMode = retention.Mode
	if retention.RetainUntilDate != "" {
		t, err := time.Parse(time.RFC3339, retention.RetainUntilDate)
		if err != nil {
			return ErrInvalidRequest
		}
		obj.RetainUntilDate = &t
	}

	return nil
}

// GetObjectLegalHold returns the legal hold status for an object.
func (b *Backend) GetObjectLegalHold(
	bucketName, key, versionId string,
) (*ObjectLockLegalHold, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return nil, ErrBucketNotFound
	}

	if !bucket.ObjectLockEnabled {
		return nil, ErrObjectLockNotEnabled
	}

	versions, exists := bucket.Objects[key]
	if !exists || len(versions.Versions) == 0 {
		return nil, ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		obj = versions.Versions[0]
	} else {
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

	status := obj.LegalHoldStatus
	if status == "" {
		status = LegalHoldStatusOff
	}

	return &ObjectLockLegalHold{
		Status: status,
	}, nil
}

// PutObjectLegalHold sets the legal hold status for an object.
func (b *Backend) PutObjectLegalHold(
	bucketName, key, versionId string,
	legalHold *ObjectLockLegalHold,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, exists := b.buckets[bucketName]
	if !exists {
		return ErrBucketNotFound
	}

	if !bucket.ObjectLockEnabled {
		return ErrObjectLockNotEnabled
	}

	versions, exists := bucket.Objects[key]
	if !exists || len(versions.Versions) == 0 {
		return ErrObjectNotFound
	}

	var obj *Object
	if versionId == "" {
		obj = versions.Versions[0]
	} else {
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

	obj.LegalHoldStatus = legalHold.Status
	return nil
}

// CreateBucketWithObjectLock creates a bucket with Object Lock enabled.
func (b *Backend) CreateBucketWithObjectLock(name string) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.buckets[name]; exists {
		return ErrBucketAlreadyOwnedByYou
	}

	b.buckets[name] = &Bucket{
		Name:              name,
		CreationDate:      time.Now().UTC(),
		VersioningStatus:  VersioningEnabled, // Object Lock requires versioning
		MFADelete:         MFADeleteDisabled,
		Objects:           make(map[string]*ObjectVersions),
		ObjectLockEnabled: true,
	}
	return nil
}
