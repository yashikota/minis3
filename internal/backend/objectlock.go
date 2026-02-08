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

	// If Object Lock is not yet enabled, allow enabling it only if versioning is Enabled
	if !bucket.ObjectLockEnabled {
		if bucket.VersioningStatus != VersioningEnabled {
			return ErrObjectLockNotEnabled
		}
		// Enable Object Lock on this versioned bucket
		bucket.ObjectLockEnabled = true
	}

	// ObjectLockEnabled must be "Enabled"
	if config.ObjectLockEnabled != "" && config.ObjectLockEnabled != "Enabled" {
		return ErrInvalidObjectLockConfig
	}

	// Validate DefaultRetention if present
	if config.Rule != nil && config.Rule.DefaultRetention != nil {
		dr := config.Rule.DefaultRetention
		// Mode must be GOVERNANCE or COMPLIANCE
		if dr.Mode != RetentionModeGovernance && dr.Mode != RetentionModeCompliance {
			return ErrInvalidObjectLockConfig
		}
		// Cannot specify both Days and Years
		if dr.Days > 0 && dr.Years > 0 {
			return ErrInvalidObjectLockConfig
		}
		// Days/Years must be positive
		if dr.Days < 0 || dr.Years < 0 {
			return ErrInvalidRetentionPeriod
		}
		// Must have at least one of Days or Years
		if dr.Days == 0 && dr.Years == 0 {
			return ErrInvalidRetentionPeriod
		}
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

	// Validate retention mode
	if retention.Mode != "" && retention.Mode != RetentionModeGovernance &&
		retention.Mode != RetentionModeCompliance {
		return ErrInvalidObjectLockConfig
	}

	// Parse new retain-until-date
	var newRetainUntil *time.Time
	if retention.RetainUntilDate != "" {
		t, err := time.Parse(time.RFC3339, retention.RetainUntilDate)
		if err != nil {
			return ErrInvalidRequest
		}
		t = t.UTC().Truncate(time.Second)
		newRetainUntil = &t
	}

	// For GOVERNANCE mode with bypass, or for COMPLIANCE mode that has expired, allow any change.
	// For active locks without bypass: only allow extending the retention period (same mode).
	if obj.RetentionMode == RetentionModeGovernance && !bypassGovernance &&
		obj.RetainUntilDate != nil && time.Now().Before(*obj.RetainUntilDate) {
		// Cannot change mode without bypass
		if retention.Mode != obj.RetentionMode {
			return ErrObjectLocked
		}
		// Can only extend the period
		if newRetainUntil == nil || newRetainUntil.Before(*obj.RetainUntilDate) {
			return ErrObjectLocked
		}
	}
	if obj.RetentionMode == RetentionModeCompliance &&
		obj.RetainUntilDate != nil && time.Now().Before(*obj.RetainUntilDate) {
		// Cannot change mode for COMPLIANCE
		if retention.Mode != obj.RetentionMode {
			return ErrObjectLocked
		}
		// Can only extend the period
		if newRetainUntil == nil || newRetainUntil.Before(*obj.RetainUntilDate) {
			return ErrObjectLocked
		}
	}

	obj.RetentionMode = retention.Mode
	obj.RetainUntilDate = newRetainUntil

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

	// Validate legal hold status
	if legalHold.Status != LegalHoldStatusOn && legalHold.Status != LegalHoldStatusOff {
		return ErrInvalidObjectLockConfig
	}

	obj.LegalHoldStatus = legalHold.Status
	return nil
}

// applyDefaultRetention applies the bucket's default retention configuration
// to an object that does not already have explicit retention set.
// Caller must hold the lock.
func applyDefaultRetention(bucket *Bucket, obj *Object) {
	if !bucket.ObjectLockEnabled || obj.RetentionMode != "" {
		return
	}
	cfg := bucket.ObjectLockConfiguration
	if cfg == nil || cfg.Rule == nil || cfg.Rule.DefaultRetention == nil {
		return
	}
	dr := cfg.Rule.DefaultRetention
	if dr.Mode == "" {
		return
	}
	obj.RetentionMode = dr.Mode
	retainUntil := obj.LastModified
	if dr.Days > 0 {
		retainUntil = retainUntil.AddDate(0, 0, dr.Days)
	} else if dr.Years > 0 {
		retainUntil = retainUntil.AddDate(dr.Years, 0, 0)
	}
	obj.RetainUntilDate = &retainUntil
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
		Name:                name,
		CreationDate:        time.Now().UTC(),
		VersioningStatus:    VersioningEnabled, // Object Lock requires versioning
		MFADelete:           MFADeleteDisabled,
		Objects:             make(map[string]*ObjectVersions),
		ObjectOwnership:     "",
		RequestPaymentPayer: RequestPayerBucketOwner,
		ObjectLockEnabled:   true,
	}
	return nil
}
