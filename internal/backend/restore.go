package backend

import (
	"time"
)

// RestoreObjectResult contains the result of a RestoreObject operation.
type RestoreObjectResult struct {
	StatusCode int // 200 for already-restored, 202 for new restore
}

// RestoreObject initiates or updates a restore for an archived object.
// For a test server, restores are instantaneous (RestoreOngoing is always false).
// Returns 200 if already restored, 202 for a new restore.
func (b *Backend) RestoreObject(
	bucketName, key, versionId string,
	days int,
) (*RestoreObjectResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return nil, ErrBucketNotFound
	}

	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return nil, ErrObjectNotFound
	}

	var obj *Object
	if versionId != "" {
		for _, v := range versions.Versions {
			if v.VersionId == versionId {
				obj = v
				break
			}
		}
		if obj == nil {
			return nil, ErrVersionNotFound
		}
	} else {
		obj = versions.Versions[0]
	}

	if obj.IsDeleteMarker {
		return nil, ErrObjectNotFound
	}

	// Only GLACIER and DEEP_ARCHIVE storage classes need restore
	if obj.StorageClass != "GLACIER" && obj.StorageClass != "DEEP_ARCHIVE" {
		return nil, ErrInvalidObjectState
	}

	// If already restored with a valid expiry, update the expiry and return 200
	if obj.RestoreExpiryDate != nil && obj.RestoreExpiryDate.After(time.Now().UTC()) {
		if days > 0 {
			expiry := time.Now().UTC().AddDate(0, 0, days)
			obj.RestoreExpiryDate = &expiry
		}
		return &RestoreObjectResult{StatusCode: 200}, nil
	}

	// For cloud-transitioned objects, copy data back from the cloud target bucket
	if obj.IsCloudTransitioned && obj.CloudTargetBucket != "" && obj.CloudTargetKey != "" {
		targetBucket, ok := b.buckets[obj.CloudTargetBucket]
		if !ok {
			return nil, ErrBucketNotFound
		}
		cloudVersions, ok := targetBucket.Objects[obj.CloudTargetKey]
		if !ok || len(cloudVersions.Versions) == 0 {
			return nil, ErrObjectNotFound
		}
		cloudObj := cloudVersions.Versions[0]
		if cloudObj.Data == nil {
			return nil, ErrObjectNotFound
		}
		obj.Data = make([]byte, len(cloudObj.Data))
		copy(obj.Data, cloudObj.Data)
		obj.Size = cloudObj.Size
	}

	// New restore — instant for test server
	obj.RestoreOngoing = false
	if days > 0 {
		expiry := time.Now().UTC().AddDate(0, 0, days)
		obj.RestoreExpiryDate = &expiry
		// Temporary restore: keep StorageClass as GLACIER/DEEP_ARCHIVE
	} else {
		// Permanent restore (days=0): no expiry, move back to STANDARD
		farFuture := time.Now().UTC().AddDate(100, 0, 0)
		obj.RestoreExpiryDate = &farFuture
		obj.StorageClass = "STANDARD"
		obj.IsCloudTransitioned = false
		obj.CloudTargetBucket = ""
		obj.CloudTargetKey = ""
	}

	return &RestoreObjectResult{StatusCode: 202}, nil
}
