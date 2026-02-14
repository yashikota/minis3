package backend

import (
	"os"
	"strconv"
	"strings"
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

	hydrateArchivedObjectDataLocked(b, bucketName, key, obj)

	// If already restored with a valid expiry, update the expiry and return 200
	if obj.RestoreExpiryDate != nil && obj.RestoreExpiryDate.After(time.Now().UTC()) {
		if days > 0 {
			expiry := time.Now().UTC().Add(time.Duration(days) * restoreDayDuration())
			obj.RestoreExpiryDate = &expiry
		} else {
			obj.StorageClass = "STANDARD"
			obj.CloudTransitionedAt = nil
		}
		return &RestoreObjectResult{StatusCode: 200}, nil
	}

	// New restore — instant for test server
	obj.RestoreOngoing = false
	if days > 0 {
		expiry := time.Now().UTC().Add(time.Duration(days) * restoreDayDuration())
		obj.RestoreExpiryDate = &expiry
	} else {
		// Permanent restore converts object back to STANDARD.
		obj.StorageClass = "STANDARD"
		obj.CloudTransitionedAt = nil
		farFuture := time.Now().UTC().AddDate(100, 0, 0)
		obj.RestoreExpiryDate = &farFuture
	}

	return &RestoreObjectResult{StatusCode: 202}, nil
}

func restoreDayDuration() time.Duration {
	restoreSeconds := 0
	if raw := strings.TrimSpace(os.Getenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			restoreSeconds = seconds
		}
	}
	lifecycleSeconds := 0
	if raw := strings.TrimSpace(os.Getenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			lifecycleSeconds = seconds
		}
	}
	if restoreSeconds == 0 {
		restoreSeconds = lifecycleSeconds
	}
	if restoreSeconds > 0 && lifecycleSeconds > 0 {
		return time.Duration(restoreSeconds+lifecycleSeconds) * time.Second
	}
	if restoreSeconds > 0 {
		return time.Duration(restoreSeconds) * time.Second
	}
	return 24 * time.Hour
}

func cloudReadThroughRestoreDays() int {
	if raw := strings.TrimSpace(os.Getenv("MINIS3_CLOUD_READ_THROUGH_RESTORE_DAYS")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	return 1
}

func cloudAllowReadThrough() bool {
	raw := strings.TrimSpace(os.Getenv("MINIS3_CLOUD_ALLOW_READ_THROUGH"))
	if raw == "" {
		return true
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return true
	}
	return parsed
}

func CloudReadThroughRestoreDays() int {
	return cloudReadThroughRestoreDays()
}

func CloudAllowReadThrough() bool {
	return cloudAllowReadThrough()
}

func hydrateArchivedObjectDataLocked(b *Backend, sourceBucketName, sourceKey string, obj *Object) {
	if obj == nil || len(obj.Data) > 0 || !IsArchivedStorageClass(obj.StorageClass) {
		return
	}
	targetBucketName := cloudTargetBucketName(obj.StorageClass)
	targetBucket, ok := b.buckets[targetBucketName]
	if !ok {
		return
	}
	cloudKey := cloudObjectKey(sourceBucketName, sourceKey, obj.VersionId)
	versions, ok := targetBucket.Objects[cloudKey]
	if !ok || versions == nil || len(versions.Versions) == 0 || versions.Versions[0] == nil {
		return
	}
	cloudObj := versions.Versions[0]
	obj.Data = append([]byte(nil), cloudObj.Data...)
	obj.Size = int64(len(obj.Data))
}
