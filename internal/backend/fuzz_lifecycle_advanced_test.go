package backend

import (
	"testing"
	"time"
)

func FuzzCloudObjectKey(f *testing.F) {
	f.Add("my-bucket", "photos/image.jpg", "ver123")
	f.Add("bucket", "key", "")
	f.Add("bucket", "key", NullVersionId)
	f.Add("", "", "")
	f.Add("bucket-name", "path/to/deep/key.txt", "version-id-long-string")

	f.Fuzz(func(t *testing.T, sourceBucket, sourceKey, versionID string) {
		_ = cloudObjectKey(sourceBucket, sourceKey, versionID)
	})
}

func FuzzIsLifecycleRuleEnabled(f *testing.F) {
	f.Add("Enabled", "prefix/", "tag-key", "tag-value")
	f.Add("Disabled", "", "", "")
	f.Add("enabled", "pre", "k", "v")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, status, prefix, tagKey, tagValue string) {
		rule := LifecycleRule{
			Status: status,
			Filter: &LifecycleFilter{
				Prefix: prefix,
			},
		}
		if tagKey != "" {
			rule.Filter.Tag = &Tag{Key: tagKey, Value: tagValue}
		}
		_ = isLifecycleRuleEnabled(rule)
	})
}

func FuzzObjectHasTag(f *testing.F) {
	f.Add("env", "prod", "env", "prod")
	f.Add("env", "prod", "env", "dev")
	f.Add("key", "value", "other", "val")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, objTagKey, objTagVal, searchKey, searchVal string) {
		obj := &Object{
			Tags: map[string]string{},
		}
		if objTagKey != "" {
			obj.Tags[objTagKey] = objTagVal
		}
		tag := Tag{Key: searchKey, Value: searchVal}
		_ = objectHasTag(obj, tag)
	})
}

func FuzzUploadHasTag(f *testing.F) {
	f.Add("env", "prod", "env", "prod")
	f.Add("env", "prod", "env", "dev")
	f.Add("", "", "key", "val")

	f.Fuzz(func(t *testing.T, uploadTagKey, uploadTagVal, searchKey, searchVal string) {
		upload := &MultipartUpload{
			Tags: map[string]string{},
		}
		if uploadTagKey != "" {
			upload.Tags[uploadTagKey] = uploadTagVal
		}
		tag := Tag{Key: searchKey, Value: searchVal}
		_ = uploadHasTag(upload, tag)
	})
}

func FuzzLifecycleNoncurrentExpirationDue(f *testing.F) {
	f.Add(30, 1, int64(1700000000), int64(1702592000))
	f.Add(0, 0, int64(1700000000), int64(1700000000))
	f.Add(1, 5, int64(1700000000), int64(1700086400))
	f.Add(365, 0, int64(1700000000), int64(1731536000))

	f.Fuzz(func(t *testing.T, noncurrentDays, newerVersions int, lastModUnix, nowUnix int64) {
		if noncurrentDays < 0 || newerVersions < 0 {
			return
		}
		if lastModUnix < 0 || nowUnix < 0 || lastModUnix > 1e12 || nowUnix > 1e12 {
			return
		}
		exp := &NoncurrentVersionExpiration{
			NoncurrentDays:          noncurrentDays,
			NewerNoncurrentVersions: newerVersions,
		}
		lastMod := time.Unix(lastModUnix, 0)
		now := time.Unix(nowUnix, 0)
		_ = lifecycleNoncurrentExpirationDue(exp, lastMod, now, 0)
	})
}

func FuzzHasNonDeleteVersion(f *testing.F) {
	f.Add(true, true, false)
	f.Add(false, false, false)
	f.Add(true, false, true)

	f.Fuzz(func(t *testing.T, hasDM, hasRegular, hasAnother bool) {
		var versions []*Object
		if hasDM {
			versions = append(versions, &Object{IsDeleteMarker: true})
		}
		if hasRegular {
			versions = append(versions, &Object{IsDeleteMarker: false})
		}
		if hasAnother {
			versions = append(versions, &Object{IsDeleteMarker: false})
		}
		_ = hasNonDeleteVersion(versions)
	})
}

func FuzzShouldDeleteExpiredObjectDeleteMarker(f *testing.F) {
	f.Add("key1", true, true, 1, true, int64(1700000000))
	f.Add("key2", false, true, 0, false, int64(1700000000))
	f.Add("key3", true, false, 2, true, int64(1700000000))

	f.Fuzz(
		func(t *testing.T, key string, expiredObjDelMarker, isDM bool, numVersions int, ruleEnabled bool, nowUnix int64) {
			if numVersions < 0 || numVersions > 10 {
				return
			}
			if nowUnix < 0 || nowUnix > 1e12 {
				return
			}
			rule := LifecycleRule{
				Status: "Enabled",
				Expiration: &LifecycleExpiration{
					ExpiredObjectDeleteMarker: expiredObjDelMarker,
				},
			}
			if !ruleEnabled {
				rule.Status = "Disabled"
			}
			var versions []*Object
			if isDM {
				versions = append(
					versions,
					&Object{IsDeleteMarker: true, LastModified: time.Unix(nowUnix-86400, 0)},
				)
			}
			for i := 0; i < numVersions; i++ {
				versions = append(versions, &Object{IsDeleteMarker: false})
			}
			now := time.Unix(nowUnix, 0)
			_ = shouldDeleteExpiredObjectDeleteMarker(
				key,
				versions,
				[]LifecycleRule{rule},
				now,
				24*time.Hour,
			)
		},
	)
}

func FuzzIsArchivedStorageClass(f *testing.F) {
	f.Add("GLACIER")
	f.Add("DEEP_ARCHIVE")
	f.Add("GLACIER_IR")
	f.Add("STANDARD")
	f.Add("REDUCED_REDUNDANCY")
	f.Add("")
	f.Add("glacier")
	f.Add("INTELLIGENT_TIERING")

	f.Fuzz(func(t *testing.T, sc string) {
		_ = IsArchivedStorageClass(sc)
	})
}

func FuzzNormalizeLifecycleConfiguration(f *testing.F) {
	f.Add("rule-1", "Enabled", "prefix/", 30)
	f.Add("", "Disabled", "", 0)
	f.Add("rule-id", "Enabled", "", 365)

	f.Fuzz(func(t *testing.T, ruleID, status, prefix string, days int) {
		if days < 0 {
			return
		}
		config := &LifecycleConfiguration{
			Rules: []LifecycleRule{
				{
					ID:     ruleID,
					Status: status,
					Filter: &LifecycleFilter{Prefix: prefix},
					Expiration: &LifecycleExpiration{
						Days: days,
					},
				},
			},
		}
		_ = normalizeLifecycleConfiguration(config)
	})
}
