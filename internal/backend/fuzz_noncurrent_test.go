package backend

import (
	"testing"
	"time"
)

func FuzzDueNoncurrentTransitionStorageClass(f *testing.F) {
	f.Add("GLACIER", 30, 0, int64(1700000000), int64(1703000000), 1)
	f.Add("DEEP_ARCHIVE", 90, 2, int64(1700000000), int64(1710000000), 3)
	f.Add("", 0, 0, int64(1700000000), int64(1700000000), 0)
	f.Add("GLACIER", 1, 0, int64(1700000000), int64(1700100000), 0)
	f.Add("GLACIER_IR", 30, 1, int64(1700000000), int64(1703000000), 1)

	f.Fuzz(
		func(t *testing.T, sc string, noncurrentDays, newerVersions int, lastModUnix, nowUnix int64, seenMatching int) {
			if noncurrentDays < 0 || newerVersions < 0 || seenMatching < 0 {
				return
			}
			if lastModUnix < 0 || nowUnix < 0 || lastModUnix > 1e12 || nowUnix > 1e12 {
				return
			}
			transitions := []NoncurrentVersionTransition{
				{
					StorageClass:            sc,
					NoncurrentDays:          noncurrentDays,
					NewerNoncurrentVersions: newerVersions,
				},
			}
			lastMod := time.Unix(lastModUnix, 0)
			now := time.Unix(nowUnix, 0)
			_, _, _ = dueNoncurrentTransitionStorageClass(
				transitions,
				lastMod,
				now,
				24*time.Hour,
				seenMatching,
			)
		},
	)
}

func FuzzApplyNoncurrentExpirationRules(f *testing.F) {
	f.Add("prefix/key", 30, 0, int64(1700000000), int64(1703000000))
	f.Add("key", 1, 2, int64(1700000000), int64(1700100000))
	f.Add("", 0, 0, int64(1700000000), int64(1700000000))
	f.Add("deep/nested/key", 365, 1, int64(1700000000), int64(1731536000))

	f.Fuzz(
		func(t *testing.T, key string, noncurrentDays, newerVersions int, lastModUnix, nowUnix int64) {
			if noncurrentDays < 0 || newerVersions < 0 {
				return
			}
			if lastModUnix < 0 || nowUnix < 0 || lastModUnix > 1e12 || nowUnix > 1e12 {
				return
			}
			rule := LifecycleRule{
				Status: LifecycleStatusEnabled,
				NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
					NoncurrentDays:          noncurrentDays,
					NewerNoncurrentVersions: newerVersions,
				},
			}
			lastMod := time.Unix(lastModUnix, 0)
			versions := []*Object{
				{IsLatest: true, LastModified: lastMod},
				{IsLatest: false, LastModified: lastMod, IsDeleteMarker: false},
				{
					IsLatest:       false,
					LastModified:   lastMod.Add(-24 * time.Hour),
					IsDeleteMarker: false,
				},
			}
			now := time.Unix(nowUnix, 0)
			_ = applyNoncurrentExpirationRules(
				key,
				versions,
				[]LifecycleRule{rule},
				now,
				24*time.Hour,
			)
		},
	)
}
