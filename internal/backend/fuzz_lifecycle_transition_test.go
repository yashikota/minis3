package backend

import (
	"testing"
	"time"
)

func FuzzDueLifecycleTransitionStorageClass(f *testing.F) {
	f.Add("GLACIER", 30, "", "DEEP_ARCHIVE", 90, "", int64(1700000000), int64(1703000000))
	f.Add("GLACIER", 0, "2024-01-01T00:00:00Z", "", 0, "", int64(1700000000), int64(1704067200))
	f.Add("", 0, "", "", 0, "", int64(1700000000), int64(1700000000))
	f.Add("GLACIER_IR", 1, "", "", 0, "", int64(1700000000), int64(1700100000))

	f.Fuzz(func(t *testing.T, sc1 string, days1 int, date1, sc2 string, days2 int, date2 string, lastModUnix, nowUnix int64) {
		if days1 < 0 || days2 < 0 || lastModUnix < 0 || nowUnix < 0 {
			return
		}
		if lastModUnix > 1e12 || nowUnix > 1e12 {
			return
		}
		transitions := []LifecycleTransition{
			{StorageClass: sc1, Days: days1, Date: date1},
		}
		if sc2 != "" || days2 > 0 || date2 != "" {
			transitions = append(transitions, LifecycleTransition{
				StorageClass: sc2, Days: days2, Date: date2,
			})
		}
		lastMod := time.Unix(lastModUnix, 0)
		now := time.Unix(nowUnix, 0)
		_, _, _ = dueLifecycleTransitionStorageClass(transitions, lastMod, now, 24*time.Hour)
	})
}

func FuzzLifecycleTransitionDueAt(f *testing.F) {
	f.Add("GLACIER", 30, "", int64(1700000000))
	f.Add("DEEP_ARCHIVE", 0, "2024-01-01T00:00:00Z", int64(1700000000))
	f.Add("", 0, "", int64(1700000000))
	f.Add("GLACIER", 1, "", int64(0))
	f.Add("GLACIER_IR", 0, "invalid-date", int64(1700000000))
	f.Add("GLACIER", 365, "", int64(1700000000))

	f.Fuzz(func(t *testing.T, sc string, days int, date string, lastModUnix int64) {
		if days < 0 || lastModUnix < 0 || lastModUnix > 1e12 {
			return
		}
		transition := LifecycleTransition{
			StorageClass: sc,
			Days:         days,
			Date:         date,
		}
		lastMod := time.Unix(lastModUnix, 0)
		_, _ = lifecycleTransitionDueAt(transition, lastMod, 24*time.Hour)
	})
}

func FuzzCloudTargetBucketName(f *testing.F) {
	f.Add("GLACIER")
	f.Add("DEEP_ARCHIVE")
	f.Add("STANDARD")
	f.Add("")
	f.Add("custom-class")
	f.Add("INTELLIGENT_TIERING")

	f.Fuzz(func(t *testing.T, storageClass string) {
		_ = cloudTargetBucketName(storageClass)
	})
}
