package backend

import (
	"testing"
	"time"
)

func FuzzLifecycleObjectSizeMatch(f *testing.F) {
	f.Add(int64(100), int64(0), int64(0))
	f.Add(int64(100), int64(50), int64(200))
	f.Add(int64(100), int64(100), int64(0))
	f.Add(int64(100), int64(0), int64(100))
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(1000000), int64(500000), int64(2000000))
	f.Add(int64(-1), int64(0), int64(100))

	f.Fuzz(func(t *testing.T, size, greaterThan, lessThan int64) {
		_ = lifecycleObjectSizeMatch(size, greaterThan, lessThan)
	})
}

func FuzzLifecycleExpirationDue(f *testing.F) {
	now := time.Now()
	f.Add(int64(30), "", now.Add(-31*24*time.Hour).Unix(), now.Unix())
	f.Add(int64(30), "", now.Add(-29*24*time.Hour).Unix(), now.Unix())
	f.Add(int64(0), "2024-01-01T00:00:00Z", now.Unix(), now.Unix())
	f.Add(int64(0), "2099-01-01T00:00:00Z", now.Unix(), now.Unix())
	f.Add(int64(1), "", now.Unix(), now.Unix())
	f.Add(int64(0), "invalid-date", now.Unix(), now.Unix())
	f.Add(int64(0), "", now.Unix(), now.Unix())

	f.Fuzz(func(t *testing.T, days int64, date string, lastModifiedUnix, nowUnix int64) {
		expiration := &LifecycleExpiration{
			Days: int(days),
			Date: date,
		}
		lastModified := time.Unix(lastModifiedUnix, 0)
		nowTime := time.Unix(nowUnix, 0)
		_ = lifecycleExpirationDue(expiration, lastModified, nowTime, 24*time.Hour)
	})
}

func FuzzLifecycleRuleMatchesObject(f *testing.F) {
	f.Add("prefix/", "prefix/key.txt", int64(1024), "tag-key", "tag-value")
	f.Add("", "any-key.txt", int64(0), "", "")
	f.Add("logs/", "data/file.txt", int64(500), "", "")
	f.Add("", "key", int64(999999999), "env", "prod")

	f.Fuzz(func(t *testing.T, prefix, key string, size int64, tagKey, tagValue string) {
		if size < 0 {
			size = 0
		}
		obj := &Object{
			Size: size,
		}
		if tagKey != "" {
			obj.Tags = map[string]string{tagKey: tagValue}
		}
		rule := LifecycleRule{
			Status: LifecycleStatusEnabled,
			Prefix: prefix,
		}
		_ = lifecycleRuleMatchesObject(rule, key, obj)
	})
}
