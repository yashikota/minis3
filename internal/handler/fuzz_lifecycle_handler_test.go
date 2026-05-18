package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzLifecycleExpiryDate(f *testing.F) {
	f.Add(30, "", int64(1700000000))
	f.Add(0, "2024-01-01T00:00:00.000Z", int64(1700000000))
	f.Add(0, "", int64(1700000000))
	f.Add(365, "", int64(1700000000))
	f.Add(0, "invalid-date", int64(1700000000))

	f.Fuzz(func(t *testing.T, days int, date string, baseUnix int64) {
		if days < 0 || baseUnix < 0 || baseUnix > 1e12 {
			return
		}
		exp := &backend.LifecycleExpiration{
			Days: days,
			Date: date,
		}
		base := time.Unix(baseUnix, 0)
		_, _ = lifecycleExpiryDate(exp, base)
	})
}

func FuzzLifecycleRuleMatchesObjectForHeader(f *testing.F) {
	f.Add("prefix/", "prefix/key.txt", int64(1024), "env", "prod")
	f.Add("", "any-key", int64(0), "", "")
	f.Add("logs/", "data/file.csv", int64(500), "", "")
	f.Add("", "key", int64(100), "tag", "value")

	f.Fuzz(func(t *testing.T, prefix, key string, size int64, tagKey, tagValue string) {
		if size < 0 {
			return
		}
		rule := backend.LifecycleRule{
			Status: backend.LifecycleStatusEnabled,
			Filter: &backend.LifecycleFilter{
				Prefix: prefix,
			},
			Expiration: &backend.LifecycleExpiration{Days: 30},
		}
		if tagKey != "" {
			rule.Filter.Tag = &backend.Tag{Key: tagKey, Value: tagValue}
		}
		obj := &backend.Object{
			Size: size,
			Tags: map[string]string{},
		}
		if tagKey != "" {
			obj.Tags[tagKey] = tagValue
		}
		_ = lifecycleRuleMatchesObjectForHeader(rule, key, obj)
	})
}

func FuzzFindLifecycleExpirationForObject(f *testing.F) {
	f.Add("rule-1", "prefix/", 30, "prefix/key.txt", int64(1024), int64(1700000000))
	f.Add("", "", 0, "key", int64(0), int64(1700000000))
	f.Add("rule-2", "logs/", 365, "logs/app.log", int64(500), int64(1700000000))

	f.Fuzz(func(t *testing.T, ruleID, prefix string, days int, key string, size, lastModUnix int64) {
		if days < 0 || size < 0 || lastModUnix < 0 || lastModUnix > 1e12 {
			return
		}
		config := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:     ruleID,
					Status: backend.LifecycleStatusEnabled,
					Filter: &backend.LifecycleFilter{Prefix: prefix},
					Expiration: &backend.LifecycleExpiration{
						Days: days,
					},
				},
			},
		}
		obj := &backend.Object{
			Size:         size,
			LastModified: time.Unix(lastModUnix, 0),
			Tags:         map[string]string{},
		}
		_, _, _ = findLifecycleExpirationForObject(config, key, obj)
	})
}

func FuzzEvaluateDeletePreconditions(f *testing.F) {
	f.Add("\"etag123\"", "", "", "\"etag123\"", int64(1024), int64(1700000000), false)
	f.Add("*", "", "", "\"etag\"", int64(0), int64(1700000000), false)
	f.Add("", "2024-01-01T00:00:00Z", "", "\"etag\"", int64(500), int64(1700000000), false)
	f.Add("", "", "1024", "\"etag\"", int64(1024), int64(1700000000), false)
	f.Add("", "", "", "\"etag\"", int64(0), int64(1700000000), true)

	f.Fuzz(func(t *testing.T, ifMatch, lastModTime, ifMatchSize, etag string, size, lastModUnix int64, isDeleteMarker bool) {
		if lastModUnix < 0 || lastModUnix > 1e12 || size < 0 {
			return
		}
		req, err := http.NewRequest(http.MethodDelete, "/bucket/key", nil)
		if err != nil {
			return
		}
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		if lastModTime != "" {
			req.Header.Set("x-amz-if-match-last-modified-time", lastModTime)
		}
		if ifMatchSize != "" {
			req.Header.Set("x-amz-if-match-size", ifMatchSize)
		}
		obj := &backend.Object{
			ETag:           etag,
			Size:           size,
			LastModified:   time.Unix(lastModUnix, 0),
			IsDeleteMarker: isDeleteMarker,
		}
		_, _, _ = evaluateDeletePreconditions(req, obj)
	})
}
