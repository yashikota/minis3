package backend

import (
	"fmt"
	"strings"
	"time"
)

// ApplyLifecycle evaluates lifecycle rules against current backend state.
// dayDuration is used as the "one day" unit for debug/test environments.
func (b *Backend) ApplyLifecycle(now time.Time, dayDuration time.Duration) {
	if dayDuration <= 0 {
		dayDuration = 24 * time.Hour
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, bucket := range b.buckets {
		if bucket.LifecycleConfiguration == nil {
			continue
		}
		b.applyBucketLifecycle(bucket, now, dayDuration)
	}
	b.applyMultipartLifecycle(now, dayDuration)
}

func (b *Backend) applyBucketLifecycle(bucket *Bucket, now time.Time, dayDuration time.Duration) {
	for key, versions := range bucket.Objects {
		if versions == nil || len(versions.Versions) == 0 {
			delete(bucket.Objects, key)
			continue
		}

		if b.shouldExpireCurrentVersion(bucket, key, versions, now, dayDuration) {
			if bucket.VersioningStatus == VersioningEnabled ||
				bucket.VersioningStatus == VersioningSuspended {
				if !versions.Versions[0].IsDeleteMarker {
					_ = createDeleteMarkerUnlocked(bucket, key)
				}
			} else {
				delete(bucket.Objects, key)
				continue
			}
		}

		updated := bucket.Objects[key]
		applyCurrentTransitionRules(
			key,
			updated.Versions,
			bucket.LifecycleConfiguration.Rules,
			now,
			dayDuration,
		)
		applyNoncurrentTransitionRules(
			key,
			updated.Versions,
			bucket.LifecycleConfiguration.Rules,
			now,
			dayDuration,
		)
		updated.Versions = applyNoncurrentExpirationRules(
			key,
			updated.Versions,
			bucket.LifecycleConfiguration.Rules,
			now,
			dayDuration,
		)
		if len(updated.Versions) == 0 {
			delete(bucket.Objects, key)
			continue
		}
		if shouldDeleteExpiredObjectDeleteMarker(
			key,
			updated.Versions,
			bucket.LifecycleConfiguration.Rules,
			now,
			dayDuration,
		) {
			delete(bucket.Objects, key)
			continue
		}
		updated.Versions[0].IsLatest = true
	}
}

func applyCurrentTransitionRules(
	key string,
	versions []*Object,
	rules []LifecycleRule,
	now time.Time,
	dayDuration time.Duration,
) {
	if len(versions) == 0 || versions[0] == nil || versions[0].IsDeleteMarker {
		return
	}

	current := versions[0]
	for _, rule := range rules {
		if !isLifecycleRuleEnabled(rule) || len(rule.Transition) == 0 {
			continue
		}
		if !lifecycleRuleMatchesObject(rule, key, current) {
			continue
		}
		targetStorageClass, ok := dueLifecycleTransitionStorageClass(
			rule.Transition,
			current.LastModified,
			now,
			dayDuration,
		)
		if ok {
			current.StorageClass = targetStorageClass
		}
	}
}

func dueLifecycleTransitionStorageClass(
	transitions []LifecycleTransition,
	lastModified, now time.Time,
	dayDuration time.Duration,
) (string, bool) {
	bestClass := ""
	bestDueAt := time.Time{}
	found := false

	for _, transition := range transitions {
		if strings.TrimSpace(transition.StorageClass) == "" {
			continue
		}

		dueAt, ok := lifecycleTransitionDueAt(transition, lastModified, dayDuration)
		if !ok || dueAt.After(now) {
			continue
		}
		if !found || !dueAt.Before(bestDueAt) {
			bestClass = transition.StorageClass
			bestDueAt = dueAt
			found = true
		}
	}

	return bestClass, found
}

func lifecycleTransitionDueAt(
	transition LifecycleTransition,
	lastModified time.Time,
	dayDuration time.Duration,
) (time.Time, bool) {
	if transition.Days > 0 {
		return lastModified.Add(time.Duration(transition.Days) * dayDuration), true
	}
	if transition.Date == "" {
		return time.Time{}, false
	}

	transitionDate, err := parseLifecycleDate(transition.Date)
	if err != nil {
		return time.Time{}, false
	}
	return transitionDate, true
}

func applyNoncurrentTransitionRules(
	key string,
	versions []*Object,
	rules []LifecycleRule,
	now time.Time,
	dayDuration time.Duration,
) {
	if len(versions) == 0 {
		return
	}

	for _, rule := range rules {
		if !isLifecycleRuleEnabled(rule) || len(rule.NoncurrentVersionTransition) == 0 {
			continue
		}

		seenMatchingNoncurrent := 0
		for _, obj := range versions {
			if obj == nil || obj.IsLatest || obj.IsDeleteMarker {
				continue
			}
			if !lifecycleRuleMatchesObject(rule, key, obj) {
				continue
			}
			seenMatchingNoncurrent++

			targetStorageClass, ok := dueNoncurrentTransitionStorageClass(
				rule.NoncurrentVersionTransition,
				obj.LastModified,
				now,
				dayDuration,
				seenMatchingNoncurrent,
			)
			if ok {
				obj.StorageClass = targetStorageClass
			}
		}
	}
}

func dueNoncurrentTransitionStorageClass(
	transitions []NoncurrentVersionTransition,
	lastModified, now time.Time,
	dayDuration time.Duration,
	seenMatchingNoncurrent int,
) (string, bool) {
	bestClass := ""
	bestDueAt := time.Time{}
	found := false

	for _, transition := range transitions {
		if transition.NoncurrentDays <= 0 || strings.TrimSpace(transition.StorageClass) == "" {
			continue
		}
		if transition.NewerNoncurrentVersions > 0 &&
			seenMatchingNoncurrent <= transition.NewerNoncurrentVersions {
			continue
		}

		dueAt := lastModified.Add(time.Duration(transition.NoncurrentDays) * dayDuration)
		if dueAt.After(now) {
			continue
		}
		if !found || !dueAt.Before(bestDueAt) {
			bestClass = transition.StorageClass
			bestDueAt = dueAt
			found = true
		}
	}

	return bestClass, found
}

func (b *Backend) shouldExpireCurrentVersion(
	bucket *Bucket,
	key string,
	versions *ObjectVersions,
	now time.Time,
	dayDuration time.Duration,
) bool {
	if versions == nil || len(versions.Versions) == 0 {
		return false
	}
	current := versions.Versions[0]
	if current.IsDeleteMarker {
		return false
	}

	for _, rule := range bucket.LifecycleConfiguration.Rules {
		if !isLifecycleRuleEnabled(rule) || rule.Expiration == nil {
			continue
		}
		if !lifecycleRuleMatchesObject(rule, key, current) {
			continue
		}
		if lifecycleExpirationDue(rule.Expiration, current.LastModified, now, dayDuration) {
			return true
		}
	}
	return false
}

func applyNoncurrentExpirationRules(
	key string,
	versions []*Object,
	rules []LifecycleRule,
	now time.Time,
	dayDuration time.Duration,
) []*Object {
	if len(versions) == 0 {
		return versions
	}

	toDelete := make(map[int]struct{})
	for _, rule := range rules {
		nc := rule.NoncurrentVersionExpiration
		if !isLifecycleRuleEnabled(rule) || nc == nil || nc.NoncurrentDays <= 0 {
			continue
		}

		seenMatchingNoncurrent := 0
		for idx, obj := range versions {
			if obj.IsLatest || obj.IsDeleteMarker {
				continue
			}
			if !lifecycleRuleMatchesObject(rule, key, obj) {
				continue
			}
			seenMatchingNoncurrent++
			if nc.NewerNoncurrentVersions > 0 &&
				seenMatchingNoncurrent <= nc.NewerNoncurrentVersions {
				continue
			}
			if lifecycleNoncurrentExpirationDue(
				nc,
				obj.LastModified,
				now,
				dayDuration,
			) {
				toDelete[idx] = struct{}{}
			}
		}
	}

	if len(toDelete) == 0 {
		return versions
	}

	next := make([]*Object, 0, len(versions)-len(toDelete))
	for idx, obj := range versions {
		if _, ok := toDelete[idx]; ok {
			continue
		}
		next = append(next, obj)
	}
	return next
}

func isLifecycleRuleEnabled(rule LifecycleRule) bool {
	return rule.Status == LifecycleStatusEnabled
}

func lifecycleRuleMatchesObject(rule LifecycleRule, key string, obj *Object) bool {
	if obj == nil {
		return false
	}
	if rule.Prefix != "" && !strings.HasPrefix(key, rule.Prefix) {
		return false
	}
	if rule.Filter == nil {
		return true
	}

	filter := rule.Filter
	if filter.Prefix != "" && !strings.HasPrefix(key, filter.Prefix) {
		return false
	}
	if !lifecycleObjectSizeMatch(
		obj.Size,
		filter.ObjectSizeGreaterThan,
		filter.ObjectSizeLessThan,
	) {
		return false
	}
	if filter.Tag != nil && !objectHasTag(obj, *filter.Tag) {
		return false
	}

	if filter.And != nil {
		if filter.And.Prefix != "" && !strings.HasPrefix(key, filter.And.Prefix) {
			return false
		}
		if !lifecycleObjectSizeMatch(
			obj.Size,
			filter.And.ObjectSizeGreaterThan,
			filter.And.ObjectSizeLessThan,
		) {
			return false
		}
		for _, tag := range filter.And.Tags {
			if !objectHasTag(obj, tag) {
				return false
			}
		}
	}
	return true
}

func lifecycleObjectSizeMatch(size int64, greaterThan, lessThan int64) bool {
	if greaterThan > 0 && size <= greaterThan {
		return false
	}
	if lessThan > 0 && size >= lessThan {
		return false
	}
	return true
}

func objectHasTag(obj *Object, tag Tag) bool {
	if obj == nil || obj.Tags == nil || tag.Key == "" {
		return false
	}
	value, ok := obj.Tags[tag.Key]
	return ok && value == tag.Value
}

func lifecycleExpirationDue(
	expiration *LifecycleExpiration,
	lastModified, now time.Time,
	dayDuration time.Duration,
) bool {
	if expiration == nil {
		return false
	}
	if expiration.Days > 0 {
		return !lastModified.Add(time.Duration(expiration.Days) * dayDuration).After(now)
	}
	if expiration.Date != "" {
		date, err := parseLifecycleDate(expiration.Date)
		if err != nil {
			return false
		}
		return !date.After(now)
	}
	return false
}

func lifecycleNoncurrentExpirationDue(
	expiration *NoncurrentVersionExpiration,
	lastModified, now time.Time,
	dayDuration time.Duration,
) bool {
	if expiration == nil || expiration.NoncurrentDays <= 0 {
		return false
	}
	return !lastModified.Add(time.Duration(expiration.NoncurrentDays) * dayDuration).After(now)
}

func shouldDeleteExpiredObjectDeleteMarker(
	key string,
	versions []*Object,
	rules []LifecycleRule,
	now time.Time,
	dayDuration time.Duration,
) bool {
	if len(versions) == 0 || !versions[0].IsDeleteMarker {
		return false
	}
	if hasNonDeleteVersion(versions) {
		return false
	}

	currentDeleteMarker := versions[0]
	for _, rule := range rules {
		if !isLifecycleRuleEnabled(rule) || rule.Expiration == nil {
			continue
		}
		if !lifecycleRuleMatchesObject(rule, key, currentDeleteMarker) {
			continue
		}

		expiration := rule.Expiration
		if expiration.ExpiredObjectDeleteMarker {
			return true
		}
		if expiration.Days > 0 {
			if !currentDeleteMarker.LastModified.Add(
				time.Duration(expiration.Days) * dayDuration,
			).After(now) {
				return true
			}
			continue
		}
		if expiration.Date != "" {
			expiryDate, err := parseLifecycleDate(expiration.Date)
			if err == nil && !expiryDate.After(now) {
				return true
			}
		}
	}
	return false
}

func hasNonDeleteVersion(versions []*Object) bool {
	for _, version := range versions {
		if !version.IsDeleteMarker {
			return true
		}
	}
	return false
}

func (b *Backend) applyMultipartLifecycle(now time.Time, dayDuration time.Duration) {
	for uploadID, upload := range b.uploads {
		if upload == nil {
			continue
		}
		bucket, ok := b.buckets[upload.Bucket]
		if !ok || bucket.LifecycleConfiguration == nil {
			continue
		}
		initiated, err := time.Parse(time.RFC3339, upload.Initiated)
		if err != nil {
			continue
		}

		for _, rule := range bucket.LifecycleConfiguration.Rules {
			abort := rule.AbortIncompleteMultipartUpload
			if !isLifecycleRuleEnabled(rule) || abort == nil || abort.DaysAfterInitiation <= 0 {
				continue
			}
			if !lifecycleRuleMatchesUpload(rule, upload) {
				continue
			}
			expireAt := initiated.Add(time.Duration(abort.DaysAfterInitiation) * dayDuration)
			if !expireAt.After(now) {
				delete(b.uploads, uploadID)
				break
			}
		}
	}
}

func lifecycleRuleMatchesUpload(rule LifecycleRule, upload *MultipartUpload) bool {
	if upload == nil {
		return false
	}
	key := upload.Key
	if rule.Prefix != "" && !strings.HasPrefix(key, rule.Prefix) {
		return false
	}
	if rule.Filter == nil {
		return true
	}
	if rule.Filter.Prefix != "" && !strings.HasPrefix(key, rule.Filter.Prefix) {
		return false
	}
	if rule.Filter.Tag != nil && !uploadHasTag(upload, *rule.Filter.Tag) {
		return false
	}
	if rule.Filter.And != nil {
		if rule.Filter.And.Prefix != "" && !strings.HasPrefix(key, rule.Filter.And.Prefix) {
			return false
		}
		for _, tag := range rule.Filter.And.Tags {
			if !uploadHasTag(upload, tag) {
				return false
			}
		}
	}
	return true
}

func uploadHasTag(upload *MultipartUpload, tag Tag) bool {
	if upload == nil || upload.Tags == nil || tag.Key == "" {
		return false
	}
	value, ok := upload.Tags[tag.Key]
	return ok && value == tag.Value
}

func parseLifecycleDate(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid lifecycle date: %q", value)
}
