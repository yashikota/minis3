package backend

import (
	"errors"
	"testing"
	"time"
)

func TestApplyLifecycleExpiresCurrentObjectByPrefix(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-apply"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject("lifecycle-apply", "expire1/foo", []byte("foo"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject expire1/foo failed: %v", err)
	}
	if _, err := b.PutObject("lifecycle-apply", "keep2/bar", []byte("bar"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject keep2/bar failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "rule1",
				Status: LifecycleStatusEnabled,
				Prefix: "expire1/",
				Expiration: &LifecycleExpiration{
					Days: 1,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-apply", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	b.ApplyLifecycle(time.Now().UTC().Add(11*time.Second), 10*time.Second)

	if _, err := b.GetObject("lifecycle-apply", "expire1/foo"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected expire1/foo to be expired, got err=%v", err)
	}
	if _, err := b.GetObject("lifecycle-apply", "keep2/bar"); err != nil {
		t.Fatalf("expected keep2/bar to remain, got err=%v", err)
	}
}

func TestApplyLifecycleExpiresByTagAndAndFilter(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-tags"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject("lifecycle-tags", "days1/tom", []byte("tom"), PutObjectOptions{
		Tags: map[string]string{"tom": "sawyer"},
	}); err != nil {
		t.Fatalf("PutObject days1/tom failed: %v", err)
	}
	if _, err := b.PutObject("lifecycle-tags", "days1/huck", []byte("huck"), PutObjectOptions{
		Tags: map[string]string{"tom": "sawyer", "huck": "finn"},
	}); err != nil {
		t.Fatalf("PutObject days1/huck failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "rule_tag1",
				Status: LifecycleStatusEnabled,
				Expiration: &LifecycleExpiration{
					Days: 1,
				},
				Filter: &LifecycleFilter{
					Prefix: "days1/",
					Tag: &Tag{
						Key:   "tom",
						Value: "sawyer",
					},
					And: &LifecycleFilterAnd{
						Prefix: "days1",
						Tags: []Tag{
							{
								Key:   "huck",
								Value: "finn",
							},
						},
					},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-tags", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	b.ApplyLifecycle(time.Now().UTC().Add(11*time.Second), 10*time.Second)

	if _, err := b.GetObject("lifecycle-tags", "days1/huck"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected days1/huck to be expired, got err=%v", err)
	}
	if _, err := b.GetObject("lifecycle-tags", "days1/tom"); err != nil {
		t.Fatalf("expected days1/tom to remain, got err=%v", err)
	}
}

func TestApplyLifecycleExpiresNoncurrentVersions(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-noncurrent"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("lifecycle-noncurrent", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	for i := 0; i < 4; i++ {
		if _, err := b.PutObject(
			"lifecycle-noncurrent",
			"myobject",
			[]byte{byte('a' + i)},
			PutObjectOptions{},
		); err != nil {
			t.Fatalf("PutObject version %d failed: %v", i, err)
		}
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "noncurrent-rule",
				Status: LifecycleStatusEnabled,
				Filter: &LifecycleFilter{
					Prefix: "",
				},
				NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
					NoncurrentDays:          1,
					NewerNoncurrentVersions: 1,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-noncurrent", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	b.ApplyLifecycle(time.Now().UTC().Add(11*time.Second), 10*time.Second)

	bucket, ok := b.GetBucket("lifecycle-noncurrent")
	if !ok || bucket == nil {
		t.Fatal("GetBucket failed after lifecycle apply")
	}
	versions := bucket.Objects["myobject"].Versions
	if len(versions) != 2 {
		t.Fatalf("expected current + 1 noncurrent versions, got %d", len(versions))
	}
	if !versions[0].IsLatest {
		t.Fatal("expected newest version to stay latest")
	}
}

func TestApplyLifecycleDeletesExpiredObjectDeleteMarker(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-delete-marker"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("lifecycle-delete-marker", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	if _, err := b.PutObject("lifecycle-delete-marker", "test1/a", []byte("a"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject test1/a failed: %v", err)
	}
	if _, err := b.PutObject("lifecycle-delete-marker", "test2/abc", []byte("b"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject test2/abc failed: %v", err)
	}
	if _, err := b.DeleteObject("lifecycle-delete-marker", "test1/a", false); err != nil {
		t.Fatalf("DeleteObject test1/a failed: %v", err)
	}
	if _, err := b.DeleteObject("lifecycle-delete-marker", "test2/abc", false); err != nil {
		t.Fatalf("DeleteObject test2/abc failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "rule1",
				Status: LifecycleStatusEnabled,
				Prefix: "test1/",
				NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
					NoncurrentDays: 1,
				},
				Expiration: &LifecycleExpiration{
					ExpiredObjectDeleteMarker: true,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-delete-marker", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	b.ApplyLifecycle(time.Now().UTC().Add(70*time.Second), 10*time.Second)

	bucket, ok := b.GetBucket("lifecycle-delete-marker")
	if !ok || bucket == nil {
		t.Fatal("GetBucket failed")
	}
	if _, exists := bucket.Objects["test1/a"]; exists {
		t.Fatalf(
			"expected test1/a to be removed after delete marker expiration, objects=%+v",
			bucket.Objects["test1/a"],
		)
	}
	if versions, exists := bucket.Objects["test2/abc"]; !exists || len(versions.Versions) != 2 {
		t.Fatalf("expected test2/abc to remain with 2 versions, got %+v", versions)
	}
}

func TestApplyLifecycleDeletesOrphanDeleteMarkerAfterExpirationDays(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-delete-marker-days"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("lifecycle-delete-marker-days", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	if _, err := b.PutObject("lifecycle-delete-marker-days", "test1/a", []byte("a"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject test1/a failed: %v", err)
	}
	if _, err := b.DeleteObject("lifecycle-delete-marker-days", "test1/a", false); err != nil {
		t.Fatalf("DeleteObject test1/a failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "rule1",
				Status: LifecycleStatusEnabled,
				Prefix: "test1/",
				NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
					NoncurrentDays: 1,
				},
				Expiration: &LifecycleExpiration{
					Days: 5,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-delete-marker-days", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	bucket, ok := b.GetBucket("lifecycle-delete-marker-days")
	if !ok || bucket == nil {
		t.Fatal("GetBucket failed")
	}
	dmTime := bucket.Objects["test1/a"].Versions[0].LastModified

	// Before 5 debug-days (5 * 10 seconds), delete marker should remain.
	b.ApplyLifecycle(dmTime.Add(40*time.Second), 10*time.Second)
	if versions, exists := bucket.Objects["test1/a"]; !exists || len(versions.Versions) != 1 {
		t.Fatalf("expected delete marker to remain before expiration, got %+v", versions)
	}

	// After 5 debug-days, delete marker should expire.
	b.ApplyLifecycle(dmTime.Add(60*time.Second), 10*time.Second)
	if _, exists := bucket.Objects["test1/a"]; exists {
		t.Fatalf(
			"expected delete marker to expire after 5 debug-days, got %+v",
			bucket.Objects["test1/a"],
		)
	}
}

func TestApplyLifecycleAbortsIncompleteMultipartUpload(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-multipart"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	up1, err := b.CreateMultipartUpload(
		"lifecycle-multipart",
		"test1/a",
		CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload test1/a failed: %v", err)
	}
	up2, err := b.CreateMultipartUpload(
		"lifecycle-multipart",
		"test2/",
		CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload test2/ failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "rule1",
				Status: LifecycleStatusEnabled,
				Prefix: "test1/",
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 2,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-multipart", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	initiated, err := time.Parse(time.RFC3339, up1.Initiated)
	if err != nil {
		t.Fatalf("failed to parse upload initiation time: %v", err)
	}
	b.ApplyLifecycle(initiated.Add(25*time.Second), 10*time.Second)

	if _, ok := b.GetUpload(up1.UploadId); ok {
		t.Fatal("expected test1/a multipart upload to be aborted")
	}
	if _, ok := b.GetUpload(up2.UploadId); !ok {
		t.Fatal("expected test2/ multipart upload to remain")
	}
}

func TestApplyLifecycleTransitionsCurrentObjectStorageClass(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-current-transition"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject(
		"lifecycle-current-transition",
		"obj",
		[]byte("data"),
		PutObjectOptions{},
	); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "transition-rule",
				Status: LifecycleStatusEnabled,
				Transition: []LifecycleTransition{
					{Days: 1, StorageClass: "STANDARD_IA"},
					{Days: 3, StorageClass: "GLACIER"},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-current-transition", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	obj, err := b.GetObject("lifecycle-current-transition", "obj")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	base := obj.LastModified

	b.ApplyLifecycle(base.Add(11*time.Second), 10*time.Second)

	obj, err = b.GetObject("lifecycle-current-transition", "obj")
	if err != nil {
		t.Fatalf("GetObject after first transition failed: %v", err)
	}
	if obj.StorageClass != "STANDARD_IA" {
		t.Fatalf("expected STANDARD_IA after first transition, got %q", obj.StorageClass)
	}

	b.ApplyLifecycle(base.Add(31*time.Second), 10*time.Second)

	obj, err = b.GetObject("lifecycle-current-transition", "obj")
	if err != nil {
		t.Fatalf("GetObject after second transition failed: %v", err)
	}
	if obj.StorageClass != "GLACIER" {
		t.Fatalf("expected GLACIER after second transition, got %q", obj.StorageClass)
	}
}

func TestApplyLifecycleTransitionsNoncurrentVersionsStorageClass(t *testing.T) {
	b := New()
	if err := b.CreateBucket("lifecycle-noncurrent-transition"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning(
		"lifecycle-noncurrent-transition",
		VersioningEnabled,
		MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := b.PutObject(
			"lifecycle-noncurrent-transition",
			"obj",
			[]byte{byte('a' + i)},
			PutObjectOptions{},
		); err != nil {
			t.Fatalf("PutObject version %d failed: %v", i, err)
		}
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "noncurrent-transition-rule",
				Status: LifecycleStatusEnabled,
				NoncurrentVersionTransition: []NoncurrentVersionTransition{
					{
						NoncurrentDays:          1,
						StorageClass:            "STANDARD_IA",
						NewerNoncurrentVersions: 1,
					},
					{
						NoncurrentDays: 2,
						StorageClass:   "GLACIER",
					},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-noncurrent-transition", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	bucket, ok := b.GetBucket("lifecycle-noncurrent-transition")
	if !ok || bucket == nil {
		t.Fatal("GetBucket failed")
	}
	base := bucket.Objects["obj"].Versions[0].LastModified

	b.ApplyLifecycle(base.Add(11*time.Second), 10*time.Second)

	versions := bucket.Objects["obj"].Versions
	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}
	if versions[1].StorageClass != "STANDARD" {
		t.Fatalf(
			"expected newest noncurrent to remain STANDARD, got %q",
			versions[1].StorageClass,
		)
	}
	if versions[2].StorageClass != "STANDARD_IA" {
		t.Fatalf(
			"expected oldest noncurrent to transition to STANDARD_IA, got %q",
			versions[2].StorageClass,
		)
	}

	b.ApplyLifecycle(base.Add(21*time.Second), 10*time.Second)

	versions = bucket.Objects["obj"].Versions
	if versions[1].StorageClass != "GLACIER" {
		t.Fatalf(
			"expected newest noncurrent to transition to GLACIER, got %q",
			versions[1].StorageClass,
		)
	}
	if versions[2].StorageClass != "GLACIER" {
		t.Fatalf(
			"expected oldest noncurrent to transition to GLACIER, got %q",
			versions[2].StorageClass,
		)
	}
}

func TestApplyLifecycleCurrentTransitionKeepsLatestDueAcrossRules(t *testing.T) {
	t.Setenv("MINIS3_CLOUD_STORAGE_CLASS", "GLACIER")
	t.Setenv("MINIS3_CLOUD_RETAIN_HEAD_OBJECT", "true")
	t.Setenv("MINIS3_CLOUD_TARGET_BUCKET", "lifecycle-cloud-target")

	b := New()
	if err := b.CreateBucket("lifecycle-multi-rules"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject(
		"lifecycle-multi-rules",
		"expire1/foo",
		[]byte("data"),
		PutObjectOptions{},
	); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "to-ia",
				Status: LifecycleStatusEnabled,
				Prefix: "expire1/",
				Transition: []LifecycleTransition{
					{Days: 1, StorageClass: "STANDARD_IA"},
				},
			},
			{
				ID:     "to-glacier",
				Status: LifecycleStatusEnabled,
				Prefix: "expire1/",
				Transition: []LifecycleTransition{
					{Days: 5, StorageClass: "GLACIER"},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-multi-rules", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	obj, err := b.GetObject("lifecycle-multi-rules", "expire1/foo")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	base := obj.LastModified

	b.ApplyLifecycle(base.Add(6*time.Second), time.Second)
	obj, err = b.GetObject("lifecycle-multi-rules", "expire1/foo")
	if err != nil {
		t.Fatalf("GetObject after cloud transition failed: %v", err)
	}
	if obj.StorageClass != "GLACIER" {
		t.Fatalf("expected GLACIER, got %q", obj.StorageClass)
	}
	if obj.CloudTransitionedAt == nil {
		t.Fatal("expected CloudTransitionedAt to be set")
	}
	firstTransitionAt := *obj.CloudTransitionedAt

	b.ApplyLifecycle(base.Add(7*time.Second), time.Second)
	obj, err = b.GetObject("lifecycle-multi-rules", "expire1/foo")
	if err != nil {
		t.Fatalf("GetObject after second apply failed: %v", err)
	}
	if obj.StorageClass != "GLACIER" {
		t.Fatalf("expected GLACIER after second apply, got %q", obj.StorageClass)
	}
	if obj.CloudTransitionedAt == nil {
		t.Fatal("expected CloudTransitionedAt to stay set")
	}
	if !obj.CloudTransitionedAt.Equal(firstTransitionAt) {
		t.Fatalf(
			"expected CloudTransitionedAt unchanged, before=%v after=%v",
			firstTransitionAt,
			*obj.CloudTransitionedAt,
		)
	}
}

func TestApplyLifecycleDoesNotRetransitionTemporarilyRestoredObject(t *testing.T) {
	t.Setenv("MINIS3_CLOUD_STORAGE_CLASS", "GLACIER")
	t.Setenv("MINIS3_CLOUD_RETAIN_HEAD_OBJECT", "true")
	t.Setenv("MINIS3_CLOUD_TARGET_BUCKET", "lifecycle-cloud-target-restore")

	b := New()
	if err := b.CreateBucket("lifecycle-restore"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject(
		"lifecycle-restore",
		"obj",
		[]byte("restorable"),
		PutObjectOptions{},
	); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	cfg := &LifecycleConfiguration{
		Rules: []LifecycleRule{
			{
				ID:     "to-glacier",
				Status: LifecycleStatusEnabled,
				Transition: []LifecycleTransition{
					{Days: 1, StorageClass: "GLACIER"},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-restore", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	obj, err := b.GetObject("lifecycle-restore", "obj")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	base := obj.LastModified

	b.ApplyLifecycle(base.Add(2*time.Second), time.Second)

	result, err := b.RestoreObject("lifecycle-restore", "obj", "", 2)
	if err != nil {
		t.Fatalf("RestoreObject failed: %v", err)
	}
	if result.StatusCode != 202 {
		t.Fatalf("expected restore status 202, got %d", result.StatusCode)
	}

	obj, err = b.GetObject("lifecycle-restore", "obj")
	if err != nil {
		t.Fatalf("GetObject after restore failed: %v", err)
	}
	if obj.Size == 0 {
		t.Fatal("expected restored object size > 0")
	}
	if obj.RestoreExpiryDate == nil {
		t.Fatal("expected RestoreExpiryDate to be set")
	}
	expiry := *obj.RestoreExpiryDate

	b.ApplyLifecycle(base.Add(3*time.Second), time.Second)
	obj, err = b.GetObject("lifecycle-restore", "obj")
	if err != nil {
		t.Fatalf("GetObject after lifecycle reapply failed: %v", err)
	}
	if obj.Size == 0 {
		t.Fatal("expected restored data to remain available")
	}
	if obj.RestoreExpiryDate == nil {
		t.Fatal("expected RestoreExpiryDate to remain set")
	}
	if !obj.RestoreExpiryDate.Equal(expiry) {
		t.Fatalf(
			"expected RestoreExpiryDate unchanged, before=%v after=%v",
			expiry,
			*obj.RestoreExpiryDate,
		)
	}
}
