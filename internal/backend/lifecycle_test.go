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
