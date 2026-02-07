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
