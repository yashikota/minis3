package backend

import (
	"errors"
	"testing"
	"time"
)

func TestObjectLockConfigAndBucketCreationBranches(t *testing.T) {
	b := New()

	if err := b.PutObjectLockConfiguration("missing", &ObjectLockConfiguration{
		ObjectLockEnabled: "Enabled",
	}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound from PutObjectLockConfiguration, got %v", err)
	}

	if _, err := b.GetObjectLockConfiguration("missing"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("plain-lock-branch"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.GetObjectLockConfiguration("plain-lock-branch"); !errors.Is(err, ErrObjectLockNotEnabled) {
		t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("lock-default-config"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	cfg, err := b.GetObjectLockConfiguration("lock-default-config")
	if err != nil {
		t.Fatalf("GetObjectLockConfiguration failed: %v", err)
	}
	if cfg.ObjectLockEnabled != "Enabled" || cfg.Rule != nil {
		t.Fatalf("unexpected default config: %+v", cfg)
	}

	if err := b.CreateBucket("versioned-enablable-lock"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("versioned-enablable-lock", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if err := b.PutObjectLockConfiguration("versioned-enablable-lock", &ObjectLockConfiguration{
		ObjectLockEnabled: "Enabled",
		Rule:              &ObjectLockRule{DefaultRetention: &DefaultRetention{Mode: RetentionModeGovernance, Days: 1}},
	}); err != nil {
		t.Fatalf("PutObjectLockConfiguration failed: %v", err)
	}
	bucket, ok := b.GetBucket("versioned-enablable-lock")
	if !ok || !bucket.ObjectLockEnabled {
		t.Fatalf("expected object lock enabled after PutObjectLockConfiguration, bucket=%+v", bucket)
	}

	if err := b.PutObjectLockConfiguration("versioned-enablable-lock", &ObjectLockConfiguration{
		ObjectLockEnabled: "Enabled",
		Rule:              &ObjectLockRule{DefaultRetention: &DefaultRetention{Mode: RetentionModeGovernance, Days: -1}},
	}); !errors.Is(err, ErrInvalidRetentionPeriod) {
		t.Fatalf("expected ErrInvalidRetentionPeriod for negative days, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("Invalid_Name"); !errors.Is(err, ErrInvalidBucketName) {
		t.Fatalf("expected ErrInvalidBucketName, got %v", err)
	}
	if err := b.CreateBucketWithObjectLock("lock-default-config"); !errors.Is(err, ErrBucketAlreadyOwnedByYou) {
		t.Fatalf("expected ErrBucketAlreadyOwnedByYou, got %v", err)
	}
}

func TestObjectRetentionBranches(t *testing.T) {
	b := New()

	if err := b.PutObjectRetention("missing", "key", "", &ObjectLockRetention{}, false); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("plain-retention-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject("plain-retention-bucket", "obj", []byte("x"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if err := b.PutObjectRetention("plain-retention-bucket", "obj", "", &ObjectLockRetention{}, false); !errors.Is(err, ErrObjectLockNotEnabled) {
		t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("retention-bucket-branches"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	if err := b.PutObjectRetention("retention-bucket-branches", "missing", "", &ObjectLockRetention{}, false); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	future := time.Now().UTC().Add(2 * time.Hour)
	obj, err := b.PutObject("retention-bucket-branches", "obj", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeGovernance,
		RetainUntilDate: &future,
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	if err := b.PutObjectRetention("retention-bucket-branches", "obj", "missing-version", &ObjectLockRetention{}, false); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	if err := b.PutObjectRetention("retention-bucket-branches", "obj", obj.VersionId, &ObjectLockRetention{
		Mode:            RetentionModeGovernance,
		RetainUntilDate: future.Add(1 * time.Hour).Format(time.RFC3339),
	}, false); err != nil {
		t.Fatalf("expected governance extension to succeed, got %v", err)
	}

	if err := b.PutObjectRetention("retention-bucket-branches", "obj", obj.VersionId, &ObjectLockRetention{
		Mode:            RetentionModeCompliance,
		RetainUntilDate: future.Add(2 * time.Hour).Format(time.RFC3339),
	}, false); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("expected ErrObjectLocked for governance mode change without bypass, got %v", err)
	}

	compFuture := time.Now().UTC().Add(3 * time.Hour)
	compObj, err := b.PutObject("retention-bucket-branches", "compliance", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeCompliance,
		RetainUntilDate: &compFuture,
	})
	if err != nil {
		t.Fatalf("PutObject compliance failed: %v", err)
	}

	if err := b.PutObjectRetention("retention-bucket-branches", "compliance", compObj.VersionId, &ObjectLockRetention{
		Mode:            RetentionModeGovernance,
		RetainUntilDate: compFuture.Add(1 * time.Hour).Format(time.RFC3339),
	}, true); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("expected ErrObjectLocked for compliance mode change, got %v", err)
	}

	if err := b.PutObjectRetention("retention-bucket-branches", "compliance", compObj.VersionId, &ObjectLockRetention{
		Mode:            RetentionModeCompliance,
		RetainUntilDate: compFuture.Add(-30 * time.Minute).Format(time.RFC3339),
	}, true); !errors.Is(err, ErrObjectLocked) {
		t.Fatalf("expected ErrObjectLocked for compliance shortening, got %v", err)
	}

	_, err = b.DeleteObject("retention-bucket-branches", "compliance", false)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if err := b.PutObjectRetention("retention-bucket-branches", "compliance", "", &ObjectLockRetention{}, false); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound on delete marker latest, got %v", err)
	}

	if _, err := b.GetObjectRetention("missing", "obj", ""); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if _, err := b.GetObjectRetention("plain-retention-bucket", "obj", ""); !errors.Is(err, ErrObjectLockNotEnabled) {
		t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
	}
	if _, err := b.GetObjectRetention("retention-bucket-branches", "missing", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
	if _, err := b.GetObjectRetention("retention-bucket-branches", "obj", "missing-version"); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
	if _, err := b.GetObjectRetention("retention-bucket-branches", "obj", ""); err != nil {
		t.Fatalf("expected GetObjectRetention latest-version lookup success, got %v", err)
	}

	if _, err := b.DeleteObject("retention-bucket-branches", "obj", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if _, err := b.GetObjectRetention("retention-bucket-branches", "obj", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound from GetObjectRetention on delete marker, got %v", err)
	}
}

func TestObjectLegalHoldBranches(t *testing.T) {
	b := New()

	if _, err := b.GetObjectLegalHold("missing", "key", ""); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if err := b.PutObjectLegalHold("missing", "key", "", &ObjectLockLegalHold{Status: LegalHoldStatusOn}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("plain-legalhold-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObject("plain-legalhold-bucket", "obj", []byte("x"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if _, err := b.GetObjectLegalHold("plain-legalhold-bucket", "obj", ""); !errors.Is(err, ErrObjectLockNotEnabled) {
		t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
	}
	if err := b.PutObjectLegalHold("plain-legalhold-bucket", "obj", "", &ObjectLockLegalHold{Status: LegalHoldStatusOn}); !errors.Is(err, ErrObjectLockNotEnabled) {
		t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("legalhold-bucket-branches"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	if _, err := b.GetObjectLegalHold("legalhold-bucket-branches", "missing", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
	if err := b.PutObjectLegalHold("legalhold-bucket-branches", "missing", "", &ObjectLockLegalHold{Status: LegalHoldStatusOn}); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	obj, err := b.PutObject("legalhold-bucket-branches", "obj", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	if _, err := b.GetObjectLegalHold("legalhold-bucket-branches", "obj", "missing-version"); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
	if err := b.PutObjectLegalHold("legalhold-bucket-branches", "obj", "missing-version", &ObjectLockLegalHold{Status: LegalHoldStatusOn}); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	if err := b.PutObjectLegalHold("legalhold-bucket-branches", "obj", obj.VersionId, &ObjectLockLegalHold{Status: LegalHoldStatusOff}); err != nil {
		t.Fatalf("PutObjectLegalHold OFF failed: %v", err)
	}
	if hold, err := b.GetObjectLegalHold("legalhold-bucket-branches", "obj", obj.VersionId); err != nil {
		t.Fatalf("GetObjectLegalHold failed: %v", err)
	} else if hold.Status != LegalHoldStatusOff {
		t.Fatalf("expected legal hold OFF, got %q", hold.Status)
	}

	_, err = b.DeleteObject("legalhold-bucket-branches", "obj", false)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if _, err := b.GetObjectLegalHold("legalhold-bucket-branches", "obj", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound on delete marker latest, got %v", err)
	}
	if err := b.PutObjectLegalHold("legalhold-bucket-branches", "obj", "", &ObjectLockLegalHold{Status: LegalHoldStatusOn}); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound on delete marker latest, got %v", err)
	}
}
