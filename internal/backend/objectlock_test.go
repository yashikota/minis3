package backend

import (
	"errors"
	"testing"
	"time"
)

func TestPutObjectLockConfigurationValidation(t *testing.T) {
	b := New()
	if err := b.CreateBucket("plain-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.CreateBucketWithObjectLock("lock-bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}

	t.Run("cannot configure on bucket without object lock", func(t *testing.T) {
		err := b.PutObjectLockConfiguration("plain-bucket", &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
		})
		if !errors.Is(err, ErrObjectLockNotEnabled) {
			t.Fatalf("expected ErrObjectLockNotEnabled, got %v", err)
		}
	})

	t.Run("invalid ObjectLockEnabled value", func(t *testing.T) {
		err := b.PutObjectLockConfiguration("lock-bucket", &ObjectLockConfiguration{
			ObjectLockEnabled: "Disabled",
		})
		if !errors.Is(err, ErrInvalidObjectLockConfig) {
			t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
		}
	})

	t.Run("invalid default retention mode", func(t *testing.T) {
		err := b.PutObjectLockConfiguration("lock-bucket", &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
			Rule: &ObjectLockRule{
				DefaultRetention: &DefaultRetention{
					Mode: "INVALID",
					Days: 10,
				},
			},
		})
		if !errors.Is(err, ErrInvalidObjectLockConfig) {
			t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
		}
	})

	t.Run("days and years cannot be set together", func(t *testing.T) {
		err := b.PutObjectLockConfiguration("lock-bucket", &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
			Rule: &ObjectLockRule{
				DefaultRetention: &DefaultRetention{
					Mode:  RetentionModeGovernance,
					Days:  10,
					Years: 1,
				},
			},
		})
		if !errors.Is(err, ErrInvalidObjectLockConfig) {
			t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
		}
	})

	t.Run("zero days and zero years is invalid", func(t *testing.T) {
		err := b.PutObjectLockConfiguration("lock-bucket", &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
			Rule: &ObjectLockRule{
				DefaultRetention: &DefaultRetention{
					Mode: RetentionModeGovernance,
				},
			},
		})
		if !errors.Is(err, ErrInvalidRetentionPeriod) {
			t.Fatalf("expected ErrInvalidRetentionPeriod, got %v", err)
		}
	})

	t.Run("valid default retention is stored", func(t *testing.T) {
		want := &ObjectLockConfiguration{
			ObjectLockEnabled: "Enabled",
			Rule: &ObjectLockRule{
				DefaultRetention: &DefaultRetention{
					Mode: RetentionModeCompliance,
					Days: 30,
				},
			},
		}
		if err := b.PutObjectLockConfiguration("lock-bucket", want); err != nil {
			t.Fatalf("PutObjectLockConfiguration failed: %v", err)
		}

		got, err := b.GetObjectLockConfiguration("lock-bucket")
		if err != nil {
			t.Fatalf("GetObjectLockConfiguration failed: %v", err)
		}
		if got.ObjectLockEnabled != "Enabled" {
			t.Fatalf("unexpected ObjectLockEnabled: %q", got.ObjectLockEnabled)
		}
		if got.Rule == nil || got.Rule.DefaultRetention == nil {
			t.Fatalf("expected default retention to be present: %#v", got)
		}
		if got.Rule.DefaultRetention.Mode != RetentionModeCompliance ||
			got.Rule.DefaultRetention.Days != 30 {
			t.Fatalf("unexpected default retention: %#v", got.Rule.DefaultRetention)
		}
	})
}

func TestPutObjectRetentionValidation(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("lock-retention-bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}

	future := time.Now().UTC().Add(24 * time.Hour)
	obj, err := b.PutObject("lock-retention-bucket", "obj", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeGovernance,
		RetainUntilDate: &future,
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("invalid mode", func(t *testing.T) {
		err := b.PutObjectRetention(
			"lock-retention-bucket",
			"obj",
			obj.VersionId,
			&ObjectLockRetention{
				Mode:            "INVALID",
				RetainUntilDate: future.Format(time.RFC3339),
			},
			false,
		)
		if !errors.Is(err, ErrInvalidObjectLockConfig) {
			t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
		}
	})

	t.Run("invalid retain-until-date format", func(t *testing.T) {
		err := b.PutObjectRetention(
			"lock-retention-bucket",
			"obj",
			obj.VersionId,
			&ObjectLockRetention{
				Mode:            RetentionModeGovernance,
				RetainUntilDate: "invalid-date",
			},
			false,
		)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest, got %v", err)
		}
	})

	t.Run("cannot shorten active governance retention without bypass", func(t *testing.T) {
		shorter := future.Add(-time.Hour).Format(time.RFC3339)
		err := b.PutObjectRetention(
			"lock-retention-bucket",
			"obj",
			obj.VersionId,
			&ObjectLockRetention{
				Mode:            RetentionModeGovernance,
				RetainUntilDate: shorter,
			},
			false,
		)
		if !errors.Is(err, ErrObjectLocked) {
			t.Fatalf("expected ErrObjectLocked, got %v", err)
		}
	})

	t.Run("can shorten active governance retention with bypass", func(t *testing.T) {
		shorter := future.Add(-time.Hour).Format(time.RFC3339)
		err := b.PutObjectRetention(
			"lock-retention-bucket",
			"obj",
			obj.VersionId,
			&ObjectLockRetention{
				Mode:            RetentionModeGovernance,
				RetainUntilDate: shorter,
			},
			true,
		)
		if err != nil {
			t.Fatalf("expected success with bypass, got %v", err)
		}

		got, err := b.GetObjectRetention("lock-retention-bucket", "obj", obj.VersionId)
		if err != nil {
			t.Fatalf("GetObjectRetention failed: %v", err)
		}
		if got.Mode != RetentionModeGovernance || got.RetainUntilDate != shorter {
			t.Fatalf("unexpected retention after bypass update: %#v", got)
		}
	})
}

func TestPutObjectLegalHoldValidation(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("lock-legalhold-bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	obj, err := b.PutObject("lock-legalhold-bucket", "obj", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	err = b.PutObjectLegalHold("lock-legalhold-bucket", "obj", obj.VersionId, &ObjectLockLegalHold{
		Status: "INVALID",
	})
	if !errors.Is(err, ErrInvalidObjectLockConfig) {
		t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
	}
}

func TestGetObjectLegalHoldDefaultOff(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("bucket-legalhold-default"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	obj, err := b.PutObject("bucket-legalhold-default", "obj", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	lh, err := b.GetObjectLegalHold("bucket-legalhold-default", "obj", obj.VersionId)
	if err != nil {
		t.Fatalf("GetObjectLegalHold failed: %v", err)
	}
	if lh.Status != LegalHoldStatusOff {
		t.Fatalf("unexpected legal hold status: got %q, want %q", lh.Status, LegalHoldStatusOff)
	}
}

func TestGetObjectRetentionMissingConfiguration(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("bucket-retention-missing"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	obj, err := b.PutObject("bucket-retention-missing", "obj", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	_, err = b.GetObjectRetention("bucket-retention-missing", "obj", obj.VersionId)
	if !errors.Is(err, ErrNoSuchObjectLockConfig) {
		t.Fatalf("expected ErrNoSuchObjectLockConfig, got %v", err)
	}
}

func TestPutObjectRetentionVersionNotFound(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("bucket-retention-version"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	if _, err := b.PutObject("bucket-retention-version", "obj", []byte("data"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	err := b.PutObjectRetention(
		"bucket-retention-version",
		"obj",
		"missing-version",
		&ObjectLockRetention{
			Mode:            RetentionModeGovernance,
			RetainUntilDate: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		},
		false,
	)
	if !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
}
