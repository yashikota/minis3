package backend

import (
	"errors"
	"testing"
	"time"
)

func TestObjectLockRetentionModeValidation(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)

	t.Run("validateRetentionMode helper", func(t *testing.T) {
		cases := []struct {
			name    string
			mode    string
			wantErr bool
		}{
			{"empty allowed", "", false},
			{"governance allowed", RetentionModeGovernance, false},
			{"compliance allowed", RetentionModeCompliance, false},
			{"invalid FOO", "FOO", true},
			{"lowercase governance rejected", "governance", true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := validateRetentionMode(tc.mode)
				if tc.wantErr && !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("validateRetentionMode(%q) = %v, want ErrInvalidRequest", tc.mode, err)
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("validateRetentionMode(%q) = %v, want nil", tc.mode, err)
				}
			})
		}
	})

	setupLockBucket := func(t *testing.T, name string) *Backend {
		t.Helper()
		b := New()
		if err := b.CreateBucketWithObjectLock(name); err != nil {
			t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
		}
		if _, err := b.PutObject(name, "seed", []byte("data"), PutObjectOptions{}); err != nil {
			t.Fatalf("seed PutObject failed: %v", err)
		}
		return b
	}

	t.Run("PutObject", func(t *testing.T) {
		cases := []struct {
			name        string
			mode        string
			withDate    bool
			wantErr     bool
			wantSuccess bool
		}{
			{"invalid mode FOO", "FOO", true, true, false},
			{"mode without date", RetentionModeGovernance, false, true, false},
			{"governance with date", RetentionModeGovernance, true, false, true},
			{"compliance with date", RetentionModeCompliance, true, false, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := setupLockBucket(t, "lock-put")
				var date *time.Time
				if tc.withDate {
					d := future
					date = &d
				}
				obj, err := b.PutObject("lock-put", "k-"+tc.name, []byte("data"), PutObjectOptions{
					RetentionMode:   tc.mode,
					RetainUntilDate: date,
				})
				if tc.wantErr {
					if !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("PutObject mode=%q date=%v = %v, want ErrInvalidRequest", tc.mode, date, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("PutObject failed: %v", err)
				}
				if tc.wantSuccess && obj.RetentionMode != tc.mode {
					t.Fatalf("RetentionMode = %q, want %q", obj.RetentionMode, tc.mode)
				}
			})
		}
	})

	t.Run("CopyObject", func(t *testing.T) {
		cases := []struct {
			name     string
			mode     string
			withDate bool
			wantErr  bool
		}{
			{"invalid mode FOO", "FOO", true, true},
			{"mode without date", RetentionModeGovernance, false, true},
			{"governance with date", RetentionModeGovernance, true, false},
			{"compliance with date", RetentionModeCompliance, true, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := setupLockBucket(t, "lock-copy")
				var date *time.Time
				if tc.withDate {
					d := future
					date = &d
				}
				_, _, err := b.CopyObject("lock-copy", "seed", "", "lock-copy", "dst-"+tc.name, CopyObjectOptions{
					RetentionMode:   tc.mode,
					RetainUntilDate: date,
				})
				if tc.wantErr {
					if !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("CopyObject mode=%q = %v, want ErrInvalidRequest", tc.mode, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("CopyObject failed: %v", err)
				}
			})
		}
	})

	t.Run("CreateMultipartUpload", func(t *testing.T) {
		cases := []struct {
			name     string
			mode     string
			withDate bool
			wantErr  bool
		}{
			{"invalid mode FOO", "FOO", true, true},
			{"mode without date", RetentionModeGovernance, false, true},
			{"governance with date", RetentionModeGovernance, true, false},
			{"compliance with date", RetentionModeCompliance, true, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := New()
				if err := b.CreateBucketWithObjectLock("lock-mpu"); err != nil {
					t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
				}
				var date *time.Time
				if tc.withDate {
					d := future
					date = &d
				}
				_, err := b.CreateMultipartUpload("lock-mpu", "k-"+tc.name, CreateMultipartUploadOptions{
					RetentionMode:   tc.mode,
					RetainUntilDate: date,
				})
				if tc.wantErr {
					if !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("CreateMultipartUpload mode=%q = %v, want ErrInvalidRequest", tc.mode, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("CreateMultipartUpload failed: %v", err)
				}
			})
		}
	})

	t.Run("CompleteMultipartUpload", func(t *testing.T) {
		cases := []struct {
			name     string
			mode     string
			withDate bool
			wantErr  bool
		}{
			{"invalid mode FOO", "FOO", true, true},
			{"mode without date", RetentionModeGovernance, false, true},
			{"governance with date", RetentionModeGovernance, true, false},
			{"compliance with date", RetentionModeCompliance, true, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b := New()
				if err := b.CreateBucketWithObjectLock("lock-complete"); err != nil {
					t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
				}
				var date *time.Time
				if tc.withDate {
					d := future
					date = &d
				}
				upload, err := b.CreateMultipartUpload("lock-complete", "k-"+tc.name, CreateMultipartUploadOptions{})
				if err != nil {
					t.Fatalf("CreateMultipartUpload failed: %v", err)
				}
				// Inject retention directly to exercise Complete validation
				// (Create would reject invalid values, so bypass it here).
				upload.RetentionMode = tc.mode
				upload.RetainUntilDate = date
				// LegalHold empty keeps focus on retention validation.
				part, err := b.UploadPart("lock-complete", "k-"+tc.name, upload.UploadId, 1, []byte("x"))
				if err != nil {
					t.Fatalf("UploadPart failed: %v", err)
				}
				obj, err := b.CompleteMultipartUpload("lock-complete", "k-"+tc.name, upload.UploadId, []CompletePart{
					{PartNumber: 1, ETag: part.ETag},
				})
				if tc.wantErr {
					if !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("CompleteMultipartUpload mode=%q = %v, want ErrInvalidRequest", tc.mode, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("CompleteMultipartUpload failed: %v", err)
				}
				if obj.RetentionMode != tc.mode {
					t.Fatalf("RetentionMode = %q, want %q", obj.RetentionMode, tc.mode)
				}
			})
		}
	})
}
