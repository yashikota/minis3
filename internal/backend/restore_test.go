package backend

import (
	"errors"
	"testing"
	"time"
)

func TestRestoreObjectHappyPath(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// New restore returns 202
	result, err := b.RestoreObject("bucket", "key", "", 1)
	if err != nil {
		t.Fatalf("RestoreObject: %v", err)
	}
	if result.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", result.StatusCode)
	}

	// Already restored returns 200
	result, err = b.RestoreObject("bucket", "key", "", 5)
	if err != nil {
		t.Fatalf("RestoreObject second call: %v", err)
	}
	if result.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", result.StatusCode)
	}
}

func TestRestoreObjectDeepArchive(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{
		StorageClass: "DEEP_ARCHIVE",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	result, err := b.RestoreObject("bucket", "key", "", 3)
	if err != nil {
		t.Fatalf("RestoreObject: %v", err)
	}
	if result.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", result.StatusCode)
	}
}

func TestRestoreObjectNonGlacierFails(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	_, err = b.RestoreObject("bucket", "key", "", 1)
	if !errors.Is(err, ErrInvalidObjectState) {
		t.Fatalf("expected ErrInvalidObjectState, got %v", err)
	}
}

func TestRestoreObjectBucketNotFound(t *testing.T) {
	b := New()
	_, err := b.RestoreObject("no-bucket", "key", "", 1)
	if !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestRestoreObjectKeyNotFound(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.RestoreObject("bucket", "no-key", "", 1)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestRestoreObjectVersionNotFound(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	_, err = b.RestoreObject("bucket", "key", "bad-version", 1)
	if !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
}

func TestRestoreObjectDeleteMarker(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Create a delete marker
	_, err = b.DeleteObject("bucket", "key", false)
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	// Restore against delete marker should fail
	_, err = b.RestoreObject("bucket", "key", "", 1)
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestRestoreObjectPermanent(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	_, err := b.PutObject("bucket", "key", []byte("data"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Permanent restore (days=0)
	result, err := b.RestoreObject("bucket", "key", "", 0)
	if err != nil {
		t.Fatalf("RestoreObject: %v", err)
	}
	if result.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", result.StatusCode)
	}

	// Verify the object is restored
	obj, err := b.GetObject("bucket", "key")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if obj.RestoreOngoing {
		t.Fatal("expected RestoreOngoing=false")
	}
	if obj.RestoreExpiryDate == nil {
		t.Fatal("expected RestoreExpiryDate to be set")
	}
	// Permanent restore should have far-future expiry
	if !obj.RestoreExpiryDate.After(time.Now().AddDate(99, 0, 0)) {
		t.Fatal("expected far-future RestoreExpiryDate for permanent restore")
	}
}

func TestRestoreObjectWithVersionId(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock: %v", err)
	}

	obj, err := b.PutObject("bucket", "key", []byte("v1"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	vid := obj.VersionId

	// Put another version
	_, err = b.PutObject("bucket", "key", []byte("v2"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject v2: %v", err)
	}

	// Restore the first version
	result, err := b.RestoreObject("bucket", "key", vid, 2)
	if err != nil {
		t.Fatalf("RestoreObject: %v", err)
	}
	if result.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", result.StatusCode)
	}
}

func TestIsArchivedStorageClass(t *testing.T) {
	tests := []struct {
		sc   string
		want bool
	}{
		{"GLACIER", true},
		{"DEEP_ARCHIVE", true},
		{"STANDARD", false},
		{"", false},
		{"REDUCED_REDUNDANCY", false},
	}
	for _, tt := range tests {
		if got := IsArchivedStorageClass(tt.sc); got != tt.want {
			t.Errorf("IsArchivedStorageClass(%q) = %v, want %v", tt.sc, got, tt.want)
		}
	}
}
