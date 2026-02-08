package backend

import (
	"testing"
)

func TestRestoreObject(t *testing.T) {
	b := New()
	if err := b.CreateBucket("bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Put a GLACIER object
	_, err := b.PutObject("bucket", "glacier-obj", []byte("data"), PutObjectOptions{
		StorageClass: "GLACIER",
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// Put a STANDARD object
	_, err = b.PutObject("bucket", "standard-obj", []byte("data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("restore GLACIER object with days", func(t *testing.T) {
		err := b.RestoreObject("bucket", "glacier-obj", "", 7)
		if err != nil {
			t.Fatalf("RestoreObject failed: %v", err)
		}
		obj, err := b.GetObject("bucket", "glacier-obj")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if !obj.Restored {
			t.Fatal("expected Restored=true")
		}
		if obj.RestoreExpiryDate == nil {
			t.Fatal("expected non-nil RestoreExpiryDate for temporary restore")
		}
	})

	t.Run("restore GLACIER object permanent", func(t *testing.T) {
		err := b.RestoreObject("bucket", "glacier-obj", "", 0)
		if err != nil {
			t.Fatalf("RestoreObject failed: %v", err)
		}
		obj, err := b.GetObject("bucket", "glacier-obj")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if !obj.Restored {
			t.Fatal("expected Restored=true")
		}
		if obj.RestoreExpiryDate != nil {
			t.Fatal("expected nil RestoreExpiryDate for permanent restore")
		}
	})

	t.Run("restore non-archived object fails", func(t *testing.T) {
		err := b.RestoreObject("bucket", "standard-obj", "", 7)
		if err != ErrInvalidObjectState {
			t.Fatalf("expected ErrInvalidObjectState, got %v", err)
		}
	})

	t.Run("restore nonexistent bucket", func(t *testing.T) {
		err := b.RestoreObject("no-such-bucket", "key", "", 7)
		if err != ErrBucketNotFound {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("restore nonexistent object", func(t *testing.T) {
		err := b.RestoreObject("bucket", "no-such-key", "", 7)
		if err != ErrObjectNotFound {
			t.Fatalf("expected ErrObjectNotFound, got %v", err)
		}
	})

	t.Run("restore DEEP_ARCHIVE object", func(t *testing.T) {
		_, err := b.PutObject("bucket", "deep-obj", []byte("data"), PutObjectOptions{
			StorageClass: "DEEP_ARCHIVE",
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		err = b.RestoreObject("bucket", "deep-obj", "", 3)
		if err != nil {
			t.Fatalf("RestoreObject failed: %v", err)
		}
		obj, err := b.GetObject("bucket", "deep-obj")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if !obj.Restored {
			t.Fatal("expected Restored=true")
		}
	})
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
