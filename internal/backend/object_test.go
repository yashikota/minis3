package backend

import (
	"errors"
	"testing"
	"time"
)

func TestObjectTagging(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")
	_, _ = b.PutObject("test-bucket", "test-key", []byte("test data"), PutObjectOptions{})

	t.Run("no tags initially", func(t *testing.T) {
		tags, versionId, err := b.GetObjectTagging("test-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if len(tags) != 0 {
			t.Errorf("expected empty tags, got %v", tags)
		}
		if versionId != NullVersionId {
			t.Errorf("expected null version id, got %q", versionId)
		}
	})

	t.Run("put and get tags", func(t *testing.T) {
		tags := map[string]string{"Project": "Test", "Environment": "Dev"}
		versionId, err := b.PutObjectTagging("test-bucket", "test-key", "", tags)
		if err != nil {
			t.Fatalf("PutObjectTagging failed: %v", err)
		}
		if versionId != NullVersionId {
			t.Errorf("expected null version id, got %q", versionId)
		}

		result, _, err := b.GetObjectTagging("test-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if result["Project"] != "Test" || result["Environment"] != "Dev" {
			t.Errorf("tags mismatch: %v", result)
		}
	})

	t.Run("update tags", func(t *testing.T) {
		newTags := map[string]string{"NewKey": "NewValue"}
		_, err := b.PutObjectTagging("test-bucket", "test-key", "", newTags)
		if err != nil {
			t.Fatalf("PutObjectTagging failed: %v", err)
		}

		result, _, err := b.GetObjectTagging("test-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if len(result) != 1 || result["NewKey"] != "NewValue" {
			t.Errorf("tags should be replaced: %v", result)
		}
	})

	t.Run("delete tags", func(t *testing.T) {
		_, err := b.DeleteObjectTagging("test-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("DeleteObjectTagging failed: %v", err)
		}

		result, _, err := b.GetObjectTagging("test-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if len(result) != 0 {
			t.Errorf("expected empty tags after delete, got %v", result)
		}
	})

	t.Run("non-existent bucket", func(t *testing.T) {
		_, _, err := b.GetObjectTagging("non-existent", "test-key", "")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Errorf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("non-existent object", func(t *testing.T) {
		_, _, err := b.GetObjectTagging("test-bucket", "non-existent", "")
		if !errors.Is(err, ErrObjectNotFound) {
			t.Errorf("expected ErrObjectNotFound, got %v", err)
		}
	})
}

func TestObjectTaggingWithVersioning(t *testing.T) {
	b := New()
	_ = b.CreateBucket("versioned-bucket")
	_ = b.SetBucketVersioning("versioned-bucket", VersioningEnabled, MFADeleteDisabled)

	// Create first version
	obj1, _ := b.PutObject("versioned-bucket", "test-key", []byte("version 1"), PutObjectOptions{})
	// Create second version
	obj2, _ := b.PutObject("versioned-bucket", "test-key", []byte("version 2"), PutObjectOptions{})

	t.Run("set tags on specific version", func(t *testing.T) {
		tags := map[string]string{"Version": "1"}
		_, err := b.PutObjectTagging("versioned-bucket", "test-key", obj1.VersionId, tags)
		if err != nil {
			t.Fatalf("PutObjectTagging failed: %v", err)
		}

		// Get tags for version 1
		result, versionId, err := b.GetObjectTagging("versioned-bucket", "test-key", obj1.VersionId)
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if versionId != obj1.VersionId {
			t.Errorf("expected version %q, got %q", obj1.VersionId, versionId)
		}
		if result["Version"] != "1" {
			t.Errorf("expected Version=1, got %v", result)
		}

		// Version 2 should have no tags
		result2, _, err := b.GetObjectTagging("versioned-bucket", "test-key", obj2.VersionId)
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if len(result2) != 0 {
			t.Errorf("expected empty tags for version 2, got %v", result2)
		}
	})

	t.Run("get tags for latest version", func(t *testing.T) {
		tags := map[string]string{"Latest": "true"}
		_, _ = b.PutObjectTagging("versioned-bucket", "test-key", obj2.VersionId, tags)

		// Get without version ID should return latest
		result, versionId, err := b.GetObjectTagging("versioned-bucket", "test-key", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if versionId != obj2.VersionId {
			t.Errorf("expected latest version %q, got %q", obj2.VersionId, versionId)
		}
		if result["Latest"] != "true" {
			t.Errorf("expected Latest=true, got %v", result)
		}
	})

	t.Run("non-existent version", func(t *testing.T) {
		_, _, err := b.GetObjectTagging("versioned-bucket", "test-key", "non-existent-version")
		if !errors.Is(err, ErrVersionNotFound) {
			t.Errorf("expected ErrVersionNotFound, got %v", err)
		}
	})
}

func TestCopyPart(t *testing.T) {
	b := New()
	_ = b.CreateBucket("src-bucket")
	_ = b.CreateBucket("dst-bucket")

	// Create source object with 10MB of data
	srcData := make([]byte, 10*1024*1024)
	for i := range srcData {
		srcData[i] = byte(i % 256)
	}
	_, _ = b.PutObject("src-bucket", "src-key", srcData, PutObjectOptions{})

	// Start multipart upload
	upload, _ := b.CreateMultipartUpload("dst-bucket", "dst-key", CreateMultipartUploadOptions{})

	t.Run("copy full object as part", func(t *testing.T) {
		part, err := b.CopyPart(
			"src-bucket",
			"src-key",
			"dst-bucket",
			"dst-key",
			upload.UploadId,
			1,
			-1,
			-1,
		)
		if err != nil {
			t.Fatalf("CopyPart failed: %v", err)
		}
		if part.Size != int64(len(srcData)) {
			t.Errorf("expected size %d, got %d", len(srcData), part.Size)
		}
		if part.PartNumber != 1 {
			t.Errorf("expected part number 1, got %d", part.PartNumber)
		}
	})

	t.Run("copy with byte range", func(t *testing.T) {
		part, err := b.CopyPart(
			"src-bucket",
			"src-key",
			"dst-bucket",
			"dst-key",
			upload.UploadId,
			2,
			0,
			5*1024*1024-1,
		)
		if err != nil {
			t.Fatalf("CopyPart failed: %v", err)
		}
		if part.Size != 5*1024*1024 {
			t.Errorf("expected size %d, got %d", 5*1024*1024, part.Size)
		}
	})

	t.Run("non-existent source bucket", func(t *testing.T) {
		_, err := b.CopyPart(
			"non-existent",
			"src-key",
			"dst-bucket",
			"dst-key",
			upload.UploadId,
			3,
			-1,
			-1,
		)
		if !errors.Is(err, ErrSourceBucketNotFound) {
			t.Errorf("expected ErrSourceBucketNotFound, got %v", err)
		}
	})

	t.Run("non-existent source object", func(t *testing.T) {
		_, err := b.CopyPart(
			"src-bucket",
			"non-existent",
			"dst-bucket",
			"dst-key",
			upload.UploadId,
			3,
			-1,
			-1,
		)
		if !errors.Is(err, ErrSourceObjectNotFound) {
			t.Errorf("expected ErrSourceObjectNotFound, got %v", err)
		}
	})

	t.Run("non-existent upload", func(t *testing.T) {
		_, err := b.CopyPart(
			"src-bucket",
			"src-key",
			"dst-bucket",
			"dst-key",
			"non-existent-upload",
			3,
			-1,
			-1,
		)
		if !errors.Is(err, ErrNoSuchUpload) {
			t.Errorf("expected ErrNoSuchUpload, got %v", err)
		}
	})
}

func TestPutObjectWithTags(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	tags := map[string]string{"Project": "Test", "Environment": "Dev"}
	_, err := b.PutObject("test-bucket", "test-key", []byte("data"), PutObjectOptions{
		Tags: tags,
	})
	if err != nil {
		t.Fatalf("PutObject with tags failed: %v", err)
	}

	result, _, err := b.GetObjectTagging("test-bucket", "test-key", "")
	if err != nil {
		t.Fatalf("GetObjectTagging failed: %v", err)
	}

	if result["Project"] != "Test" || result["Environment"] != "Dev" {
		t.Errorf("tags mismatch: got %v", result)
	}
}

func TestPutObjectWithObjectLock(t *testing.T) {
	b := New()
	_ = b.CreateBucketWithObjectLock("lock-bucket")

	retainUntil := time.Now().Add(24 * time.Hour).UTC()
	obj, err := b.PutObject("lock-bucket", "locked-key", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeGovernance,
		RetainUntilDate: &retainUntil,
		LegalHoldStatus: LegalHoldStatusOn,
	})
	if err != nil {
		t.Fatalf("PutObject with object lock failed: %v", err)
	}

	if obj.RetentionMode != RetentionModeGovernance {
		t.Errorf("expected retention mode %q, got %q", RetentionModeGovernance, obj.RetentionMode)
	}
	if obj.RetainUntilDate == nil || !obj.RetainUntilDate.Equal(retainUntil) {
		t.Errorf("expected retain until date %v, got %v", retainUntil, obj.RetainUntilDate)
	}
	if obj.LegalHoldStatus != LegalHoldStatusOn {
		t.Errorf("expected legal hold %q, got %q", LegalHoldStatusOn, obj.LegalHoldStatus)
	}

	t.Run("fails without object lock enabled", func(t *testing.T) {
		_ = b.CreateBucket("normal-bucket")
		_, err := b.PutObject("normal-bucket", "key", []byte("data"), PutObjectOptions{
			RetentionMode: RetentionModeGovernance,
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("expected ErrInvalidRequest, got %v", err)
		}
	})
}

func TestCopyObjectWithTaggingDirective(t *testing.T) {
	b := New()
	_ = b.CreateBucket("bucket")

	// Create source object with tags
	_, _ = b.PutObject("bucket", "src", []byte("data"), PutObjectOptions{
		Tags: map[string]string{"Env": "Prod"},
	})

	t.Run("COPY directive copies tags", func(t *testing.T) {
		_, _, err := b.CopyObject("bucket", "src", "", "bucket", "dst-copy", CopyObjectOptions{
			TaggingDirective: "COPY",
		})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}

		tags, _, err := b.GetObjectTagging("bucket", "dst-copy", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if tags["Env"] != "Prod" {
			t.Errorf("expected tag Env=Prod, got %v", tags)
		}
	})

	t.Run("REPLACE directive uses new tags", func(t *testing.T) {
		_, _, err := b.CopyObject("bucket", "src", "", "bucket", "dst-replace", CopyObjectOptions{
			TaggingDirective: "REPLACE",
			Tags:             map[string]string{"NewTag": "NewVal"},
		})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}

		tags, _, err := b.GetObjectTagging("bucket", "dst-replace", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if tags["NewTag"] != "NewVal" {
			t.Errorf("expected tag NewTag=NewVal, got %v", tags)
		}
		if _, ok := tags["Env"]; ok {
			t.Errorf("expected Env tag to not be present, got %v", tags)
		}
	})

	t.Run("default copies tags", func(t *testing.T) {
		_, _, err := b.CopyObject("bucket", "src", "", "bucket", "dst-default", CopyObjectOptions{})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}

		tags, _, err := b.GetObjectTagging("bucket", "dst-default", "")
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if tags["Env"] != "Prod" {
			t.Errorf("expected tag Env=Prod (default COPY), got %v", tags)
		}
	})
}
