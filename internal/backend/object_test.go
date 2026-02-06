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

func TestDeleteObjectRespectsObjectLock(t *testing.T) {
	b := New()
	_ = b.CreateBucketWithObjectLock("lock-bucket")
	_ = b.SetBucketVersioning("lock-bucket", VersioningEnabled, MFADeleteDisabled)

	future := time.Now().Add(24 * time.Hour).UTC()
	past := time.Now().Add(-24 * time.Hour).UTC()

	t.Run("COMPLIANCE mode blocks deletion", func(t *testing.T) {
		obj, _ := b.PutObject("lock-bucket", "compliance-key", []byte("data"), PutObjectOptions{
			RetentionMode:   RetentionModeCompliance,
			RetainUntilDate: &future,
		})
		_, err := b.DeleteObjectVersion("lock-bucket", "compliance-key", obj.VersionId, false)
		if !errors.Is(err, ErrObjectLocked) {
			t.Errorf("expected ErrObjectLocked, got %v", err)
		}
		// bypass does not help with COMPLIANCE
		_, err = b.DeleteObjectVersion("lock-bucket", "compliance-key", obj.VersionId, true)
		if !errors.Is(err, ErrObjectLocked) {
			t.Errorf("expected ErrObjectLocked even with bypass for COMPLIANCE, got %v", err)
		}
	})

	t.Run("GOVERNANCE mode blocks without bypass", func(t *testing.T) {
		obj, _ := b.PutObject("lock-bucket", "gov-key", []byte("data"), PutObjectOptions{
			RetentionMode:   RetentionModeGovernance,
			RetainUntilDate: &future,
		})
		_, err := b.DeleteObjectVersion("lock-bucket", "gov-key", obj.VersionId, false)
		if !errors.Is(err, ErrObjectLocked) {
			t.Errorf("expected ErrObjectLocked, got %v", err)
		}
		// bypass allows deletion
		_, err = b.DeleteObjectVersion("lock-bucket", "gov-key", obj.VersionId, true)
		if err != nil {
			t.Errorf("expected success with bypass for GOVERNANCE, got %v", err)
		}
	})

	t.Run("LegalHold blocks deletion", func(t *testing.T) {
		obj, _ := b.PutObject("lock-bucket", "legal-key", []byte("data"), PutObjectOptions{
			LegalHoldStatus: LegalHoldStatusOn,
		})
		_, err := b.DeleteObjectVersion("lock-bucket", "legal-key", obj.VersionId, true)
		if !errors.Is(err, ErrObjectLocked) {
			t.Errorf("expected ErrObjectLocked for legal hold even with bypass, got %v", err)
		}
	})

	t.Run("expired retention allows deletion", func(t *testing.T) {
		obj, _ := b.PutObject("lock-bucket", "expired-key", []byte("data"), PutObjectOptions{
			RetentionMode:   RetentionModeCompliance,
			RetainUntilDate: &past,
		})
		_, err := b.DeleteObjectVersion("lock-bucket", "expired-key", obj.VersionId, false)
		if err != nil {
			t.Errorf("expected success for expired retention, got %v", err)
		}
	})

	t.Run("delete marker creation always succeeds", func(t *testing.T) {
		_, _ = b.PutObject("lock-bucket", "marker-key", []byte("data"), PutObjectOptions{
			RetentionMode:   RetentionModeCompliance,
			RetainUntilDate: &future,
			LegalHoldStatus: LegalHoldStatusOn,
		})
		// DeleteObject without versionId creates a delete marker, should succeed
		result, err := b.DeleteObject("lock-bucket", "marker-key", false)
		if err != nil {
			t.Errorf("expected delete marker creation to succeed, got %v", err)
		}
		if !result.IsDeleteMarker {
			t.Errorf("expected result to be a delete marker")
		}
	})
}

func TestDeleteObjectsRespectsObjectLock(t *testing.T) {
	b := New()
	_ = b.CreateBucketWithObjectLock("lock-bucket")
	_ = b.SetBucketVersioning("lock-bucket", VersioningEnabled, MFADeleteDisabled)

	future := time.Now().Add(24 * time.Hour).UTC()

	obj, _ := b.PutObject("lock-bucket", "locked-key", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeCompliance,
		RetainUntilDate: &future,
	})
	unlocked, _ := b.PutObject("lock-bucket", "unlocked-key", []byte("data"), PutObjectOptions{})

	results, err := b.DeleteObjects("lock-bucket", []ObjectIdentifier{
		{Key: "locked-key", VersionId: obj.VersionId},
		{Key: "unlocked-key", VersionId: unlocked.VersionId},
	}, false)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// locked-key should have an error
	if !errors.Is(results[0].Error, ErrObjectLocked) {
		t.Errorf("expected ErrObjectLocked for locked-key, got %v", results[0].Error)
	}
	// unlocked-key should succeed
	if results[1].Error != nil {
		t.Errorf("expected success for unlocked-key, got %v", results[1].Error)
	}
}

func TestCopyObjectCopiesObjectLock(t *testing.T) {
	b := New()
	_ = b.CreateBucketWithObjectLock("lock-bucket")
	_ = b.CreateBucket("normal-bucket")

	future := time.Now().Add(24 * time.Hour).UTC()

	// Source object with lock
	_, _ = b.PutObject("lock-bucket", "src-key", []byte("data"), PutObjectOptions{
		RetentionMode:   RetentionModeGovernance,
		RetainUntilDate: &future,
		LegalHoldStatus: LegalHoldStatusOn,
	})

	t.Run("copies lock fields to lock-enabled bucket", func(t *testing.T) {
		copied, _, err := b.CopyObject(
			"lock-bucket",
			"src-key",
			"",
			"lock-bucket",
			"dst-key",
			CopyObjectOptions{},
		)
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}
		if copied.RetentionMode != RetentionModeGovernance {
			t.Errorf(
				"expected RetentionMode %q, got %q",
				RetentionModeGovernance,
				copied.RetentionMode,
			)
		}
		if copied.LegalHoldStatus != LegalHoldStatusOn {
			t.Errorf(
				"expected LegalHoldStatus %q, got %q",
				LegalHoldStatusOn,
				copied.LegalHoldStatus,
			)
		}
		if copied.RetainUntilDate == nil {
			t.Error("expected RetainUntilDate to be set")
		}
	})

	t.Run("explicit override", func(t *testing.T) {
		newFuture := time.Now().Add(48 * time.Hour).UTC()
		copied, _, err := b.CopyObject(
			"lock-bucket",
			"src-key",
			"",
			"lock-bucket",
			"dst-override",
			CopyObjectOptions{
				RetentionMode:   RetentionModeCompliance,
				RetainUntilDate: &newFuture,
				LegalHoldStatus: LegalHoldStatusOff,
			},
		)
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}
		if copied.RetentionMode != RetentionModeCompliance {
			t.Errorf(
				"expected RetentionMode %q, got %q",
				RetentionModeCompliance,
				copied.RetentionMode,
			)
		}
		if copied.LegalHoldStatus != LegalHoldStatusOff {
			t.Errorf(
				"expected LegalHoldStatus %q, got %q",
				LegalHoldStatusOff,
				copied.LegalHoldStatus,
			)
		}
	})

	t.Run("lock override to non-lock bucket fails", func(t *testing.T) {
		_, _, err := b.CopyObject(
			"lock-bucket",
			"src-key",
			"",
			"normal-bucket",
			"dst-key",
			CopyObjectOptions{
				RetentionMode: RetentionModeGovernance,
			},
		)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("expected ErrInvalidRequest, got %v", err)
		}
	})

	t.Run("copy to non-lock bucket omits lock fields", func(t *testing.T) {
		copied, _, err := b.CopyObject(
			"lock-bucket",
			"src-key",
			"",
			"normal-bucket",
			"dst-key",
			CopyObjectOptions{},
		)
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}
		if copied.RetentionMode != "" {
			t.Errorf(
				"expected empty RetentionMode for non-lock bucket, got %q",
				copied.RetentionMode,
			)
		}
	})
}

func TestCompleteMultipartUploadAppliesAttributes(t *testing.T) {
	b := New()
	_ = b.CreateBucketWithObjectLock("mp-bucket")

	future := time.Now().Add(24 * time.Hour).UTC()
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	upload, err := b.CreateMultipartUpload("mp-bucket", "mp-key", CreateMultipartUploadOptions{
		ContentType:          "application/json",
		Tags:                 map[string]string{"Env": "Test"},
		CacheControl:         "max-age=3600",
		Expires:              &expires,
		ContentEncoding:      "gzip",
		ContentLanguage:      "en",
		ContentDisposition:   "attachment",
		RetentionMode:        RetentionModeGovernance,
		RetainUntilDate:      &future,
		LegalHoldStatus:      LegalHoldStatusOn,
		StorageClass:         "GLACIER",
		ServerSideEncryption: "AES256",
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}

	// Upload a part (>5MB not required for single part which is also last)
	data := make([]byte, 1024)
	part, err := b.UploadPart("mp-bucket", "mp-key", upload.UploadId, 1, data)
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	obj, err := b.CompleteMultipartUpload("mp-bucket", "mp-key", upload.UploadId, []CompletePart{
		{PartNumber: 1, ETag: part.ETag},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload failed: %v", err)
	}

	if obj.ContentType != "application/json" {
		t.Errorf("expected ContentType application/json, got %q", obj.ContentType)
	}
	if obj.CacheControl != "max-age=3600" {
		t.Errorf("expected CacheControl max-age=3600, got %q", obj.CacheControl)
	}
	if obj.ContentEncoding != "gzip" {
		t.Errorf("expected ContentEncoding gzip, got %q", obj.ContentEncoding)
	}
	if obj.ContentLanguage != "en" {
		t.Errorf("expected ContentLanguage en, got %q", obj.ContentLanguage)
	}
	if obj.ContentDisposition != "attachment" {
		t.Errorf("expected ContentDisposition attachment, got %q", obj.ContentDisposition)
	}
	if obj.StorageClass != "GLACIER" {
		t.Errorf("expected StorageClass GLACIER, got %q", obj.StorageClass)
	}
	if obj.ServerSideEncryption != "AES256" {
		t.Errorf("expected ServerSideEncryption AES256, got %q", obj.ServerSideEncryption)
	}
	if obj.RetentionMode != RetentionModeGovernance {
		t.Errorf("expected RetentionMode %q, got %q", RetentionModeGovernance, obj.RetentionMode)
	}
	if obj.LegalHoldStatus != LegalHoldStatusOn {
		t.Errorf("expected LegalHoldStatus %q, got %q", LegalHoldStatusOn, obj.LegalHoldStatus)
	}

	// Tags
	tags, _, err := b.GetObjectTagging("mp-bucket", "mp-key", "")
	if err != nil {
		t.Fatalf("GetObjectTagging failed: %v", err)
	}
	if tags["Env"] != "Test" {
		t.Errorf("expected tag Env=Test, got %v", tags)
	}
}

func TestStorageClass(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	t.Run("default STANDARD", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "default-key", []byte("data"), PutObjectOptions{})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.StorageClass != "STANDARD" {
			t.Errorf("expected StorageClass STANDARD, got %q", obj.StorageClass)
		}
	})

	t.Run("explicit storage class", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "glacier-key", []byte("data"), PutObjectOptions{
			StorageClass: "GLACIER",
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.StorageClass != "GLACIER" {
			t.Errorf("expected StorageClass GLACIER, got %q", obj.StorageClass)
		}
	})
}

func TestServerSideEncryptionFields(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	t.Run("AES256", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "sse-key", []byte("data"), PutObjectOptions{
			ServerSideEncryption: "AES256",
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.ServerSideEncryption != "AES256" {
			t.Errorf("expected SSE AES256, got %q", obj.ServerSideEncryption)
		}
	})

	t.Run("aws:kms with key", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "kms-key", []byte("data"), PutObjectOptions{
			ServerSideEncryption: "aws:kms",
			SSEKMSKeyId:          "arn:aws:kms:us-east-1:123456789:key/test-key-id",
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.ServerSideEncryption != "aws:kms" {
			t.Errorf("expected SSE aws:kms, got %q", obj.ServerSideEncryption)
		}
		if obj.SSEKMSKeyId != "arn:aws:kms:us-east-1:123456789:key/test-key-id" {
			t.Errorf("expected KMS key ID, got %q", obj.SSEKMSKeyId)
		}
	})
}

func TestContentTypeDefault(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	t.Run("default application/octet-stream when not specified", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "no-ct", []byte("data"), PutObjectOptions{})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.ContentType != "application/octet-stream" {
			t.Errorf("expected application/octet-stream, got %q", obj.ContentType)
		}
	})

	t.Run("explicit content-type is preserved", func(t *testing.T) {
		obj, err := b.PutObject("test-bucket", "with-ct", []byte("data"), PutObjectOptions{
			ContentType: "text/plain",
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if obj.ContentType != "text/plain" {
			t.Errorf("expected text/plain, got %q", obj.ContentType)
		}
	})

	t.Run("CopyObject REPLACE without content-type defaults", func(t *testing.T) {
		_, _ = b.PutObject("test-bucket", "src", []byte("data"), PutObjectOptions{
			ContentType: "image/png",
		})
		copied, _, err := b.CopyObject("test-bucket", "src", "", "test-bucket", "dst-replace", CopyObjectOptions{
			MetadataDirective: "REPLACE",
		})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}
		if copied.ContentType != "application/octet-stream" {
			t.Errorf("expected application/octet-stream, got %q", copied.ContentType)
		}
	})

	t.Run("CopyObject COPY preserves source content-type", func(t *testing.T) {
		_, _ = b.PutObject("test-bucket", "src2", []byte("data"), PutObjectOptions{
			ContentType: "image/png",
		})
		copied, _, err := b.CopyObject("test-bucket", "src2", "", "test-bucket", "dst-copy", CopyObjectOptions{
			MetadataDirective: "COPY",
		})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}
		if copied.ContentType != "image/png" {
			t.Errorf("expected image/png, got %q", copied.ContentType)
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
