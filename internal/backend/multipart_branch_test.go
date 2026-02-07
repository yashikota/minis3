package backend

import (
	"errors"
	"strings"
	"testing"
)

func TestMultipartCreateAndUploadPartBranches(t *testing.T) {
	b := New()

	if _, err := b.CreateMultipartUpload("missing", "key", CreateMultipartUploadOptions{}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("multipart-branch-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload("multipart-branch-bucket", "key", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}

	if _, err := b.UploadPart("multipart-branch-bucket", "key", "missing-upload", 1, []byte("x")); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("expected ErrNoSuchUpload, got %v", err)
	}
	if _, err := b.UploadPart("multipart-branch-bucket", "wrong-key", upload.UploadId, 1, []byte("x")); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("expected ErrNoSuchUpload for key mismatch, got %v", err)
	}
	if _, err := b.UploadPart("multipart-branch-bucket", "key", upload.UploadId, 0, []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for part number 0, got %v", err)
	}
	if _, err := b.UploadPart("multipart-branch-bucket", "key", upload.UploadId, 10001, []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for part number 10001, got %v", err)
	}
}

func TestCompleteMultipartUploadBranches(t *testing.T) {
	b := New()
	if err := b.CreateBucket("complete-branch-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload("complete-branch-bucket", "obj", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	p1, err := b.UploadPart("complete-branch-bucket", "obj", upload.UploadId, 1, make([]byte, 5*1024*1024))
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}
	if _, err := b.UploadPart(
		"complete-branch-bucket",
		"obj",
		upload.UploadId,
		2,
		make([]byte, 1024),
	); err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", "missing-upload", []CompletePart{}); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("expected ErrNoSuchUpload, got %v", err)
	}
	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "wrong", upload.UploadId, []CompletePart{}); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("expected ErrNoSuchUpload for key mismatch, got %v", err)
	}

	uploadBucketGone, err := b.CreateMultipartUpload("complete-branch-bucket", "obj-bucket-gone", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	delete(b.buckets, "complete-branch-bucket")
	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj-bucket-gone", uploadBucketGone.UploadId, []CompletePart{{PartNumber: 1}}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	// restore bucket for remaining checks
	if err := b.CreateBucket("complete-branch-bucket"); err != nil {
		t.Fatalf("CreateBucket restore failed: %v", err)
	}
	// recreate upload/parts after bucket restore
	upload, err = b.CreateMultipartUpload("complete-branch-bucket", "obj", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	p1, _ = b.UploadPart("complete-branch-bucket", "obj", upload.UploadId, 1, make([]byte, 5*1024*1024))
	_, _ = b.UploadPart("complete-branch-bucket", "obj", upload.UploadId, 2, make([]byte, 1024))

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", upload.UploadId, nil); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("expected ErrInvalidPart for empty parts, got %v", err)
	}

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", upload.UploadId, []CompletePart{
		{PartNumber: 1, ETag: p1.ETag},
		{PartNumber: 1, ETag: p1.ETag},
	}); !errors.Is(err, ErrInvalidPartOrder) {
		t.Fatalf("expected ErrInvalidPartOrder, got %v", err)
	}

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", upload.UploadId, []CompletePart{{PartNumber: 3, ETag: "\"missing\""}}); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("expected ErrInvalidPart for missing part, got %v", err)
	}

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", upload.UploadId, []CompletePart{{PartNumber: 1, ETag: "\"wrong\""}}); !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("expected ErrInvalidPart for ETag mismatch, got %v", err)
	}

	// first part too small when not last
	smallUpload, err := b.CreateMultipartUpload("complete-branch-bucket", "small", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload small failed: %v", err)
	}
	s1, _ := b.UploadPart("complete-branch-bucket", "small", smallUpload.UploadId, 1, []byte("small"))
	s2, _ := b.UploadPart("complete-branch-bucket", "small", smallUpload.UploadId, 2, []byte("last"))
	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "small", smallUpload.UploadId, []CompletePart{
		{PartNumber: 1, ETag: s1.ETag},
		{PartNumber: 2, ETag: s2.ETag},
	}); !errors.Is(err, ErrEntityTooSmall) {
		t.Fatalf("expected ErrEntityTooSmall, got %v", err)
	}

	invalidETagUpload, err := b.CreateMultipartUpload("complete-branch-bucket", "invalid-etag", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload invalid-etag failed: %v", err)
	}
	_, _ = b.UploadPart("complete-branch-bucket", "invalid-etag", invalidETagUpload.UploadId, 1, []byte("abc"))
	invalid := b.uploads[invalidETagUpload.UploadId]
	invalid.Parts[1].ETag = "\"not-hex\""
	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "invalid-etag", invalidETagUpload.UploadId, []CompletePart{{PartNumber: 1, ETag: "\"not-hex\""}}); err == nil || !strings.Contains(err.Error(), "invalid ETag format") {
		t.Fatalf("expected invalid ETag format error, got %v", err)
	}

	if _, err := b.CompleteMultipartUpload("complete-branch-bucket", "obj", upload.UploadId, []CompletePart{{PartNumber: 1, ETag: p1.ETag}}); err != nil {
		t.Fatalf("expected valid completion for single part, got %v", err)
	}
}

func TestCompleteMultipartUploadDefaultsAndLocks(t *testing.T) {
	b := New()
	if err := b.CreateBucket("complete-defaults"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	if err := b.PutBucketEncryption("complete-defaults", &ServerSideEncryptionConfiguration{
		Rules: []ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &ServerSideEncryptionByDefault{SSEAlgorithm: SSEAlgorithmAWSKMS, KMSMasterKeyID: "kms-default"},
		}},
	}); err != nil {
		t.Fatalf("PutBucketEncryption failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload("complete-defaults", "obj", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	part, _ := b.UploadPart("complete-defaults", "obj", upload.UploadId, 1, []byte("data"))
	obj, err := b.CompleteMultipartUpload("complete-defaults", "obj", upload.UploadId, []CompletePart{{PartNumber: 1, ETag: part.ETag}})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload failed: %v", err)
	}
	if obj.ContentType != "application/octet-stream" {
		t.Fatalf("expected default content type, got %q", obj.ContentType)
	}
	if obj.StorageClass != "STANDARD" {
		t.Fatalf("expected default storage class, got %q", obj.StorageClass)
	}
	if obj.ServerSideEncryption != SSEAlgorithmAWSKMS || obj.SSEKMSKeyId != "kms-default" {
		t.Fatalf("expected default bucket encryption applied, got sse=%q kms=%q", obj.ServerSideEncryption, obj.SSEKMSKeyId)
	}

	if err := b.SetBucketVersioning("complete-defaults", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	uploadV, _ := b.CreateMultipartUpload("complete-defaults", "obj-v", CreateMultipartUploadOptions{})
	partV, _ := b.UploadPart("complete-defaults", "obj-v", uploadV.UploadId, 1, []byte("v"))
	objV, err := b.CompleteMultipartUpload("complete-defaults", "obj-v", uploadV.UploadId, []CompletePart{{PartNumber: 1, ETag: partV.ETag}})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload versioned failed: %v", err)
	}
	if objV.VersionId == NullVersionId {
		t.Fatal("expected generated version id when versioning enabled")
	}

	// object lock fields on non-lock bucket should fail
	uploadLock, _ := b.CreateMultipartUpload("complete-defaults", "obj-lock", CreateMultipartUploadOptions{RetentionMode: RetentionModeGovernance})
	partLock, _ := b.UploadPart("complete-defaults", "obj-lock", uploadLock.UploadId, 1, []byte("x"))
	if _, err := b.CompleteMultipartUpload("complete-defaults", "obj-lock", uploadLock.UploadId, []CompletePart{{PartNumber: 1, ETag: partLock.ETag}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for lock fields on non-lock bucket, got %v", err)
	}
}

func TestMultipartListingAndCopyPartBranches(t *testing.T) {
	b := New()
	if err := b.CreateBucket("list-multipart-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.CreateBucket("src-copypart-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	u1, _ := b.CreateMultipartUpload("list-multipart-branches", "a/dir/file-1", CreateMultipartUploadOptions{})
	u2, _ := b.CreateMultipartUpload("list-multipart-branches", "a/dir/file-2", CreateMultipartUploadOptions{})
	u3, _ := b.CreateMultipartUpload("list-multipart-branches", "b/key", CreateMultipartUploadOptions{})
	_ = u3

	page, err := b.ListMultipartUploads("list-multipart-branches", ListMultipartUploadsOptions{
		KeyMarker:      "a/dir/file-1",
		UploadIdMarker: u1.UploadId,
		Prefix:         "a/",
		Delimiter:      "/",
		MaxUploads:     -1,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	if len(page.CommonPrefixes) == 0 {
		t.Fatalf("expected common prefixes with delimiter, got %+v", page)
	}

	// Branch where marker key matches but upload id is not greater and thus skipped.
	pageSkip, err := b.ListMultipartUploads("list-multipart-branches", ListMultipartUploadsOptions{
		KeyMarker:      "a/dir/file-1",
		UploadIdMarker: "zzzzzzzzzzzzzzzzzzzzzzzz",
		MaxUploads:     10,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	for _, up := range pageSkip.Uploads {
		if up.Key == "a/dir/file-1" {
			t.Fatalf(
				"expected marker-matching key uploads to be skipped by large upload-id marker, got %+v",
				pageSkip.Uploads,
			)
		}
	}

	partsRes, _, err := b.ListParts("list-multipart-branches", "a/dir/file-2", u2.UploadId, ListPartsOptions{MaxParts: 0})
	if err != nil {
		t.Fatalf("ListParts failed: %v", err)
	}
	if partsRes.IsTruncated {
		t.Fatalf("expected non-truncated list with default max parts, got %+v", partsRes)
	}

	// CopyPart branches
	if _, err := b.PutObject("src-copypart-branches", "src", []byte("0123456789"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	upload, _ := b.CreateMultipartUpload("list-multipart-branches", "dst", CreateMultipartUploadOptions{})
	if _, err := b.CopyPart(
		"src-copypart-branches",
		"src",
		NullVersionId,
		"list-multipart-branches",
		"dst",
		upload.UploadId,
		1,
		-1,
		-1,
	); err != nil {
		t.Fatalf("expected CopyPart success with explicit source version id, got %v", err)
	}

	if _, err := b.CopyPart("src-copypart-branches", "src", "", "list-multipart-branches", "wrong-dst", upload.UploadId, 1, -1, -1); !errors.Is(err, ErrNoSuchUpload) {
		t.Fatalf("expected ErrNoSuchUpload for dst mismatch, got %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "src", "missing-version", "list-multipart-branches", "dst", upload.UploadId, 1, -1, -1); !errors.Is(err, ErrSourceObjectNotFound) {
		t.Fatalf("expected ErrSourceObjectNotFound for missing src version, got %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "src", "", "list-multipart-branches", "dst", upload.UploadId, 1, 10, 10); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for rangeStart>=size, got %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "src", "", "list-multipart-branches", "dst", upload.UploadId, 1, 0, 10); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for rangeEnd>=size, got %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "src", "", "list-multipart-branches", "dst", upload.UploadId, 1, 5, 3); !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("expected ErrInvalidRange for start>end, got %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "src", "", "list-multipart-branches", "dst", upload.UploadId, 1, 3, -1); err != nil {
		t.Fatalf("expected open-ended copy part success, got %v", err)
	}

	// source latest non-delete marker nil branch
	if err := b.SetBucketVersioning("src-copypart-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if _, err := b.DeleteObject("src-copypart-branches", "only-delete-marker", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if _, err := b.CopyPart("src-copypart-branches", "only-delete-marker", "", "list-multipart-branches", "dst", upload.UploadId, 2, -1, -1); !errors.Is(err, ErrSourceObjectNotFound) {
		t.Fatalf("expected ErrSourceObjectNotFound for latest=nil source, got %v", err)
	}
}

func TestListMultipartUploadsSameKeyMarkersAndSort(t *testing.T) {
	b := New()
	if err := b.CreateBucket("multipart-sort-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	u1, _ := b.CreateMultipartUpload("multipart-sort-bucket", "same-key", CreateMultipartUploadOptions{})
	u2, _ := b.CreateMultipartUpload("multipart-sort-bucket", "same-key", CreateMultipartUploadOptions{})
	if u1.UploadId == u2.UploadId {
		t.Fatalf("expected distinct upload IDs, got %q", u1.UploadId)
	}
	smaller := u1.UploadId
	larger := u2.UploadId
	if smaller > larger {
		smaller, larger = larger, smaller
	}

	// Trigger line 353 path: same key and upload id greater than marker.
	res, err := b.ListMultipartUploads("multipart-sort-bucket", ListMultipartUploadsOptions{
		KeyMarker:      "same-key",
		UploadIdMarker: smaller,
		MaxUploads:     10,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	if len(res.Uploads) != 1 || res.Uploads[0].UploadId != larger {
		t.Fatalf("expected only larger upload ID after marker, got %+v", res.Uploads)
	}

	// Trigger line 358 path: same key marker without upload-id marker skips equal key.
	res, err = b.ListMultipartUploads("multipart-sort-bucket", ListMultipartUploadsOptions{
		KeyMarker:  "same-key",
		MaxUploads: 10,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	if len(res.Uploads) != 0 {
		t.Fatalf("expected no uploads after key marker without upload-id marker, got %+v", res.Uploads)
	}
}
