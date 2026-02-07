package backend

import (
	"errors"
	"sort"
	"testing"
)

func TestMultipartUploadLifecycleHelpers(t *testing.T) {
	b := New()
	if err := b.CreateBucket("multipart-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload(
		"multipart-bucket",
		"path/key",
		CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}

	if got, ok := b.GetUpload(upload.UploadId); !ok || got == nil || got.Key != "path/key" {
		t.Fatalf("GetUpload returned unexpected result: ok=%v upload=%+v", ok, got)
	}

	if err := b.AbortMultipartUpload("multipart-bucket", "wrong-key", upload.UploadId); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("expected ErrNoSuchUpload for wrong key, got %v", err)
	}
	if err := b.AbortMultipartUpload("multipart-bucket", "path/key", upload.UploadId); err != nil {
		t.Fatalf("AbortMultipartUpload failed: %v", err)
	}
	if _, ok := b.GetUpload(upload.UploadId); ok {
		t.Fatal("upload should not exist after abort")
	}
	if err := b.AbortMultipartUpload("multipart-bucket", "path/key", upload.UploadId); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("expected ErrNoSuchUpload after abort, got %v", err)
	}
}

func TestListMultipartUploadsWithFiltersAndPagination(t *testing.T) {
	b := New()
	if err := b.CreateBucket("list-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.CreateBucket("other-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	_, _ = b.CreateMultipartUpload("list-bucket", "apple/one", CreateMultipartUploadOptions{})
	_, _ = b.CreateMultipartUpload("list-bucket", "banana/one", CreateMultipartUploadOptions{})
	_, _ = b.CreateMultipartUpload("list-bucket", "banana/two", CreateMultipartUploadOptions{})
	_, _ = b.CreateMultipartUpload("other-bucket", "banana/other", CreateMultipartUploadOptions{})

	res, err := b.ListMultipartUploads(
		"list-bucket",
		ListMultipartUploadsOptions{Prefix: "banana/"},
	)
	if err != nil {
		t.Fatalf("ListMultipartUploads failed: %v", err)
	}
	if len(res.Uploads) != 2 {
		t.Fatalf("expected 2 uploads with prefix banana/, got %d", len(res.Uploads))
	}
	for _, up := range res.Uploads {
		if up.Bucket != "list-bucket" {
			t.Fatalf("unexpected bucket in result: %q", up.Bucket)
		}
	}

	res, err = b.ListMultipartUploads("list-bucket", ListMultipartUploadsOptions{Delimiter: "/"})
	if err != nil {
		t.Fatalf("ListMultipartUploads with delimiter failed: %v", err)
	}
	sort.Strings(res.CommonPrefixes)
	if len(res.CommonPrefixes) != 2 || res.CommonPrefixes[0] != "apple/" ||
		res.CommonPrefixes[1] != "banana/" {
		t.Fatalf("unexpected common prefixes: %+v", res.CommonPrefixes)
	}

	page1, err := b.ListMultipartUploads("list-bucket", ListMultipartUploadsOptions{MaxUploads: 1})
	if err != nil {
		t.Fatalf("ListMultipartUploads page1 failed: %v", err)
	}
	if !page1.IsTruncated || len(page1.Uploads) != 1 || page1.NextKeyMarker == "" ||
		page1.NextUploadIdMarker == "" {
		t.Fatalf("unexpected page1 result: %+v", page1)
	}

	page2, err := b.ListMultipartUploads("list-bucket", ListMultipartUploadsOptions{
		KeyMarker:      page1.NextKeyMarker,
		UploadIdMarker: page1.NextUploadIdMarker,
		MaxUploads:     10,
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads page2 failed: %v", err)
	}
	if len(page2.Uploads) == 0 {
		t.Fatalf("expected remaining uploads in page2, got %+v", page2)
	}

	if _, err := b.ListMultipartUploads("missing", ListMultipartUploadsOptions{}); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestListPartsScenarios(t *testing.T) {
	b := New()
	if err := b.CreateBucket("parts-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload("parts-bucket", "obj", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}
	if _, err := b.UploadPart("parts-bucket", "obj", upload.UploadId, 1, []byte("part-1")); err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}
	if _, err := b.UploadPart("parts-bucket", "obj", upload.UploadId, 2, []byte("part-2")); err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}
	if _, err := b.UploadPart("parts-bucket", "obj", upload.UploadId, 3, []byte("part-3")); err != nil {
		t.Fatalf("UploadPart 3 failed: %v", err)
	}

	res, listedUpload, err := b.ListParts("parts-bucket", "obj", upload.UploadId, ListPartsOptions{
		PartNumberMarker: 1,
		MaxParts:         1,
	})
	if err != nil {
		t.Fatalf("ListParts failed: %v", err)
	}
	if listedUpload.UploadId != upload.UploadId {
		t.Fatalf("unexpected listed upload: %+v", listedUpload)
	}
	if !res.IsTruncated || res.NextPartNumberMarker != 2 || len(res.Parts) != 1 ||
		res.Parts[0].PartNumber != 2 {
		t.Fatalf("unexpected list parts result: %+v", res)
	}

	res, _, err = b.ListParts("parts-bucket", "obj", upload.UploadId, ListPartsOptions{
		PartNumberMarker: 2,
		MaxParts:         10,
	})
	if err != nil {
		t.Fatalf("ListParts second page failed: %v", err)
	}
	if res.IsTruncated || len(res.Parts) != 1 || res.Parts[0].PartNumber != 3 {
		t.Fatalf("unexpected second page result: %+v", res)
	}

	if _, _, err := b.ListParts("parts-bucket", "wrong-key", upload.UploadId, ListPartsOptions{}); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("expected ErrNoSuchUpload for wrong key, got %v", err)
	}
	if _, _, err := b.ListParts("parts-bucket", "obj", "missing-upload", ListPartsOptions{}); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("expected ErrNoSuchUpload for missing upload, got %v", err)
	}
}
