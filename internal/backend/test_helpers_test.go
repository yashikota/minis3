package backend

import "testing"

// liveBucket returns the stored bucket itself, for tests that set up state
// the API cannot reach. GetBucket returns a copy.
func liveBucket(t *testing.T, b *Backend, name string) *Bucket {
	t.Helper()
	b.mu.RLock()
	defer b.mu.RUnlock()
	bucket, ok := b.buckets[name]
	if !ok {
		t.Fatalf("bucket %q missing", name)
	}
	return bucket
}

// liveObject returns the stored version of an object (the latest when
// versionId is empty). GetObjectVersion returns a copy.
func liveObject(t *testing.T, b *Backend, bucketName, key, versionId string) *Object {
	t.Helper()
	versions, ok := liveBucket(t, b, bucketName).Objects[key]
	if !ok || len(versions.Versions) == 0 {
		t.Fatalf("object %s/%s missing", bucketName, key)
	}
	if versionId == "" {
		return versions.Versions[0]
	}
	for _, v := range versions.Versions {
		if v.VersionId == versionId {
			return v
		}
	}
	t.Fatalf("object %s/%s version %s missing", bucketName, key, versionId)
	return nil
}

// liveUpload returns the stored multipart upload. GetUpload returns a copy.
func liveUpload(t *testing.T, b *Backend, uploadId string) *MultipartUpload {
	t.Helper()
	b.mu.RLock()
	defer b.mu.RUnlock()
	upload, ok := b.uploads[uploadId]
	if !ok {
		t.Fatalf("upload %s missing", uploadId)
	}
	return upload
}
