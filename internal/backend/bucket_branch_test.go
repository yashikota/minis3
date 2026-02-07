package backend

import (
	"errors"
	"testing"
)

func TestBucketBranchCoverage(t *testing.T) {
	t.Run("create bucket validates name", func(t *testing.T) {
		b := New()
		if err := b.CreateBucket("Invalid_Name"); !errors.Is(err, ErrInvalidBucketName) {
			t.Fatalf("expected ErrInvalidBucketName, got %v", err)
		}
	})

	t.Run("bucket tagging and policy not found branches", func(t *testing.T) {
		b := New()
		if err := b.PutBucketTagging("missing", map[string]string{"k": "v"}); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound from PutBucketTagging, got %v", err)
		}
		if err := b.DeleteBucketTagging("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound from DeleteBucketTagging, got %v", err)
		}
		if err := b.PutBucketPolicy("missing", `{"Version":"2012-10-17","Statement":[]}`); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound from PutBucketPolicy, got %v", err)
		}
		if err := b.DeleteBucketPolicy("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound from DeleteBucketPolicy, got %v", err)
		}
	})

	t.Run("object ACL missing bucket and object branches", func(t *testing.T) {
		b := New()
		if err := b.PutObjectACL("missing", "key", "", NewDefaultACL()); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound from PutObjectACL, got %v", err)
		}

		if err := b.CreateBucket("acl-branch"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := b.PutObjectACL("acl-branch", "missing", "", NewDefaultACL()); !errors.Is(
			err,
			ErrObjectNotFound,
		) {
			t.Fatalf("expected ErrObjectNotFound from PutObjectACL, got %v", err)
		}
	})

	t.Run("usage skips keys whose latest is delete marker", func(t *testing.T) {
		b := New()
		if err := b.CreateBucket("usage-nil-latest"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := b.SetBucketVersioning("usage-nil-latest", VersioningEnabled, MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if _, err := b.PutObject("usage-nil-latest", "key", []byte("data"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if _, err := b.DeleteObject("usage-nil-latest", "key", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		count, bytesUsed, err := b.GetBucketUsage("usage-nil-latest")
		if err != nil {
			t.Fatalf("GetBucketUsage failed: %v", err)
		}
		if count != 1 || bytesUsed != 4 {
			t.Fatalf(
				"unexpected usage for key with older live version: count=%d bytes=%d",
				count,
				bytesUsed,
			)
		}

		if err := b.SetBucketVersioning("usage-nil-latest", VersioningSuspended, MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if _, err := b.DeleteObject("usage-nil-latest", "only-marker", false); err != nil {
			t.Fatalf("DeleteObject only-marker failed: %v", err)
		}
		count, bytesUsed, err = b.GetBucketUsage("usage-nil-latest")
		if err != nil {
			t.Fatalf("GetBucketUsage failed: %v", err)
		}
		if count != 1 || bytesUsed != 4 {
			t.Fatalf(
				"expected only live key to be counted, got count=%d bytes=%d",
				count,
				bytesUsed,
			)
		}
	})

	t.Run("canned acl extra branches", func(t *testing.T) {
		auth := CannedACLToPolicy(string(ACLAuthenticatedRead))
		if IsACLPublicRead(auth) || IsACLPublicWrite(auth) {
			t.Fatalf("authenticated-read should not be public all-users ACL: %+v", auth)
		}

		unknown := CannedACLToPolicy("unknown")
		if unknown == nil || len(unknown.AccessControlList.Grants) == 0 {
			t.Fatalf("unknown canned ACL should still return owner-only ACL: %+v", unknown)
		}
	})

	t.Run("is object publicly readable handles errors", func(t *testing.T) {
		b := New()
		if b.IsObjectPubliclyReadable("missing", "key", "") {
			t.Fatal("missing bucket must not be publicly readable")
		}
		if err := b.CreateBucket("public-read-branch"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if b.IsObjectPubliclyReadable("public-read-branch", "missing", "") {
			t.Fatal("missing object must not be publicly readable")
		}
	})
}
