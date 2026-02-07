package backend

import (
	"errors"
	"reflect"
	"testing"
)

func TestBucketManagementAndListing(t *testing.T) {
	b := New()

	for _, name := range []string{"alpha-bucket", "beta-bucket", "gamma-bucket"} {
		if err := b.CreateBucket(name); err != nil {
			t.Fatalf("CreateBucket(%q) failed: %v", name, err)
		}
	}

	if err := b.CreateBucket("alpha-bucket"); !errors.Is(err, ErrBucketAlreadyOwnedByYou) {
		t.Fatalf("expected ErrBucketAlreadyOwnedByYou, got %v", err)
	}

	bucket, ok := b.GetBucket("beta-bucket")
	if !ok || bucket == nil || bucket.Name != "beta-bucket" {
		t.Fatalf("GetBucket returned unexpected result: ok=%v bucket=%+v", ok, bucket)
	}

	b.SetBucketOwner("beta-bucket", "owner-key-1")
	bucket, ok = b.GetBucket("beta-bucket")
	if !ok || bucket.OwnerAccessKey != "owner-key-1" {
		t.Fatalf("owner was not set: ok=%v owner=%q", ok, bucket.OwnerAccessKey)
	}

	if bucket, ok := b.GetBucket("missing"); ok || bucket != nil {
		t.Fatalf("expected missing bucket, got ok=%v bucket=%+v", ok, bucket)
	}

	listAll := b.ListBuckets()
	if len(listAll) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(listAll))
	}

	res := b.ListBucketsWithOptions(ListBucketsOptions{Prefix: "beta"})
	if len(res.Buckets) != 1 || res.Buckets[0].Name != "beta-bucket" {
		t.Fatalf("unexpected prefix filter result: %+v", res)
	}

	paged := b.ListBucketsWithOptions(ListBucketsOptions{MaxBuckets: 2})
	if !paged.IsTruncated || len(paged.Buckets) != 2 || paged.ContinuationToken == "" {
		t.Fatalf("unexpected paged result: %+v", paged)
	}

	nextPage := b.ListBucketsWithOptions(ListBucketsOptions{
		ContinuationToken: paged.ContinuationToken,
		MaxBuckets:        2,
	})
	if nextPage.IsTruncated || len(nextPage.Buckets) != 1 ||
		nextPage.Buckets[0].Name != "gamma-bucket" {
		t.Fatalf("unexpected next page result: %+v", nextPage)
	}

	if _, err := b.PutObject("gamma-bucket", "obj", []byte("data"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if err := b.DeleteBucket("gamma-bucket"); !errors.Is(err, ErrBucketNotEmpty) {
		t.Fatalf("expected ErrBucketNotEmpty, got %v", err)
	}

	if _, err := b.DeleteObject("gamma-bucket", "obj", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if err := b.DeleteBucket("gamma-bucket"); err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}

	if err := b.DeleteBucket("missing"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestBucketVersioningAndTypeHelpers(t *testing.T) {
	if got := VersioningEnabled.String(); got != "Enabled" {
		t.Fatalf("VersioningEnabled.String() = %q", got)
	}
	if got := VersioningSuspended.String(); got != "Suspended" {
		t.Fatalf("VersioningSuspended.String() = %q", got)
	}
	if got := VersioningUnset.String(); got != "" {
		t.Fatalf("VersioningUnset.String() = %q", got)
	}

	if got := ParseVersioningStatus("Enabled"); got != VersioningEnabled {
		t.Fatalf("ParseVersioningStatus(Enabled) = %v", got)
	}
	if got := ParseVersioningStatus("Suspended"); got != VersioningSuspended {
		t.Fatalf("ParseVersioningStatus(Suspended) = %v", got)
	}
	if got := ParseVersioningStatus("other"); got != VersioningUnset {
		t.Fatalf("ParseVersioningStatus(other) = %v", got)
	}
	if !VersioningEnabled.IsVersioningEnabled() || VersioningSuspended.IsVersioningEnabled() {
		t.Fatal("IsVersioningEnabled returned unexpected values")
	}

	if got := MFADeleteEnabled.String(); got != "Enabled" {
		t.Fatalf("MFADeleteEnabled.String() = %q", got)
	}
	if got := MFADeleteDisabled.String(); got != "Disabled" {
		t.Fatalf("MFADeleteDisabled.String() = %q", got)
	}
	if got := ParseMFADeleteStatus("Enabled"); got != MFADeleteEnabled {
		t.Fatalf("ParseMFADeleteStatus(Enabled) = %v", got)
	}
	if got := ParseMFADeleteStatus("Disabled"); got != MFADeleteDisabled {
		t.Fatalf("ParseMFADeleteStatus(Disabled) = %v", got)
	}

	b := New()
	if err := b.CreateBucket("versioning-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	status, mfa, err := b.GetBucketVersioning("versioning-bucket")
	if err != nil {
		t.Fatalf("GetBucketVersioning failed: %v", err)
	}
	if status != VersioningUnset || mfa != MFADeleteDisabled {
		t.Fatalf("unexpected default versioning: status=%v mfa=%v", status, mfa)
	}

	if err := b.SetBucketVersioning("versioning-bucket", VersioningEnabled, MFADeleteEnabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	status, mfa, err = b.GetBucketVersioning("versioning-bucket")
	if err != nil {
		t.Fatalf("GetBucketVersioning failed: %v", err)
	}
	if status != VersioningEnabled || mfa != MFADeleteEnabled {
		t.Fatalf("unexpected versioning: status=%v mfa=%v", status, mfa)
	}

	if err := b.SetBucketVersioning("missing", VersioningEnabled, MFADeleteDisabled); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if _, _, err := b.GetBucketVersioning("missing"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("locked-bucket"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}
	if err := b.SetBucketVersioning("locked-bucket", VersioningSuspended, MFADeleteDisabled); !errors.Is(
		err,
		ErrObjectLockNotEnabled,
	) {
		t.Fatalf("expected ErrObjectLockNotEnabled when suspending object-lock bucket, got %v", err)
	}
}

func TestACLAndPublicAccessHelpers(t *testing.T) {
	owner := DefaultOwner()
	if owner == nil || owner.ID == "" || owner.DisplayName == "" {
		t.Fatalf("unexpected default owner: %+v", owner)
	}

	defaultACL := NewDefaultACL()
	if defaultACL.Owner == nil || defaultACL.Owner.ID != owner.ID {
		t.Fatalf("unexpected default ACL owner: %+v", defaultACL.Owner)
	}
	if len(defaultACL.AccessControlList.Grants) != 1 {
		t.Fatalf(
			"expected one grant in default ACL, got %d",
			len(defaultACL.AccessControlList.Grants),
		)
	}
	if defaultACL.AccessControlList.Grants[0].Permission != PermissionFullControl {
		t.Fatalf(
			"unexpected default permission: %q",
			defaultACL.AccessControlList.Grants[0].Permission,
		)
	}

	if IsACLPublicRead(nil) || IsACLPublicWrite(nil) {
		t.Fatal("nil ACL must not be public")
	}

	if acl := CannedACLToPolicy(string(ACLPrivate)); IsACLPublicRead(acl) || IsACLPublicWrite(acl) {
		t.Fatal("private ACL must not be public")
	}
	if acl := CannedACLToPolicy(string(ACLPublicRead)); !IsACLPublicRead(acl) ||
		IsACLPublicWrite(acl) {
		t.Fatal("public-read ACL flags are incorrect")
	}
	if acl := CannedACLToPolicy(string(ACLPublicReadWrite)); !IsACLPublicRead(acl) ||
		!IsACLPublicWrite(acl) {
		t.Fatal("public-read-write ACL flags are incorrect")
	}

	b := New()
	if err := b.CreateBucket("acl-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	bucketACL, err := b.GetBucketACL("acl-bucket")
	if err != nil {
		t.Fatalf("GetBucketACL failed: %v", err)
	}
	if IsACLPublicRead(bucketACL) || IsACLPublicWrite(bucketACL) {
		t.Fatal("default bucket ACL should be private")
	}
	if b.IsBucketPubliclyReadable("missing") || b.IsBucketPubliclyWritable("missing") {
		t.Fatal("missing bucket must not be treated as public")
	}

	if err := b.PutBucketACL("acl-bucket", CannedACLToPolicy(string(ACLPublicReadWrite))); err != nil {
		t.Fatalf("PutBucketACL failed: %v", err)
	}
	if !b.IsBucketPubliclyReadable("acl-bucket") || !b.IsBucketPubliclyWritable("acl-bucket") {
		t.Fatal("bucket should be public-read-write")
	}
	if err := b.PutBucketACL("missing", NewDefaultACL()); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if _, err := b.PutObject("acl-bucket", "obj", []byte("data"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	objACL, err := b.GetObjectACL("acl-bucket", "obj", "")
	if err != nil {
		t.Fatalf("GetObjectACL failed: %v", err)
	}
	if IsACLPublicRead(objACL) {
		t.Fatal("default object ACL should be private")
	}

	if err := b.PutObjectACL("acl-bucket", "obj", "", CannedACLToPolicy(string(ACLPublicRead))); err != nil {
		t.Fatalf("PutObjectACL failed: %v", err)
	}
	if !b.IsObjectPubliclyReadable("acl-bucket", "obj", "") {
		t.Fatal("object should be publicly readable")
	}

	if err := b.SetBucketVersioning("acl-bucket", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	v1, err := b.PutObject("acl-bucket", "versioned", []byte("v1"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject v1 failed: %v", err)
	}
	v2, err := b.PutObject("acl-bucket", "versioned", []byte("v2"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject v2 failed: %v", err)
	}

	if err := b.PutObjectACL("acl-bucket", "versioned", v1.VersionId, CannedACLToPolicy(string(ACLPrivate))); err != nil {
		t.Fatalf("PutObjectACL v1 failed: %v", err)
	}
	if err := b.PutObjectACL("acl-bucket", "versioned", v2.VersionId, CannedACLToPolicy(string(ACLPublicRead))); err != nil {
		t.Fatalf("PutObjectACL v2 failed: %v", err)
	}

	latestACL, err := b.GetObjectACL("acl-bucket", "versioned", "")
	if err != nil {
		t.Fatalf("GetObjectACL latest failed: %v", err)
	}
	if !IsACLPublicRead(latestACL) {
		t.Fatal("latest version should be publicly readable")
	}

	v1ACL, err := b.GetObjectACL("acl-bucket", "versioned", v1.VersionId)
	if err != nil {
		t.Fatalf("GetObjectACL v1 failed: %v", err)
	}
	if IsACLPublicRead(v1ACL) {
		t.Fatal("v1 should remain private")
	}

	if _, err := b.GetObjectACL("acl-bucket", "missing", ""); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
	if _, err := b.GetObjectACL("missing", "obj", ""); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if _, err := b.GetObjectACL("acl-bucket", "versioned", "missing-version"); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
	if err := b.PutObjectACL("acl-bucket", "versioned", "missing-version", NewDefaultACL()); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	delRes, err := b.DeleteObject("acl-bucket", "versioned", false)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if _, err := b.GetObjectACL("acl-bucket", "versioned", delRes.VersionId); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound for delete marker ACL, got %v", err)
	}
	if err := b.PutObjectACL("acl-bucket", "versioned", delRes.VersionId, NewDefaultACL()); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound for delete marker ACL write, got %v", err)
	}
}

func TestBucketConfigurationCRUD(t *testing.T) {
	b := New()
	if err := b.CreateBucket("config-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	t.Run("lifecycle", func(t *testing.T) {
		cfg := &LifecycleConfiguration{
			Rules: []LifecycleRule{{ID: "rule-1", Status: LifecycleStatusEnabled}},
		}

		if _, err := b.GetBucketLifecycleConfiguration("config-bucket"); !errors.Is(
			err,
			ErrNoSuchLifecycleConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchLifecycleConfiguration, got %v", err)
		}
		if err := b.PutBucketLifecycleConfiguration("config-bucket", cfg); err != nil {
			t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
		}
		got, err := b.GetBucketLifecycleConfiguration("config-bucket")
		if err != nil {
			t.Fatalf("GetBucketLifecycleConfiguration failed: %v", err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("lifecycle config mismatch: got=%+v want=%+v", got, cfg)
		}
		if err := b.DeleteBucketLifecycleConfiguration("config-bucket"); err != nil {
			t.Fatalf("DeleteBucketLifecycleConfiguration failed: %v", err)
		}
		if _, err := b.GetBucketLifecycleConfiguration("config-bucket"); !errors.Is(
			err,
			ErrNoSuchLifecycleConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchLifecycleConfiguration after delete, got %v", err)
		}
		if err := b.PutBucketLifecycleConfiguration("missing", cfg); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if _, err := b.GetBucketLifecycleConfiguration("missing"); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if err := b.DeleteBucketLifecycleConfiguration("missing"); !errors.Is(
			err,
			ErrBucketNotFound,
		) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("encryption", func(t *testing.T) {
		cfg := &ServerSideEncryptionConfiguration{
			Rules: []ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &ServerSideEncryptionByDefault{
					SSEAlgorithm: SSEAlgorithmAES256,
				},
			}},
		}

		if _, err := b.GetBucketEncryption("config-bucket"); !errors.Is(
			err,
			ErrServerSideEncryptionConfigurationNotFound,
		) {
			t.Fatalf("expected ErrServerSideEncryptionConfigurationNotFound, got %v", err)
		}
		if err := b.PutBucketEncryption("config-bucket", cfg); err != nil {
			t.Fatalf("PutBucketEncryption failed: %v", err)
		}
		got, err := b.GetBucketEncryption("config-bucket")
		if err != nil {
			t.Fatalf("GetBucketEncryption failed: %v", err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("encryption config mismatch: got=%+v want=%+v", got, cfg)
		}
		if err := b.DeleteBucketEncryption("config-bucket"); err != nil {
			t.Fatalf("DeleteBucketEncryption failed: %v", err)
		}
		if _, err := b.GetBucketEncryption("config-bucket"); !errors.Is(
			err,
			ErrServerSideEncryptionConfigurationNotFound,
		) {
			t.Fatalf(
				"expected ErrServerSideEncryptionConfigurationNotFound after delete, got %v",
				err,
			)
		}
		if err := b.PutBucketEncryption("missing", cfg); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if _, err := b.GetBucketEncryption("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if err := b.DeleteBucketEncryption("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("cors", func(t *testing.T) {
		cfg := &CORSConfiguration{
			CORSRules: []CORSRule{{
				AllowedMethods: []string{"GET"},
				AllowedOrigins: []string{"*"},
			}},
		}

		if _, err := b.GetBucketCORS("config-bucket"); !errors.Is(err, ErrNoSuchCORSConfiguration) {
			t.Fatalf("expected ErrNoSuchCORSConfiguration, got %v", err)
		}
		if err := b.PutBucketCORS("config-bucket", cfg); err != nil {
			t.Fatalf("PutBucketCORS failed: %v", err)
		}
		got, err := b.GetBucketCORS("config-bucket")
		if err != nil {
			t.Fatalf("GetBucketCORS failed: %v", err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("cors config mismatch: got=%+v want=%+v", got, cfg)
		}
		if err := b.DeleteBucketCORS("config-bucket"); err != nil {
			t.Fatalf("DeleteBucketCORS failed: %v", err)
		}
		if _, err := b.GetBucketCORS("config-bucket"); !errors.Is(err, ErrNoSuchCORSConfiguration) {
			t.Fatalf("expected ErrNoSuchCORSConfiguration after delete, got %v", err)
		}
		if err := b.PutBucketCORS("missing", cfg); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if _, err := b.GetBucketCORS("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if err := b.DeleteBucketCORS("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("website", func(t *testing.T) {
		cfg := &WebsiteConfiguration{IndexDocument: &IndexDocument{Suffix: "index.html"}}

		if _, err := b.GetBucketWebsite("config-bucket"); !errors.Is(
			err,
			ErrNoSuchWebsiteConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchWebsiteConfiguration, got %v", err)
		}
		if err := b.PutBucketWebsite("config-bucket", cfg); err != nil {
			t.Fatalf("PutBucketWebsite failed: %v", err)
		}
		got, err := b.GetBucketWebsite("config-bucket")
		if err != nil {
			t.Fatalf("GetBucketWebsite failed: %v", err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("website config mismatch: got=%+v want=%+v", got, cfg)
		}
		if err := b.DeleteBucketWebsite("config-bucket"); err != nil {
			t.Fatalf("DeleteBucketWebsite failed: %v", err)
		}
		if _, err := b.GetBucketWebsite("config-bucket"); !errors.Is(
			err,
			ErrNoSuchWebsiteConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchWebsiteConfiguration after delete, got %v", err)
		}
		if err := b.PutBucketWebsite("missing", cfg); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if _, err := b.GetBucketWebsite("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if err := b.DeleteBucketWebsite("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("public access block", func(t *testing.T) {
		cfg := &PublicAccessBlockConfiguration{
			BlockPublicAcls:       true,
			IgnorePublicAcls:      true,
			BlockPublicPolicy:     true,
			RestrictPublicBuckets: true,
		}

		if _, err := b.GetPublicAccessBlock("config-bucket"); !errors.Is(
			err,
			ErrNoSuchPublicAccessBlockConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchPublicAccessBlockConfiguration, got %v", err)
		}
		if err := b.PutPublicAccessBlock("config-bucket", cfg); err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}
		got, err := b.GetPublicAccessBlock("config-bucket")
		if err != nil {
			t.Fatalf("GetPublicAccessBlock failed: %v", err)
		}
		if !reflect.DeepEqual(got, cfg) {
			t.Fatalf("public access block mismatch: got=%+v want=%+v", got, cfg)
		}
		if err := b.DeletePublicAccessBlock("config-bucket"); err != nil {
			t.Fatalf("DeletePublicAccessBlock failed: %v", err)
		}
		if _, err := b.GetPublicAccessBlock("config-bucket"); !errors.Is(
			err,
			ErrNoSuchPublicAccessBlockConfiguration,
		) {
			t.Fatalf("expected ErrNoSuchPublicAccessBlockConfiguration after delete, got %v", err)
		}
		if err := b.PutPublicAccessBlock("missing", cfg); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if _, err := b.GetPublicAccessBlock("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
		if err := b.DeletePublicAccessBlock("missing"); !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})
}

func TestGetObjectVersionLookup(t *testing.T) {
	b := New()
	if err := b.CreateBucket("obj-version-bucket"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	if _, err := b.GetObject("missing", "key"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if _, err := b.GetObject("obj-version-bucket", "missing"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	if err := b.SetBucketVersioning("obj-version-bucket", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	v1, err := b.PutObject("obj-version-bucket", "k", []byte("one"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject v1 failed: %v", err)
	}
	v2, err := b.PutObject("obj-version-bucket", "k", []byte("two"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject v2 failed: %v", err)
	}

	latest, err := b.GetObject("obj-version-bucket", "k")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if latest.VersionId != v2.VersionId {
		t.Fatalf("expected latest version %q, got %q", v2.VersionId, latest.VersionId)
	}

	gotV1, err := b.GetObjectVersion("obj-version-bucket", "k", v1.VersionId)
	if err != nil {
		t.Fatalf("GetObjectVersion failed: %v", err)
	}
	if gotV1.VersionId != v1.VersionId {
		t.Fatalf("expected v1 version %q, got %q", v1.VersionId, gotV1.VersionId)
	}

	if _, err := b.GetObjectVersion("obj-version-bucket", "k", "missing-version"); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
}
