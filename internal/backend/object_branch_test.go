package backend

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestObjectVersionHelpersBranches(t *testing.T) {
	t.Run("getLatestVersion returns nil when only delete markers", func(t *testing.T) {
		ov := &ObjectVersions{Versions: []*Object{{IsDeleteMarker: true}, {IsDeleteMarker: true}}}
		if got := ov.getLatestVersion(); got != nil {
			t.Fatalf("expected nil latest version, got %+v", got)
		}
	})

	t.Run(
		"addVersionToObject removes old null versions in non-versioned buckets",
		func(t *testing.T) {
			bucket := &Bucket{
				VersioningStatus: VersioningUnset,
				Objects:          map[string]*ObjectVersions{},
			}
			bucket.Objects["k"] = &ObjectVersions{Versions: []*Object{
				{VersionId: "v1", IsLatest: true},
				{VersionId: NullVersionId, IsLatest: true},
				{VersionId: NullVersionId, IsLatest: true},
			}}
			addVersionToObject(bucket, "k", &Object{VersionId: NullVersionId, IsLatest: true})

			versions := bucket.Objects["k"].Versions
			if len(versions) != 2 {
				t.Fatalf("expected null versions to be compacted, got %d", len(versions))
			}
			if versions[0].VersionId != NullVersionId || versions[1].VersionId != "v1" {
				t.Fatalf("unexpected version order after compacting null versions: %+v", versions)
			}
		},
	)

	t.Run("createDeleteMarkerUnlocked branches", func(t *testing.T) {
		bucketEnabled := &Bucket{
			VersioningStatus: VersioningEnabled,
			Objects:          map[string]*ObjectVersions{},
		}
		res := createDeleteMarkerUnlocked(bucketEnabled, "k")
		if !res.IsDeleteMarker || res.VersionId == "" || res.VersionId == NullVersionId {
			t.Fatalf("expected generated delete marker version for enabled bucket, got %+v", res)
		}

		bucketSuspended := &Bucket{
			VersioningStatus: VersioningSuspended,
			Objects:          map[string]*ObjectVersions{},
		}
		bucketSuspended.Objects["k"] = &ObjectVersions{Versions: []*Object{
			{VersionId: NullVersionId, IsLatest: true},
			{VersionId: "v1", IsLatest: true},
		}}
		res = createDeleteMarkerUnlocked(bucketSuspended, "k")
		if res.VersionId != NullVersionId || !res.IsDeleteMarker {
			t.Fatalf("expected null delete marker for suspended bucket, got %+v", res)
		}
		if res.DeletedObject == nil {
			t.Fatalf("expected deleted object result to be set, got %+v", res)
		}

		bucketUnset := &Bucket{
			VersioningStatus: VersioningUnset,
			Objects: map[string]*ObjectVersions{
				"k": {Versions: []*Object{{VersionId: NullVersionId}}},
			},
		}
		res = createDeleteMarkerUnlocked(bucketUnset, "k")
		if !reflect.DeepEqual(res, &DeleteObjectVersionResult{}) {
			t.Fatalf("expected empty result for versioning unset delete, got %+v", res)
		}
		if _, ok := bucketUnset.Objects["k"]; ok {
			t.Fatal("expected object to be physically removed for versioning unset")
		}
	})
}

func TestPutObjectBranches(t *testing.T) {
	b := New()
	if _, err := b.PutObject("missing", "k", []byte("x"), PutObjectOptions{}); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("put-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.PutBucketEncryption("put-branches", &ServerSideEncryptionConfiguration{
		Rules: []ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &ServerSideEncryptionByDefault{SSEAlgorithm: SSEAlgorithmAWSKMS, KMSMasterKeyID: "kms-default"},
		}},
	}); err != nil {
		t.Fatalf("PutBucketEncryption failed: %v", err)
	}

	obj, err := b.PutObject("put-branches", "k1", []byte("hello"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if obj.ServerSideEncryption != SSEAlgorithmAWSKMS || obj.SSEKMSKeyId != "kms-default" {
		t.Fatalf(
			"expected bucket default encryption, got sse=%q kms=%q",
			obj.ServerSideEncryption,
			obj.SSEKMSKeyId,
		)
	}

	obj, err = b.PutObject("put-branches", "k2", []byte("hello"), PutObjectOptions{
		SSECustomerAlgorithm: "AES256",
		SSECustomerKeyMD5:    "md5",
	})
	if err != nil {
		t.Fatalf("PutObject SSE-C failed: %v", err)
	}
	if obj.ServerSideEncryption != "" || obj.SSECustomerAlgorithm != "AES256" {
		t.Fatalf("expected SSE-C only without default SSE-S3/KMS, got %+v", obj)
	}

	obj, err = b.PutObject(
		"put-branches",
		"k3",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "CRC32C"},
	)
	if err != nil || obj.ChecksumCRC32C == "" {
		t.Fatalf("expected computed CRC32C checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject("put-branches", "k3b", []byte("hello"), PutObjectOptions{
		ChecksumAlgorithm: "CRC32C",
		ChecksumCRC32C:    "provided-crc32c",
	})
	if err != nil || obj.ChecksumCRC32C != "provided-crc32c" {
		t.Fatalf("expected provided CRC32C checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject(
		"put-branches",
		"k4",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "SHA1", ChecksumSHA1: "provided-sha1"},
	)
	if err != nil || obj.ChecksumSHA1 != "provided-sha1" {
		t.Fatalf("expected provided SHA1 checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject(
		"put-branches",
		"k4b",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "SHA1"},
	)
	if err != nil || obj.ChecksumSHA1 == "" {
		t.Fatalf("expected computed SHA1 checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject(
		"put-branches",
		"k5",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "SHA256"},
	)
	if err != nil || obj.ChecksumSHA256 == "" {
		t.Fatalf("expected computed SHA256 checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject("put-branches", "k5b", []byte("hello"), PutObjectOptions{
		ChecksumAlgorithm: "SHA256",
		ChecksumSHA256:    "provided-sha256",
	})
	if err != nil || obj.ChecksumSHA256 != "provided-sha256" {
		t.Fatalf("expected provided SHA256 checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject(
		"put-branches",
		"k6",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "CRC32", ChecksumCRC32: "provided-crc32"},
	)
	if err != nil || obj.ChecksumCRC32 != "provided-crc32" {
		t.Fatalf("expected provided CRC32 checksum, err=%v obj=%+v", err, obj)
	}
	obj, err = b.PutObject(
		"put-branches",
		"k6b",
		[]byte("hello"),
		PutObjectOptions{ChecksumAlgorithm: "CRC32"},
	)
	if err != nil || obj.ChecksumCRC32 == "" {
		t.Fatalf("expected computed CRC32 checksum, err=%v obj=%+v", err, obj)
	}

	if _, err := b.PutObject("put-branches", "k-lock", []byte("x"), PutObjectOptions{RetentionMode: RetentionModeGovernance}); !errors.Is(
		err,
		ErrInvalidRequest,
	) {
		t.Fatalf(
			"expected ErrInvalidRequest on lock fields without lock-enabled bucket, got %v",
			err,
		)
	}
}

func TestDeleteObjectVersionBranches(t *testing.T) {
	b := New()
	if _, err := b.DeleteObjectVersion("missing", "k", "", false); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("delete-version-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("delete-version-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if _, err := b.DeleteObjectVersion("delete-version-branches", "missing", "v", false); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	v1, _ := b.PutObject("delete-version-branches", "k", []byte("v1"), PutObjectOptions{})
	v2, _ := b.PutObject("delete-version-branches", "k", []byte("v2"), PutObjectOptions{})

	if _, err := b.DeleteObjectVersion("delete-version-branches", "k", "missing", false); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	res, err := b.DeleteObjectVersion("delete-version-branches", "k", v2.VersionId, false)
	if err != nil {
		t.Fatalf("DeleteObjectVersion failed: %v", err)
	}
	if res.VersionId != v2.VersionId || res.IsDeleteMarker {
		t.Fatalf("unexpected delete result: %+v", res)
	}
	latest, _ := b.GetObject("delete-version-branches", "k")
	if latest.VersionId != v1.VersionId || !latest.IsLatest {
		t.Fatalf("expected v1 to become latest after deleting v2, got %+v", latest)
	}

	// delete marker version removal path with empty cleanup
	dm, err := b.DeleteObject("delete-version-branches", "k", false)
	if err != nil {
		t.Fatalf("DeleteObject create marker failed: %v", err)
	}
	if _, err := b.DeleteObjectVersion("delete-version-branches", "k", dm.VersionId, false); err != nil {
		t.Fatalf("DeleteObjectVersion delete marker failed: %v", err)
	}
	if _, err := b.DeleteObjectVersion("delete-version-branches", "k", v1.VersionId, false); err != nil {
		t.Fatalf("DeleteObjectVersion v1 failed: %v", err)
	}
	if _, ok := b.GetBucket("delete-version-branches"); !ok {
		t.Fatal("bucket should still exist")
	}
	bucket, _ := b.GetBucket("delete-version-branches")
	if _, exists := bucket.Objects["k"]; exists {
		t.Fatalf("expected object key cleanup when all versions deleted: %+v", bucket.Objects["k"])
	}
}

func TestCopyObjectBranches(t *testing.T) {
	b := New()
	if err := b.CreateBucket("src-copy-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.CreateBucket("dst-copy-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	if _, _, err := b.CopyObject("missing", "k", "", "dst-copy-branches", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrSourceBucketNotFound,
	) {
		t.Fatalf("expected ErrSourceBucketNotFound, got %v", err)
	}
	if _, _, err := b.CopyObject("src-copy-branches", "missing", "", "dst-copy-branches", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrSourceObjectNotFound,
	) {
		t.Fatalf("expected ErrSourceObjectNotFound, got %v", err)
	}

	if err := b.SetBucketVersioning("src-copy-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	srcObj, _ := b.PutObject("src-copy-branches", "src", []byte("data"), PutObjectOptions{
		ContentType:             "text/plain",
		Metadata:                map[string]string{"m": "v"},
		CacheControl:            "no-cache",
		Expires:                 ptrTimeForObjectBranch(time.Now().UTC().Add(10 * time.Minute)),
		ContentEncoding:         "gzip",
		ContentLanguage:         "en",
		ContentDisposition:      "inline",
		Tags:                    map[string]string{"tag": "value"},
		StorageClass:            "STANDARD_IA",
		ServerSideEncryption:    "aws:kms",
		SSEKMSKeyId:             "src-kms",
		WebsiteRedirectLocation: "/redir",
		ChecksumAlgorithm:       "SHA256",
	})
	if _, _, err := b.CopyObject("src-copy-branches", "src", "missing-version", "dst-copy-branches", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	dmRes, _ := b.DeleteObject("src-copy-branches", "src", false)
	if _, _, err := b.CopyObject("src-copy-branches", "src", dmRes.VersionId, "dst-copy-branches", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrSourceObjectNotFound,
	) {
		t.Fatalf("expected ErrSourceObjectNotFound for delete marker version, got %v", err)
	}

	// source latest non-delete-marker nil
	if _, err := b.DeleteObject("src-copy-branches", "only-marker", false); err != nil {
		t.Fatalf("DeleteObject only-marker failed: %v", err)
	}
	if _, _, err := b.CopyObject("src-copy-branches", "only-marker", "", "dst-copy-branches", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrSourceObjectNotFound,
	) {
		t.Fatalf("expected ErrSourceObjectNotFound for latest=nil source, got %v", err)
	}

	if _, _, err := b.CopyObject("src-copy-branches", "src", srcObj.VersionId, "missing", "d", CopyObjectOptions{}); !errors.Is(
		err,
		ErrDestinationBucketNotFound,
	) {
		t.Fatalf("expected ErrDestinationBucketNotFound, got %v", err)
	}

	if err := b.SetBucketVersioning("dst-copy-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if err := b.PutBucketEncryption("dst-copy-branches", &ServerSideEncryptionConfiguration{
		Rules: []ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &ServerSideEncryptionByDefault{SSEAlgorithm: SSEAlgorithmAWSKMS, KMSMasterKeyID: "dst-kms"},
		}},
	}); err != nil {
		t.Fatalf("PutBucketEncryption failed: %v", err)
	}

	copied, actualVersion, err := b.CopyObject(
		"src-copy-branches",
		"src",
		srcObj.VersionId,
		"dst-copy-branches",
		"dst",
		CopyObjectOptions{
			ChecksumAlgorithm:       "CRC32C",
			MetadataDirective:       "REPLACE",
			Metadata:                map[string]string{"new": "meta"},
			ContentType:             "application/json",
			CacheControl:            "max-age=1",
			ContentEncoding:         "br",
			ContentLanguage:         "ja",
			ContentDisposition:      "attachment",
			TaggingDirective:        "REPLACE",
			Tags:                    map[string]string{"newtag": "newvalue"},
			WebsiteRedirectLocation: "/new-redir",
			StorageClass:            "GLACIER",
			ServerSideEncryption:    "AES256",
		},
	)
	if err != nil {
		t.Fatalf("CopyObject with replace options failed: %v", err)
	}
	if actualVersion != srcObj.VersionId {
		t.Fatalf("unexpected source version used: got %q want %q", actualVersion, srcObj.VersionId)
	}
	if copied.VersionId == NullVersionId {
		t.Fatal("expected generated destination version id in versioned destination bucket")
	}
	if copied.ChecksumCRC32C == "" {
		t.Fatal("expected recomputed CRC32C checksum")
	}
	if copied.ContentType != "application/json" || copied.Metadata["new"] != "meta" {
		t.Fatalf("expected REPLACE metadata/content-type, got %+v", copied)
	}
	if copied.Tags["newtag"] != "newvalue" {
		t.Fatalf("expected REPLACE tags, got %+v", copied.Tags)
	}
	if copied.WebsiteRedirectLocation != "/new-redir" {
		t.Fatalf("expected website redirect override, got %q", copied.WebsiteRedirectLocation)
	}
	if copied.StorageClass != "GLACIER" {
		t.Fatalf("expected storage class override, got %q", copied.StorageClass)
	}
	if copied.ServerSideEncryption != "AES256" {
		t.Fatalf("expected explicit SSE override, got %q", copied.ServerSideEncryption)
	}

	// COPY directive branches incl metadata/tags copy, website/storage/SSE copy and destination default encryption
	if err := b.SetBucketVersioning("dst-copy-branches", VersioningUnset, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	copiedDefault, _, err := b.CopyObject(
		"src-copy-branches",
		"src",
		srcObj.VersionId,
		"dst-copy-branches",
		"dst-default",
		CopyObjectOptions{},
	)
	if err != nil {
		t.Fatalf("CopyObject default COPY failed: %v", err)
	}
	if copiedDefault.Metadata["m"] != "v" || copiedDefault.Tags["tag"] != "value" {
		t.Fatalf(
			"expected metadata/tags copied from source, got metadata=%+v tags=%+v",
			copiedDefault.Metadata,
			copiedDefault.Tags,
		)
	}
	if copiedDefault.WebsiteRedirectLocation != "/redir" {
		t.Fatalf(
			"expected website redirect copied from source, got %q",
			copiedDefault.WebsiteRedirectLocation,
		)
	}
	if copiedDefault.StorageClass != "STANDARD_IA" {
		t.Fatalf("expected storage class copied from source, got %q", copiedDefault.StorageClass)
	}
	if copiedDefault.ServerSideEncryption != "aws:kms" || copiedDefault.SSEKMSKeyId != "src-kms" {
		t.Fatalf(
			"expected source SSE copied, got sse=%q kms=%q",
			copiedDefault.ServerSideEncryption,
			copiedDefault.SSEKMSKeyId,
		)
	}
	if copiedDefault.Expires == nil {
		t.Fatal("expected Expires to be copied from source")
	}

	// Destination default encryption should apply when copied object has no SSE
	srcNoSSE, _ := b.PutObject(
		"src-copy-branches",
		"src-no-sse",
		[]byte("data"),
		PutObjectOptions{},
	)
	srcNoSSE.StorageClass = ""
	copiedEncrypted, _, err := b.CopyObject(
		"src-copy-branches",
		"src-no-sse",
		srcNoSSE.VersionId,
		"dst-copy-branches",
		"dst-encrypted",
		CopyObjectOptions{},
	)
	if err != nil {
		t.Fatalf("CopyObject default encryption apply failed: %v", err)
	}
	if copiedEncrypted.ServerSideEncryption != SSEAlgorithmAWSKMS ||
		copiedEncrypted.SSEKMSKeyId != "dst-kms" {
		t.Fatalf(
			"expected destination default encryption, got sse=%q kms=%q",
			copiedEncrypted.ServerSideEncryption,
			copiedEncrypted.SSEKMSKeyId,
		)
	}
	if copiedEncrypted.StorageClass != "STANDARD" {
		t.Fatalf(
			"expected STANDARD storage class fallback when source and options are empty, got %q",
			copiedEncrypted.StorageClass,
		)
	}

	// Checksum override extra algorithms
	if objSHA1, _, err := b.CopyObject("src-copy-branches", "src", srcObj.VersionId, "dst-copy-branches", "dst-sha1", CopyObjectOptions{ChecksumAlgorithm: "SHA1"}); err != nil ||
		objSHA1.ChecksumSHA1 == "" {
		t.Fatalf("expected SHA1 recompute, err=%v obj=%+v", err, objSHA1)
	}
	if objSHA256, _, err := b.CopyObject("src-copy-branches", "src", srcObj.VersionId, "dst-copy-branches", "dst-sha256", CopyObjectOptions{ChecksumAlgorithm: "SHA256"}); err != nil ||
		objSHA256.ChecksumSHA256 == "" {
		t.Fatalf("expected SHA256 recompute, err=%v obj=%+v", err, objSHA256)
	}
}

func TestDeleteObjectsAndListObjectVersionsBranches(t *testing.T) {
	b := New()
	if _, err := b.DeleteObjects("missing", nil, false); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucketWithObjectLock("delete-objects-branches"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
	}

	future := time.Now().UTC().Add(24 * time.Hour)
	locked, _ := b.PutObject(
		"delete-objects-branches",
		"locked",
		[]byte("l"),
		PutObjectOptions{RetentionMode: RetentionModeGovernance, RetainUntilDate: &future},
	)
	unlockedV1, _ := b.PutObject(
		"delete-objects-branches",
		"unlocked",
		[]byte("u1"),
		PutObjectOptions{},
	)
	_, _ = b.PutObject("delete-objects-branches", "unlocked", []byte("u2"), PutObjectOptions{})

	results, err := b.DeleteObjects("delete-objects-branches", []ObjectIdentifier{
		{Key: "missing-key", VersionId: "missing-ver"},
		{Key: "unlocked", VersionId: "missing-ver"},
		{Key: "locked", VersionId: locked.VersionId},
		{Key: "unlocked", VersionId: unlockedV1.VersionId},
		{Key: "unlocked"},
	}, false)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
	if !errors.Is(results[2].Error, ErrObjectLocked) {
		t.Fatalf("expected object lock error for locked object, got %+v", results[2])
	}
	if !results[4].DeleteMarker || results[4].DeleteMarkerVersionId == "" {
		t.Fatalf("expected delete marker info for no-version delete, got %+v", results[4])
	}

	if _, err := b.ListObjectsV1("missing", "", "", "", 10); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound from ListObjectsV1, got %v", err)
	}
	if _, err := b.ListObjectsV2("missing", "", "", "", "", 10); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound from ListObjectsV2, got %v", err)
	}
	resV2Filtered, err := b.ListObjectsV2("delete-objects-branches", "zzz/", "", "", "", 10)
	if err != nil {
		t.Fatalf("ListObjectsV2 filtered failed: %v", err)
	}
	if len(resV2Filtered.Objects) != 0 {
		t.Fatalf("expected no objects for unmatched prefix, got %+v", resV2Filtered.Objects)
	}

	if err := b.CreateBucket("versions-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("versions-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	vA1, _ := b.PutObject("versions-branches", "a/obj", []byte("a1"), PutObjectOptions{})
	_, _ = b.PutObject("versions-branches", "a/obj", []byte("a2"), PutObjectOptions{})
	_, _ = b.DeleteObject("versions-branches", "a/obj", false)
	_, _ = b.PutObject("versions-branches", "b/obj", []byte("b1"), PutObjectOptions{})
	_, _ = b.PutObject("versions-branches", "c/sub/obj", []byte("c1"), PutObjectOptions{})

	if _, err := b.ListObjectVersions("missing", "", "", "", "", 10); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound from ListObjectVersions, got %v", err)
	}

	res, err := b.ListObjectVersions("versions-branches", "", "/", "", "", 10)
	if err != nil {
		t.Fatalf("ListObjectVersions with delimiter failed: %v", err)
	}
	if len(res.CommonPrefixes) == 0 {
		t.Fatalf("expected common prefixes with delimiter, got %+v", res)
	}

	res, err = b.ListObjectVersions("versions-branches", "a/", "", "", "", 2)
	if err != nil {
		t.Fatalf("ListObjectVersions page1 failed: %v", err)
	}
	if !res.IsTruncated || res.NextKeyMarker == "" || res.NextVersionIdMarker == "" {
		t.Fatalf("expected truncation markers, got %+v", res)
	}
	if len(res.DeleteMarkers) == 0 {
		t.Fatalf("expected delete markers in result, got %+v", res)
	}

	res2, err := b.ListObjectVersions(
		"versions-branches",
		"",
		"",
		res.NextKeyMarker,
		res.NextVersionIdMarker,
		10,
	)
	if err != nil {
		t.Fatalf("ListObjectVersions with markers failed: %v", err)
	}
	if len(res2.Versions)+len(res2.DeleteMarkers) == 0 {
		t.Fatalf("expected remaining versions after markers, got %+v", res2)
	}
	// Key-marker present without version-id-marker: skip all versions for the marker key.
	resSkip, err := b.ListObjectVersions("versions-branches", "", "", "a/obj", "", 10)
	if err != nil {
		t.Fatalf("ListObjectVersions skip-by-key-marker failed: %v", err)
	}
	for _, v := range resSkip.Versions {
		if v.Key == "a/obj" {
			t.Fatalf(
				"expected a/obj versions to be skipped when version-id-marker is empty, got %+v",
				resSkip,
			)
		}
	}
	// key > marker branch (line 1002)
	resFromNextKey, err := b.ListObjectVersions(
		"versions-branches",
		"",
		"",
		"a/obj",
		"non-existent",
		10,
	)
	if err != nil {
		t.Fatalf("ListObjectVersions with non-existent version-id marker failed: %v", err)
	}
	if len(resFromNextKey.Versions)+len(resFromNextKey.DeleteMarkers) == 0 {
		t.Fatalf("expected entries after next key marker, got %+v", resFromNextKey)
	}

	resAfter, err := b.ListObjectVersions("versions-branches", "", "", "zzzz", "", 10)
	if err != nil {
		t.Fatalf("ListObjectVersions after-all marker failed: %v", err)
	}
	if len(resAfter.Versions) != 0 || len(resAfter.DeleteMarkers) != 0 {
		t.Fatalf("expected empty result after all markers, got %+v", resAfter)
	}

	if _, err := b.GetObjectVersion("versions-branches", "a/obj", vA1.VersionId); err != nil {
		t.Fatalf("expected known version to exist: %v", err)
	}
}

func TestObjectTaggingBranches(t *testing.T) {
	b := New()
	if _, err := b.PutObjectTagging("missing", "k", "", map[string]string{"a": "b"}); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
	if _, err := b.DeleteObjectTagging("missing", "k", ""); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}

	if err := b.CreateBucket("tagging-branches"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if _, err := b.PutObjectTagging("tagging-branches", "missing", "", map[string]string{"a": "b"}); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
	if _, err := b.DeleteObjectTagging("tagging-branches", "missing", ""); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}

	if err := b.SetBucketVersioning("tagging-branches", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	obj, _ := b.PutObject("tagging-branches", "k", []byte("data"), PutObjectOptions{})
	if _, err := b.PutObjectTagging("tagging-branches", "k", "missing-version", map[string]string{"a": "b"}); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}
	if _, err := b.DeleteObjectTagging("tagging-branches", "k", "missing-version"); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("expected ErrVersionNotFound, got %v", err)
	}

	if _, err := b.DeleteObject("tagging-branches", "k", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if _, err := b.PutObjectTagging("tagging-branches", "k", "", map[string]string{"a": "b"}); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound for delete marker, got %v", err)
	}
	if _, err := b.DeleteObjectTagging("tagging-branches", "k", ""); !errors.Is(
		err,
		ErrObjectNotFound,
	) {
		t.Fatalf("expected ErrObjectNotFound for delete marker, got %v", err)
	}

	if _, err := b.PutObjectTagging("tagging-branches", "k", obj.VersionId, map[string]string{"a": "b"}); err != nil {
		t.Fatalf("expected tagging specific non-delete version success, got %v", err)
	}
	if _, err := b.DeleteObjectTagging("tagging-branches", "k", obj.VersionId); err != nil {
		t.Fatalf("expected delete tagging on specific version success, got %v", err)
	}
}

func TestListObjectsHidesKeysWithCurrentDeleteMarker(t *testing.T) {
	b := New()
	if err := b.CreateBucket("list-delete-marker"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if err := b.SetBucketVersioning("list-delete-marker", VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}
	if _, err := b.PutObject("list-delete-marker", "k", []byte("v1"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if _, err := b.DeleteObject("list-delete-marker", "k", false); err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	v1, err := b.ListObjectsV1("list-delete-marker", "", "", "", 1000)
	if err != nil {
		t.Fatalf("ListObjectsV1 failed: %v", err)
	}
	if len(v1.Objects) != 0 {
		t.Fatalf("expected no visible objects in ListObjectsV1, got %+v", v1.Objects)
	}

	v2, err := b.ListObjectsV2("list-delete-marker", "", "", "", "", 1000)
	if err != nil {
		t.Fatalf("ListObjectsV2 failed: %v", err)
	}
	if len(v2.Objects) != 0 {
		t.Fatalf("expected no visible objects in ListObjectsV2, got %+v", v2.Objects)
	}
}

func ptrTimeForObjectBranch(t time.Time) *time.Time {
	return &t
}
