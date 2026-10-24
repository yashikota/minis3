package backend

import (
	"errors"
	"testing"
)

// Regression tests for defects found in the spec audit. Each test names the
// AWS behavior it pins down.

func TestListObjectVersionsNotTruncatedAtExactPageBoundary(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "lov-boundary")
	for range 3 {
		if _, err := b.PutObject("lov-boundary", "k", []byte("x"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject: %v", err)
		}
	}
	res, err := b.ListObjectVersions("lov-boundary", "", "", "", "", 3)
	if err != nil {
		t.Fatalf("ListObjectVersions: %v", err)
	}
	if res.IsTruncated || res.NextKeyMarker != "" || len(res.Versions) != 3 {
		t.Fatalf("exact page must not be truncated, got %+v", res)
	}
	res, _ = b.ListObjectVersions("lov-boundary", "", "", "", "", 0)
	if res.IsTruncated || len(res.Versions) != 0 {
		t.Fatalf("max-keys=0 must return nothing and not be truncated, got %+v", res)
	}
}

func TestListObjectVersionsPagesCommonPrefixes(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "lov-prefixes")
	for _, k := range []string{"a/1", "b", "c/1", "d"} {
		if _, err := b.PutObject("lov-prefixes", k, []byte("x"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject: %v", err)
		}
	}
	// AWS counts CommonPrefixes toward MaxKeys and returns each only once.
	want := []string{"a/", "b", "c/", "d"}
	var got []string
	keyMarker, versionMarker := "", ""
	for range 10 {
		res, err := b.ListObjectVersions("lov-prefixes", "", "/", keyMarker, versionMarker, 1)
		if err != nil {
			t.Fatalf("ListObjectVersions: %v", err)
		}
		if n := len(res.CommonPrefixes) + len(res.Versions); n != 1 {
			t.Fatalf("page has %d entries, want 1: %+v", n, res)
		}
		got = append(got, res.CommonPrefixes...)
		for _, v := range res.Versions {
			got = append(got, v.Key)
		}
		if !res.IsTruncated {
			break
		}
		keyMarker, versionMarker = res.NextKeyMarker, res.NextVersionIdMarker
	}
	if len(got) != len(want) {
		t.Fatalf("paged entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paged entries = %v, want %v", got, want)
		}
	}
}

func TestPutObjectLockConfigurationRejectedLeavesLockDisabled(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "lock-atomic")
	err := b.PutObjectLockConfiguration("lock-atomic", &ObjectLockConfiguration{
		ObjectLockEnabled: "Bogus",
	})
	if !errors.Is(err, ErrInvalidObjectLockConfig) {
		t.Fatalf("expected ErrInvalidObjectLockConfig, got %v", err)
	}
	// Enabling Object Lock is irreversible, so a rejected request must not
	// enable it as a side effect.
	if b.buckets["lock-atomic"].ObjectLockEnabled {
		t.Fatal("rejected configuration enabled Object Lock")
	}
	if err := b.SetBucketVersioning(
		"lock-atomic",
		VersioningSuspended,
		MFADeleteDisabled,
	); err != nil {
		t.Fatalf("bucket without Object Lock must allow suspending versioning: %v", err)
	}
}

func TestDeleteBucketDropsMultipartUploads(t *testing.T) {
	b := New()
	if err := b.CreateBucket("mpu-purge"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	u, err := b.CreateMultipartUpload("mpu-purge", "k", CreateMultipartUploadOptions{})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if err := b.DeleteBucket("mpu-purge"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if err := b.CreateBucket("mpu-purge"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	res, err := b.ListMultipartUploads("mpu-purge", ListMultipartUploadsOptions{})
	if err != nil || len(res.Uploads) != 0 {
		t.Fatalf("re-created bucket inherited uploads: %+v, %v", res, err)
	}
	if _, err := b.UploadPart(
		"mpu-purge",
		"k",
		u.UploadId,
		1,
		[]byte("x"),
	); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("upload of deleted bucket still usable: %v", err)
	}

	u, _ = b.CreateMultipartUpload("mpu-purge", "k", CreateMultipartUploadOptions{})
	if err := b.ForceDeleteBucket("mpu-purge"); err != nil {
		t.Fatalf("ForceDeleteBucket: %v", err)
	}
	if _, ok := b.GetUpload(u.UploadId); ok {
		t.Fatal("ForceDeleteBucket kept the bucket's uploads")
	}
}

func TestCompleteMultipartUploadReportsMissingBucketFirst(t *testing.T) {
	b := New()
	if _, err := b.CompleteMultipartUpload(
		"no-such-bucket",
		"k",
		"u",
		nil,
	); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestCompletedUploadLookup(t *testing.T) {
	b := New()
	if err := b.CreateBucket("mpu-done"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	u, _ := b.CreateMultipartUpload("mpu-done", "k", CreateMultipartUploadOptions{})
	p, _ := b.UploadPart("mpu-done", "k", u.UploadId, 1, []byte("data"))
	obj, err := b.CompleteMultipartUpload("mpu-done", "k", u.UploadId, []CompletePart{
		{PartNumber: 1, ETag: p.ETag},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	if got, ok := b.GetCompletedUploadObject(
		"mpu-done",
		"k",
		u.UploadId,
	); !ok ||
		got.ETag != obj.ETag {
		t.Fatalf("completed upload not found: %v %v", got, ok)
	}
	for _, tc := range []struct{ bucket, key, id string }{
		{"mpu-done", "k", "unknown-upload"},
		{"mpu-done", "other", u.UploadId},
		{"other", "k", u.UploadId},
	} {
		if _, ok := b.GetCompletedUploadObject(tc.bucket, tc.key, tc.id); ok {
			t.Fatalf("unexpected completed upload for %+v", tc)
		}
	}
	// Overwriting the key reuses the "null" version ID; the retry must not
	// report the new object as the upload's result.
	if _, err := b.PutObject("mpu-done", "k", []byte("new"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if _, ok := b.GetCompletedUploadObject("mpu-done", "k", u.UploadId); ok {
		t.Fatal("completed upload matched an object that replaced it")
	}
	// Once the key is gone the retry is no longer idempotent either.
	if _, err := b.DeleteObject("mpu-done", "k", false); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, ok := b.GetCompletedUploadObject("mpu-done", "k", u.UploadId); ok {
		t.Fatal("completed upload still reported after its object was deleted")
	}
	_ = b.DeleteBucket("mpu-done")
	if _, ok := b.GetCompletedUploadObject("mpu-done", "k", u.UploadId); ok {
		t.Fatal("completed upload reported for a deleted bucket")
	}
	// Defensive path: a record whose bucket vanished without a purge.
	b.completedUploads["orphan"] = &completedUpload{Bucket: "gone", Key: "k"}
	if _, ok := b.GetCompletedUploadObject("gone", "k", "orphan"); ok {
		t.Fatal("completed upload reported for a missing bucket")
	}
}

func TestUpdateUpload(t *testing.T) {
	b := New()
	if err := b.UpdateUpload(
		"missing",
		func(*MultipartUpload) error { return nil },
	); !errors.Is(
		err,
		ErrNoSuchUpload,
	) {
		t.Fatalf("expected ErrNoSuchUpload, got %v", err)
	}
	_ = b.CreateBucket("mpu-update")
	u, _ := b.CreateMultipartUpload("mpu-update", "k", CreateMultipartUploadOptions{})
	sentinel := errors.New("sentinel")
	if err := b.UpdateUpload(u.UploadId, func(up *MultipartUpload) error {
		up.ChecksumType = "COMPOSITE"
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("expected callback error, got %v", err)
	}
	if got, _ := b.GetUpload(u.UploadId); got.ChecksumType != "COMPOSITE" {
		t.Fatalf("UpdateUpload did not run the callback on the upload")
	}
}

func TestListMultipartUploadsSameKeyInInitiationOrder(t *testing.T) {
	b := New()
	_ = b.CreateBucket("mpu-order")
	var ids []string
	for range 20 {
		u, _ := b.CreateMultipartUpload("mpu-order", "k", CreateMultipartUploadOptions{})
		ids = append(ids, u.UploadId)
	}
	res, _ := b.ListMultipartUploads("mpu-order", ListMultipartUploadsOptions{})
	for i, u := range res.Uploads {
		if u.UploadId != ids[i] {
			t.Fatalf("upload %d = %s, want %s (initiation order)", i, u.UploadId, ids[i])
		}
	}
}

func TestCopyPartFromDeleteMarkerAndMissingVersion(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "copypart-dm")
	if _, err := b.PutObject(
		"copypart-dm",
		"src",
		[]byte("hello"),
		PutObjectOptions{},
	); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	dm, _ := b.DeleteObject("copypart-dm", "src", false)
	u, _ := b.CreateMultipartUpload("copypart-dm", "dst", CreateMultipartUploadOptions{
		ChecksumAlgorithm: "CRC32",
	})
	if _, err := b.CopyPart(
		"copypart-dm",
		"src",
		dm.VersionId,
		"copypart-dm",
		"dst",
		u.UploadId,
		1,
		-1,
		-1,
	); !errors.Is(
		err,
		ErrCopySourceDeleteMarker,
	) {
		t.Fatalf("copy from delete marker: got %v", err)
	}
	if _, err := b.CopyPart(
		"copypart-dm",
		"src",
		"nope",
		"copypart-dm",
		"dst",
		u.UploadId,
		1,
		-1,
		-1,
	); !errors.Is(
		err,
		ErrVersionNotFound,
	) {
		t.Fatalf("copy from missing version: got %v", err)
	}
	// Copied parts carry the upload's checksum like uploaded parts.
	part, err := b.CopyPart("copypart-dm", "src", "", "copypart-dm", "dst", u.UploadId, 1, -1, -1)
	if err != nil {
		t.Fatalf("CopyPart: %v", err)
	}
	want, _ := ComputeChecksumBase64("CRC32", []byte("hello"))
	if part.ChecksumCRC32 != want {
		t.Fatalf("part checksum = %q, want %q", part.ChecksumCRC32, want)
	}
}

func TestCopyObjectOwnershipAndETag(t *testing.T) {
	b := New()
	_ = b.CreateBucket("copy-owner")
	u, _ := b.CreateMultipartUpload("copy-owner", "mp", CreateMultipartUploadOptions{})
	p, _ := b.UploadPart("copy-owner", "mp", u.UploadId, 1, []byte("data"))
	src, err := b.CompleteMultipartUpload(
		"copy-owner",
		"mp",
		u.UploadId,
		[]CompletePart{{PartNumber: 1, ETag: p.ETag}},
	)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	alt := &Owner{ID: "alt-id", DisplayName: "alt"}
	dst, _, err := b.CopyObject(
		"copy-owner",
		"mp",
		"",
		"copy-owner",
		"dst",
		CopyObjectOptions{Owner: alt},
	)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	// CopyObject writes a new single-part object owned by the writer.
	if dst.ETag == src.ETag || dst.ETag != "\"8d777f385d3dfec8815d20f7496026dc\"" {
		t.Fatalf("copy ETag = %s, want MD5 of the data (source %s)", dst.ETag, src.ETag)
	}
	if dst.Owner == nil || *dst.Owner != *alt || dst.ACL == nil || dst.ACL.Owner.ID != alt.ID {
		t.Fatalf("copy owner = %+v acl=%+v, want %+v", dst.Owner, dst.ACL, alt)
	}
	plain, _, _ := b.CopyObject("copy-owner", "dst", "", "copy-owner", "dst2", CopyObjectOptions{})
	if plain.ETag != dst.ETag || *plain.Owner != *dst.Owner {
		t.Fatalf("single-part copy without owner override changed ETag/owner: %+v", plain)
	}
}

func TestSetBucketVersioningWithoutStatusKeepsState(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "versioning-keep")
	if err := b.SetBucketVersioning(
		"versioning-keep",
		VersioningUnset,
		MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning: %v", err)
	}
	// A bucket that was versioned can never return to unversioned.
	if got := b.buckets["versioning-keep"].VersioningStatus; got != VersioningEnabled {
		t.Fatalf("versioning = %v, want Enabled", got)
	}
}

func TestPutObjectRetentionRequiresModeAndDateTogether(t *testing.T) {
	b := New()
	if err := b.CreateBucketWithObjectLock("retention-pair"); err != nil {
		t.Fatalf("CreateBucketWithObjectLock: %v", err)
	}
	if _, err := b.PutObject("retention-pair", "k", []byte("x"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	for _, r := range []*ObjectLockRetention{
		{Mode: RetentionModeGovernance},
		{RetainUntilDate: "2099-01-01T00:00:00Z"},
	} {
		if err := b.PutObjectRetention(
			"retention-pair",
			"k",
			"",
			r,
			false,
		); !errors.Is(
			err,
			ErrInvalidObjectLockConfig,
		) {
			t.Fatalf("PutObjectRetention(%+v) = %v, want ErrInvalidObjectLockConfig", r, err)
		}
	}
}

func TestDeleteIAMAccessKeyRequiresOwningUser(t *testing.T) {
	b := New()
	_, _ = b.CreateIAMUser("alice", "/")
	_, _ = b.CreateIAMUser("bob", "/")
	key, _ := b.CreateIAMAccessKey("alice")
	if err := b.DeleteIAMAccessKey(
		"bob",
		key.AccessKeyId,
	); !errors.Is(
		err,
		ErrIAMAccessKeyNotFound,
	) {
		t.Fatalf("bob deleted alice's key: %v", err)
	}
	if _, ok := b.LookupCredential(key.AccessKeyId); !ok {
		t.Fatal("alice's key was removed")
	}
	if err := b.DeleteIAMAccessKey("alice", key.AccessKeyId); err != nil {
		t.Fatalf("alice could not delete her key: %v", err)
	}
}

func TestDeletePreconditionTarget(t *testing.T) {
	b := New()
	mustCreateVersionedBucket(t, b, "delete-target")
	if b.DeletePreconditionTarget("missing-bucket", "k") != nil ||
		b.DeletePreconditionTarget("delete-target", "k") != nil {
		t.Fatal("missing bucket/key must have no precondition target")
	}
	put, _ := b.PutObject("delete-target", "k", []byte("x"), PutObjectOptions{})
	if got := b.DeletePreconditionTarget(
		"delete-target",
		"k",
	); got == nil || got.VersionId != put.VersionId ||
		got.ETag != put.ETag {
		t.Fatalf("target = %+v, want current version", got)
	}
	dm, _ := b.DeleteObject("delete-target", "k", false)
	if got := b.DeletePreconditionTarget(
		"delete-target",
		"k",
	); got == nil ||
		got.VersionId != dm.VersionId {
		t.Fatalf("target = %+v, want the delete marker over a live version", got)
	}
	_, _ = b.DeleteObjectVersion("delete-target", "k", put.VersionId, false)
	if got := b.DeletePreconditionTarget("delete-target", "k"); got != nil {
		t.Fatalf("only delete markers remain, target = %+v, want nil", got)
	}
}

func TestPolicyConditionValueLists(t *testing.T) {
	deny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::bkt/*",` +
		`"Condition":{"StringEquals":{"s3:x-amz-acl":["public-read","private"]}}}]}`
	ctx := PolicyEvalContext{
		Action:   "s3:GetObject",
		Resource: "arn:aws:s3:::bkt/k",
		Headers:  map[string]string{"x-amz-acl": "private"},
	}
	// Values in a list are ORed; previously the whole policy failed to parse
	// and the Deny was silently ignored.
	if got := EvaluateBucketPolicyAccess(deny, ctx); got != PolicyEffectDeny {
		t.Fatalf("effect = %v, want Deny", got)
	}
	ctx.Headers["x-amz-acl"] = "authenticated-read"
	if got := EvaluateBucketPolicyAccess(deny, ctx); got != PolicyEffectDefault {
		t.Fatalf("effect = %v, want Default", got)
	}

	// Negated operators match only when no listed value matches.
	notDeny := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject",` +
		`"Condition":{"StringNotEquals":{"s3:x-amz-acl":["public-read","private"]}}}]}`
	if got := EvaluateBucketPolicyAccess(notDeny, ctx); got != PolicyEffectDeny {
		t.Fatalf("StringNotEquals with unlisted value: effect = %v, want Deny", got)
	}
	ctx.Headers["x-amz-acl"] = "private"
	if got := EvaluateBucketPolicyAccess(notDeny, ctx); got != PolicyEffectDefault {
		t.Fatalf("StringNotEquals with listed value: effect = %v, want Default", got)
	}

	// Boolean condition values parse.
	boolPolicy := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",` +
		`"Condition":{"Bool":{"aws:SecureTransport":false}}}]}`
	if err := ValidateBucketPolicy(boolPolicy, ""); err != nil {
		t.Fatalf("boolean condition value rejected: %v", err)
	}
}

func TestPolicyStringOrSliceRejectsMalformedJSON(t *testing.T) {
	var p PolicyStringOrSlice
	if err := p.UnmarshalJSON([]byte("[")); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestPolicyResourceWildcardsSpanSlashes(t *testing.T) {
	policy := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject",` +
		`"Resource":["arn:aws:s3:::bkt/home/*/private","arn:aws:s3:::bkt/pre*"]}]}`
	for target, want := range map[string]PolicyEffect{
		"arn:aws:s3:::bkt/prefix/sub/key":        PolicyEffectDeny,
		"arn:aws:s3:::bkt/home/a/b/private":      PolicyEffectDeny,
		"arn:aws:s3:::bkt/other":                 PolicyEffectDefault,
		"arn:aws:s3:::bkt/home/a/private/public": PolicyEffectDefault,
	} {
		ctx := PolicyEvalContext{Action: "s3:GetObject", Resource: target}
		if got := EvaluateBucketPolicyAccess(policy, ctx); got != want {
			t.Errorf("%s: effect = %v, want %v", target, got, want)
		}
	}
	// Characters that path.Match treated specially are literal in ARNs.
	if !matchResourcePattern("arn:aws:s3:::bkt/[a]*", "arn:aws:s3:::bkt/[a]/x") {
		t.Error("bracket in resource pattern must match literally")
	}
}

func mustCreateVersionedBucket(t *testing.T, b *Backend, name string) {
	t.Helper()
	if err := b.CreateBucket(name); err != nil {
		t.Fatalf("CreateBucket(%q): %v", name, err)
	}
	if err := b.SetBucketVersioning(name, VersioningEnabled, MFADeleteDisabled); err != nil {
		t.Fatalf("SetBucketVersioning(%q): %v", name, err)
	}
}
