package backend

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fill sets every reachable field of v to a value derived from seed, so two
// fills with the same seed give equal, independent values.
func fill(v reflect.Value, seed *int, depth int) {
	*seed++
	n := *seed
	if v.Type() == reflect.TypeFor[time.Time]() {
		v.Set(reflect.ValueOf(time.Unix(int64(n), 0).UTC()))
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(fmt.Sprintf("s%d", n))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(n % 100))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(n % 100))
	case reflect.Pointer:
		if depth == 0 {
			return
		}
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), seed, depth-1)
		v.Set(p)
	case reflect.Slice:
		if depth == 0 {
			return
		}
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := range 2 {
			fill(s.Index(i), seed, depth-1)
		}
		v.Set(s)
	case reflect.Map:
		if depth == 0 {
			return
		}
		m := reflect.MakeMap(v.Type())
		for range 2 {
			k := reflect.New(v.Type().Key()).Elem()
			fill(k, seed, depth-1)
			e := reflect.New(v.Type().Elem()).Elem()
			fill(e, seed, depth-1)
			m.SetMapIndex(k, e)
		}
		v.Set(m)
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fill(v.Field(i), seed, depth)
			}
		}
	}
}

// scribble changes every value reachable from v except byte slices, which
// snapshots share by design.
func scribble(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString(v.String() + "!")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	case reflect.Pointer:
		if !v.IsNil() {
			scribble(v.Elem())
		}
	case reflect.Slice:
		if v.Type() == byteSliceType {
			return
		}
		for i := range v.Len() {
			scribble(v.Index(i))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			scribble(e)
			v.SetMapIndex(k, e)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(v.Interface().(time.Time).Add(time.Hour)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				scribble(v.Field(i))
			}
		}
	}
}

func filled[T any](seed int) T {
	var v T
	fill(reflect.ValueOf(&v).Elem(), &seed, 6)
	return v
}

// TestSnapshotSharesNothingMutable fills every field of the stored types,
// takes a snapshot, changes everything reachable from the snapshot and
// checks that the original did not change.
func TestSnapshotSharesNothingMutable(t *testing.T) {
	t.Parallel()
	check := func(t *testing.T, name string, original, reference, copied any) {
		t.Helper()
		if !reflect.DeepEqual(copied, original) {
			t.Fatalf("%s: snapshot differs from the original", name)
		}
		scribble(reflect.ValueOf(copied))
		if reflect.DeepEqual(copied, original) {
			t.Fatalf("%s: scribble changed nothing", name)
		}
		if !reflect.DeepEqual(original, reference) {
			t.Fatalf("%s: changing the snapshot changed the original", name)
		}
	}
	t.Run("Object", func(t *testing.T) {
		o, ref := filled[*Object](1), filled[*Object](1)
		check(t, "Object", o, ref, snapshot(o))
	})
	t.Run("MultipartUpload", func(t *testing.T) {
		u, ref := filled[*MultipartUpload](2), filled[*MultipartUpload](2)
		check(t, "MultipartUpload", u, ref, snapshot(u))
	})
	t.Run("Bucket", func(t *testing.T) {
		bkt, ref := filled[*Bucket](3), filled[*Bucket](3)
		copied := snapshotBucket(bkt)
		if copied.Objects != nil {
			t.Fatal("bucket snapshot carries objects")
		}
		copied.Objects = snapshot(bkt.Objects)
		check(t, "Bucket", bkt, ref, copied)
	})
	t.Run("ListObjectVersionsResult", func(t *testing.T) {
		r, ref := filled[*ListObjectVersionsResult](4), filled[*ListObjectVersionsResult](4)
		check(t, "ListObjectVersionsResult", r, ref, snapshot(r))
	})
	t.Run("PutObjectOptions", func(t *testing.T) {
		o, ref := filled[PutObjectOptions](5), filled[PutObjectOptions](5)
		copied := snapshot(o)
		check(t, "PutObjectOptions", &o, &ref, &copied)
	})
}

func TestSnapshotSharesByteSlicesAndErrors(t *testing.T) {
	t.Parallel()
	o := &Object{Data: []byte("body")}
	if c := snapshot(o); &c.Data[0] != &o.Data[0] {
		t.Fatal("object data copied, want shared")
	}
	r := []DeleteObjectsResult{{Error: ErrObjectLocked}}
	if c := snapshot(r); !errors.Is(c[0].Error, ErrObjectLocked) {
		t.Fatal("snapshot broke error identity")
	}
	var nilObject *Object
	if snapshot(nilObject) != nil || snapshotBucket(nil) != nil || snapshotBuckets(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}

func newSnapshotBackend(t *testing.T) *Backend {
	t.Helper()
	b := New()
	mustCreateVersionedBucket(t, b, "snap")
	if err := b.CreateBucket("snap-logs"); err != nil {
		t.Fatal(err)
	}
	if err := b.PutBucketACL("snap", CannedACLToPolicy("private")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutObject("snap", "k", []byte("v1"), PutObjectOptions{
		Metadata: map[string]string{"m": "1"},
		Tags:     map[string]string{"t": "1"},
	}); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBackendReturnsSnapshots changes what every getter returns and checks
// the stored state did not change.
func TestBackendReturnsSnapshots(t *testing.T) {
	t.Parallel()
	b := newSnapshotBackend(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T)
		intact func(t *testing.T) bool
	}{
		{"GetBucket", func(t *testing.T) {
			bkt, _ := b.GetBucket("snap")
			bkt.Policy = "changed"
			bkt.ACL.AccessControlList.Grants[0].Permission = "changed"
		}, func(t *testing.T) bool {
			bkt := liveBucket(t, b, "snap")
			return bkt.Policy == "" &&
				bkt.ACL.AccessControlList.Grants[0].Permission == PermissionFullControl
		}},
		{"ListBuckets", func(t *testing.T) {
			b.ListBuckets()[0].Name = "changed"
			b.ListBucketsWithOptions(ListBucketsOptions{}).Buckets[0].Name = "changed"
		}, func(t *testing.T) bool {
			_, ok := b.GetBucket("snap")
			return ok && liveBucket(t, b, "snap").Name == "snap"
		}},
		{"GetObject", func(t *testing.T) {
			obj, _ := b.GetObject("snap", "k")
			obj.Metadata["m"] = "changed"
			obj.Tags["t"] = "changed"
			obj.Owner.ID = "changed"
			obj.IsLatest = false
		}, func(t *testing.T) bool {
			obj := liveObject(t, b, "snap", "k", "")
			return obj.Metadata["m"] == "1" && obj.Tags["t"] == "1" &&
				obj.Owner.ID != "changed" && obj.IsLatest
		}},
		{"GetObjectTagging", func(t *testing.T) {
			tags, _, _ := b.GetObjectTagging("snap", "k", "")
			tags["t"] = "changed"
		}, func(t *testing.T) bool {
			return liveObject(t, b, "snap", "k", "").Tags["t"] == "1"
		}},
		{"GetObjectACL", func(t *testing.T) {
			acl, _ := b.GetObjectACL("snap", "k", "")
			acl.AccessControlList.Grants = nil
		}, func(t *testing.T) bool {
			return len(liveObject(t, b, "snap", "k", "").ACL.AccessControlList.Grants) > 0
		}},
		{"ListObjectsV2", func(t *testing.T) {
			r, _ := b.ListObjectsV2("snap", "", "", "", "", 1000)
			r.Objects[0].Size = 99
		}, func(t *testing.T) bool {
			return liveObject(t, b, "snap", "k", "").Size == 2
		}},
		{"ListObjectVersions", func(t *testing.T) {
			r, _ := b.ListObjectVersions("snap", "", "", "", "", 1000)
			r.Versions[0].ETag = "changed"
		}, func(t *testing.T) bool {
			return liveObject(t, b, "snap", "k", "").ETag != "changed"
		}},
		{"PutObject result", func(t *testing.T) {
			obj, _ := b.PutObject("snap", "p", []byte("x"), PutObjectOptions{})
			obj.ContentType = "changed"
		}, func(t *testing.T) bool {
			return liveObject(t, b, "snap", "p", "").ContentType != "changed"
		}},
		{"GetBucketLogging", func(t *testing.T) {
			if err := b.PutBucketLogging("snap", &BucketLoggingStatus{
				LoggingEnabled: &LoggingEnabled{TargetBucket: "snap-logs"},
			}); err != nil {
				t.Fatal(err)
			}
			cfg, _ := b.GetBucketLogging("snap")
			cfg.LoggingEnabled.TargetPrefix = "changed"
		}, func(t *testing.T) bool {
			return liveBucket(t, b, "snap").LoggingConfiguration.LoggingEnabled.TargetPrefix == ""
		}},
		{"GetBucketCORS", func(t *testing.T) {
			_ = b.PutBucketCORS("snap", &CORSConfiguration{
				CORSRules: []CORSRule{{AllowedMethods: []string{"GET"}}},
			})
			cfg, _ := b.GetBucketCORS("snap")
			cfg.CORSRules[0].AllowedMethods[0] = "changed"
		}, func(t *testing.T) bool {
			return liveBucket(t, b, "snap").CORSConfiguration.CORSRules[0].AllowedMethods[0] == "GET"
		}},
		{"GetPublicAccessBlock", func(t *testing.T) {
			_ = b.PutPublicAccessBlock(
				"snap",
				&PublicAccessBlockConfiguration{BlockPublicAcls: true},
			)
			cfg, _ := b.GetPublicAccessBlock("snap")
			cfg.BlockPublicAcls = false
		}, func(t *testing.T) bool {
			return liveBucket(t, b, "snap").PublicAccessBlock.BlockPublicAcls
		}},
		{"GetUpload and ListParts", func(t *testing.T) {
			u, _ := b.CreateMultipartUpload("snap", "mp", CreateMultipartUploadOptions{})
			u.Key = "changed"
			part, _ := b.UploadPart("snap", "mp", u.UploadId, 1, []byte("x"))
			part.ETag = "changed"
			got, _ := b.GetUpload(u.UploadId)
			got.Parts[1].Size = 99
			parts, upload, _ := b.ListParts("snap", "mp", u.UploadId, ListPartsOptions{})
			parts.Parts[0].PartNumber = 99
			upload.Bucket = "changed"
		}, func(t *testing.T) bool {
			for _, u := range b.uploads {
				if u.Key == "mp" {
					p := u.Parts[1]
					return u.Bucket == "snap" && p.Size == 1 && p.ETag != "changed" &&
						p.PartNumber == 1
				}
			}
			return false
		}},
		{"IAM", func(t *testing.T) {
			u, _ := b.CreateIAMUser("alice", "/")
			u.Arn = "changed"
			k, _ := b.CreateIAMAccessKey("alice")
			k.SecretAccessKey = "changed"
			b.ListIAMUsers("")[0].UserName = "changed"
			b.ListIAMAccessKeys("alice")[0].Status = "changed"
		}, func(t *testing.T) bool {
			u := b.iamUsers["alice"]
			for _, k := range b.iamAccessKeys {
				if k.SecretAccessKey == "changed" || k.Status != "Active" {
					return false
				}
			}
			return u.Arn != "changed" && u.UserName == "alice"
		}},
	}
	for _, tc := range tests {
		tc.mutate(t)
		if !tc.intact(t) {
			t.Errorf("%s: changing the returned value changed stored state", tc.name)
		}
	}
}

// TestBackendCopiesInputs changes what was handed to a setter after the
// call and checks the stored state did not change.
func TestBackendCopiesInputs(t *testing.T) {
	t.Parallel()
	b := newSnapshotBackend(t)

	tags := map[string]string{"a": "1"}
	_ = b.PutBucketTagging("snap", tags)
	tags["a"] = "changed"

	acl := CannedACLToPolicy("public-read")
	_ = b.PutBucketACL("snap", acl)
	acl.AccessControlList.Grants[0].Permission = "changed"

	cors := &CORSConfiguration{CORSRules: []CORSRule{{AllowedOrigins: []string{"*"}}}}
	_ = b.PutBucketCORS("snap", cors)
	cors.CORSRules[0].AllowedOrigins[0] = "changed"

	opts := PutObjectOptions{Metadata: map[string]string{"m": "1"}}
	_, _ = b.PutObject("snap", "in", []byte("x"), opts)
	opts.Metadata["m"] = "changed"

	objTags := map[string]string{"t": "1"}
	_, _ = b.PutObjectTagging("snap", "in", "", objTags)
	objTags["t"] = "changed"

	bkt := liveBucket(t, b, "snap")
	obj := liveObject(t, b, "snap", "in", "")
	for name, ok := range map[string]bool{
		"PutBucketTagging":  bkt.Tags["a"] == "1",
		"PutBucketACL":      bkt.ACL.AccessControlList.Grants[0].Permission != "changed",
		"PutBucketCORS":     bkt.CORSConfiguration.CORSRules[0].AllowedOrigins[0] == "*",
		"PutObject":         obj.Metadata["m"] == "1",
		"PutObjectTagging":  obj.Tags["t"] == "1",
		"normalizeACL left": acl.Xmlns == S3Xmlns || acl.Xmlns == "",
	} {
		if !ok {
			t.Errorf("%s: changing the input after the call changed stored state", name)
		}
	}
}

// TestBackendSnapshotsAreRaceFree runs readers that change what they get
// against writers; run with -race.
func TestBackendSnapshotsAreRaceFree(t *testing.T) {
	t.Parallel()
	b := newSnapshotBackend(t)
	if err := b.PutBucketLogging("snap", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "snap-logs"},
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 50 {
				key := fmt.Sprintf("k%d", j%4)
				if i%2 == 0 {
					_, _ = b.PutObject("snap", key, []byte("x"), PutObjectOptions{
						Tags: map[string]string{"n": fmt.Sprint(j)},
					})
					_ = b.PutObjectACL("snap", key, "", CannedACLToPolicy("private"))
					_ = b.PutBucketTagging("snap", map[string]string{"n": fmt.Sprint(j)})
					continue
				}
				if obj, err := b.GetObject("snap", key); err == nil && obj.Tags != nil {
					obj.Tags["n"] = "reader"
					obj.IsLatest = !obj.IsLatest
				}
				if bkt, ok := b.GetBucket("snap"); ok && bkt.Tags != nil {
					bkt.Tags["n"] = "reader"
				}
				if cfg, err := b.GetBucketLogging("snap"); err == nil {
					cfg.LoggingEnabled.TargetPrefix = "reader"
				}
				if r, err := b.ListObjectVersions("snap", "", "", "", "", 1000); err == nil {
					for _, v := range r.Versions {
						v.IsLatest = false
					}
				}
			}
		})
	}
	wg.Wait()
	for key, versions := range liveBucket(t, b, "snap").Objects {
		if !versions.Versions[0].IsLatest {
			t.Fatalf("%s: latest version lost IsLatest to a reader", key)
		}
		for _, v := range versions.Versions {
			if v.Tags["n"] == "reader" {
				t.Fatalf("%s: a reader changed stored tags", key)
			}
		}
	}
}

func TestUpdateBucketAndObject(t *testing.T) {
	t.Parallel()
	b := newSnapshotBackend(t)
	v1 := liveObject(t, b, "snap", "k", "").VersionId
	if _, err := b.PutObject("snap", "k", []byte("v2"), PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateBucket("snap", func(bkt *Bucket) { bkt.Policy = "p" }); err != nil ||
		liveBucket(t, b, "snap").Policy != "p" {
		t.Fatalf("UpdateBucket = %v, policy %q", err, liveBucket(t, b, "snap").Policy)
	}
	if err := b.UpdateObject(
		"snap",
		"k",
		"",
		func(o *Object) { o.ContentType = "latest" },
	); err != nil ||
		liveObject(t, b, "snap", "k", "").ContentType != "latest" {
		t.Fatalf("UpdateObject latest = %v", err)
	}
	if err := b.UpdateObject(
		"snap",
		"k",
		v1,
		func(o *Object) { o.ContentType = "v1" },
	); err != nil ||
		liveObject(t, b, "snap", "k", v1).ContentType != "v1" {
		t.Fatalf("UpdateObject version = %v", err)
	}
	called := false
	never := func(*Object) { called = true }
	for _, tc := range []struct {
		bucket, key, version string
		want                 error
	}{
		{"missing", "k", "", ErrBucketNotFound},
		{"snap", "missing", "", ErrObjectNotFound},
		{"snap", "k", "missing", ErrVersionNotFound},
	} {
		if err := b.UpdateObject(tc.bucket, tc.key, tc.version, never); !errors.Is(err, tc.want) {
			t.Errorf(
				"UpdateObject(%s/%s@%s) = %v, want %v",
				tc.bucket,
				tc.key,
				tc.version,
				err,
				tc.want,
			)
		}
	}
	if err := b.UpdateBucket(
		"missing",
		func(*Bucket) { called = true },
	); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Errorf("UpdateBucket(missing) = %v, want ErrBucketNotFound", err)
	}
	if called {
		t.Fatal("fn ran for a missing target")
	}
}

func TestSnapshotArraysAndNilContainers(t *testing.T) {
	t.Parallel()
	type holder struct {
		Arr  [2]*Owner
		Nil  map[string]string
		Ptrs []*Owner
	}
	h := holder{Arr: [2]*Owner{{ID: "a"}, nil}}
	c := snapshot(h)
	if c.Arr[0] == h.Arr[0] || c.Arr[0].ID != "a" || c.Arr[1] != nil || c.Nil != nil ||
		c.Ptrs != nil {
		t.Fatalf("snapshot(%+v) = %+v", h, c)
	}
}
