package backend

import (
	"maps"
	"reflect"
	"slices"
)

// Callers of Backend get snapshots: every pointer, slice and map a method
// returns is a copy, and every one it is given is copied before it is
// stored, so no caller can change backend state except through Backend's
// methods and their locking, and no later write changes what a caller
// already holds.
//
// Byte slices are the exception: object and part data are never modified
// in place once stored (writes replace the slice), so snapshots share them
// rather than copying every object body on each read. Callers must not
// modify a byte slice after handing it to Backend either.

// snapshot returns a deep copy of v that shares only byte slices and
// interface values with it.
func snapshot[T any](v T) T {
	src := reflect.ValueOf(&v).Elem()
	dst := reflect.New(src.Type()).Elem()
	copyValue(dst, src)
	return dst.Interface().(T)
}

// snapshotBucket copies a bucket's settings without its objects, which
// callers read through the object methods.
func snapshotBucket(bucket *Bucket) *Bucket {
	if bucket == nil {
		return nil
	}
	settings := *bucket
	settings.Objects = nil
	return snapshot(&settings)
}

func snapshotBuckets(buckets []*Bucket) []*Bucket {
	if buckets == nil {
		return nil
	}
	out := make([]*Bucket, len(buckets))
	for i, bucket := range buckets {
		out[i] = snapshotBucket(bucket)
	}
	return out
}

var (
	byteSliceType = reflect.TypeFor[[]byte]()
	objectPtrType = reflect.TypeFor[*Object]()
)

// cloneObject is snapshot for *Object without reflection, since listings
// copy many objects. TestSnapshotSharesNothingMutable checks it against
// every field of Object.
func cloneObject(o *Object) *Object {
	if o == nil {
		return nil
	}
	c := *o
	c.Owner = clonePointer(o.Owner)
	c.ACL = cloneACL(o.ACL)
	c.Tags = maps.Clone(o.Tags)
	c.Metadata = maps.Clone(o.Metadata)
	c.Expires = clonePointer(o.Expires)
	c.RetainUntilDate = clonePointer(o.RetainUntilDate)
	c.RestoreExpiryDate = clonePointer(o.RestoreExpiryDate)
	c.CloudTransitionedAt = clonePointer(o.CloudTransitionedAt)
	c.Parts = slices.Clone(o.Parts)
	return &c
}

func cloneACL(acl *AccessControlPolicy) *AccessControlPolicy {
	if acl == nil {
		return nil
	}
	c := *acl
	c.Owner = clonePointer(acl.Owner)
	c.AccessControlList.Grants = slices.Clone(acl.AccessControlList.Grants)
	for i := range c.AccessControlList.Grants {
		c.AccessControlList.Grants[i].Grantee = clonePointer(c.AccessControlList.Grants[i].Grantee)
	}
	return &c
}

// clonePointer copies a pointer to a value without pointers of its own.
func clonePointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

func copyValue(dst, src reflect.Value) {
	if src.Type() == objectPtrType {
		dst.Set(reflect.ValueOf(cloneObject(src.Interface().(*Object))))
		return
	}
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		p := reflect.New(src.Type().Elem())
		copyValue(p.Elem(), src.Elem())
		dst.Set(p)
	case reflect.Slice:
		if src.IsNil() || src.Type() == byteSliceType {
			dst.Set(src)
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			copyValue(s.Index(i), src.Index(i))
		}
		dst.Set(s)
	case reflect.Map:
		if src.IsNil() {
			return
		}
		m := reflect.MakeMapWithSize(src.Type(), src.Len())
		iter := src.MapRange()
		for iter.Next() {
			v := reflect.New(src.Type().Elem()).Elem()
			copyValue(v, iter.Value())
			m.SetMapIndex(iter.Key(), v)
		}
		dst.Set(m)
	case reflect.Struct:
		// Unexported fields (time.Time's, for instance) are values that
		// are never shared mutably, so the plain copy is enough for them.
		dst.Set(src)
		for i := range src.NumField() {
			if src.Type().Field(i).IsExported() {
				copyValue(dst.Field(i), src.Field(i))
			}
		}
	case reflect.Array:
		for i := range src.Len() {
			copyValue(dst.Index(i), src.Index(i))
		}
	default:
		// Scalars, and interfaces: the only ones stored are errors, whose
		// identity errors.Is relies on.
		dst.Set(src)
	}
}

// UpdateBucket runs fn with exclusive access to a bucket's stored settings,
// for changes no S3 operation makes (test fixtures, for instance). fn must
// not keep the pointer, and must not touch the bucket's objects; use
// UpdateObject for those.
func (b *Backend) UpdateBucket(name string, fn func(*Bucket)) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[name]
	if !ok {
		return ErrBucketNotFound
	}
	fn(bucket)
	return nil
}

// UpdateObject runs fn with exclusive access to one stored object version
// (the latest when versionId is empty), like UpdateBucket.
func (b *Backend) UpdateObject(bucketName, key, versionId string, fn func(*Object)) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bucket, ok := b.buckets[bucketName]
	if !ok {
		return ErrBucketNotFound
	}
	versions, ok := bucket.Objects[key]
	if !ok || len(versions.Versions) == 0 {
		return ErrObjectNotFound
	}
	if versionId == "" {
		fn(versions.Versions[0])
		return nil
	}
	for _, v := range versions.Versions {
		if v.VersionId == versionId {
			fn(v)
			return nil
		}
	}
	return ErrVersionNotFound
}
