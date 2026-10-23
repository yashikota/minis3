package backend

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"
)

// This file is a model-based (stateful property) test of the versioning,
// delete-marker and legal-hold semantics. versioningModel is a direct
// transliteration of the actions of formal/tla/S3Versioning.tla, which TLC
// model-checks exhaustively for small bounds. Here the same model is run in
// lockstep with the real Backend over random operation sequences: after
// every step the observable state (version stacks, IsLatest, GET, list
// results) and every error outcome must agree. Together the two give a
// refinement argument: TLC shows the model satisfies the invariants, and
// this test shows the implementation behaves like the model.

const modelBucket = "model-bucket"

var modelKeys = []string{"a", "b/c", "b/d"}

type modelVersion struct {
	id   string
	dm   bool
	hold bool
}

type versioningModel struct {
	versioning VersioningStatus
	lock       bool
	keys       map[string][]modelVersion // newest first, like ObjectVersions
	seenIDs    map[string]bool           // every non-null version ID ever issued
}

func newVersioningModel() *versioningModel {
	return &versioningModel{
		keys:    map[string][]modelVersion{},
		seenIDs: map[string]bool{},
	}
}

// removeNull drops the null version of key (TLA+: RemoveNull).
func (m *versioningModel) removeNull(key string) {
	m.keys[key] = slices.DeleteFunc(m.keys[key], func(v modelVersion) bool {
		return v.id == NullVersionId
	})
}

// push prepends a version and records a fresh ID (TLA+: Push).
func (m *versioningModel) push(t *testing.T, key string, v modelVersion) {
	t.Helper()
	if v.id != NullVersionId {
		if m.seenIDs[v.id] {
			t.Fatalf("version ID %q issued twice", v.id)
		}
		m.seenIDs[v.id] = true
	}
	m.keys[key] = append([]modelVersion{v}, m.keys[key]...)
}

// expectNewID checks the null/non-null rule for a newly written version.
func (m *versioningModel) expectNewID(t *testing.T, op, got string) {
	t.Helper()
	if m.versioning == VersioningEnabled {
		if got == NullVersionId || got == "" {
			t.Fatalf("%s: versioning enabled but got version ID %q", op, got)
		}
		return
	}
	if got != NullVersionId {
		t.Fatalf("%s: versioning %v must write the null version, got %q", op, m.versioning, got)
	}
}

func (m *versioningModel) put(t *testing.T, key, gotID string) {
	t.Helper()
	m.expectNewID(t, "Put", gotID)
	if m.versioning != VersioningEnabled {
		m.removeNull(key)
	}
	m.push(t, key, modelVersion{id: gotID})
}

func (m *versioningModel) delete(t *testing.T, key string, res *DeleteObjectVersionResult) {
	t.Helper()
	switch m.versioning {
	case VersioningEnabled:
		if !res.IsDeleteMarker {
			t.Fatalf("Delete(%s): expected a delete marker, got %+v", key, res)
		}
		m.expectNewID(t, "Delete", res.VersionId)
		m.push(t, key, modelVersion{id: res.VersionId, dm: true})
	case VersioningSuspended:
		if !res.IsDeleteMarker || res.VersionId != NullVersionId {
			t.Fatalf("Delete(%s): expected a null delete marker, got %+v", key, res)
		}
		m.removeNull(key)
		m.push(t, key, modelVersion{id: NullVersionId, dm: true})
	default:
		if res.IsDeleteMarker {
			t.Fatalf("Delete(%s): unversioned bucket created a delete marker", key)
		}
		delete(m.keys, key)
	}
}

// deleteVersion returns the error the backend must report.
func (m *versioningModel) deleteVersion(key, id string) error {
	versions, ok := m.keys[key]
	if !ok {
		return ErrObjectNotFound
	}
	idx := slices.IndexFunc(versions, func(v modelVersion) bool { return v.id == id })
	if idx < 0 {
		return ErrVersionNotFound
	}
	if !versions[idx].dm && versions[idx].hold {
		return ErrObjectLocked
	}
	m.keys[key] = slices.Delete(versions, idx, idx+1)
	if len(m.keys[key]) == 0 {
		delete(m.keys, key)
	}
	return nil
}

func (m *versioningModel) setVersioning(status VersioningStatus) error {
	if m.lock && status == VersioningSuspended {
		return ErrObjectLockNotEnabled
	}
	if status != VersioningUnset {
		m.versioning = status
	}
	return nil
}

func (m *versioningModel) enableLock() error {
	if !m.lock && m.versioning != VersioningEnabled {
		return ErrObjectLockNotEnabled
	}
	m.lock = true
	return nil
}

func (m *versioningModel) setHold(key, id string, on bool) error {
	if !m.lock {
		return ErrObjectLockNotEnabled
	}
	versions, ok := m.keys[key]
	if !ok {
		return ErrObjectNotFound
	}
	idx := slices.IndexFunc(versions, func(v modelVersion) bool { return v.id == id })
	if idx < 0 {
		return ErrVersionNotFound
	}
	if versions[idx].dm {
		return ErrObjectNotFound
	}
	versions[idx].hold = on
	return nil
}

// pickVersionID chooses an existing version ID of key, or a missing one.
func (m *versioningModel) pickVersionID(key string, r *rand.Rand) string {
	versions := m.keys[key]
	if len(versions) == 0 || r.IntN(5) == 0 {
		return "no-such-version"
	}
	return versions[r.IntN(len(versions))].id
}

// checkAgainst compares every observable of the backend with the model.
func (m *versioningModel) checkAgainst(t *testing.T, b *Backend, step string) {
	t.Helper()
	bucket := b.buckets[modelBucket]
	if bucket.VersioningStatus != m.versioning || bucket.ObjectLockEnabled != m.lock {
		t.Fatalf("%s: bucket state versioning=%v lock=%v, model versioning=%v lock=%v",
			step, bucket.VersioningStatus, bucket.ObjectLockEnabled, m.versioning, m.lock)
	}
	if len(bucket.Objects) != len(m.keys) {
		t.Fatalf("%s: backend has %d keys, model %d", step, len(bucket.Objects), len(m.keys))
	}

	var visible []string
	for _, key := range modelKeys {
		want := m.keys[key]
		ov, ok := bucket.Objects[key]
		if !ok {
			if len(want) != 0 {
				t.Fatalf("%s: key %q missing, model has %+v", step, key, want)
			}
			if _, err := b.GetObject(modelBucket, key); !errors.Is(err, ErrObjectNotFound) {
				t.Fatalf("%s: GET %q on missing key: %v", step, key, err)
			}
			continue
		}
		if len(ov.Versions) != len(want) {
			t.Fatalf("%s: key %q has %d versions, model %d", step, key, len(ov.Versions), len(want))
		}
		for i, v := range ov.Versions {
			hold := v.LegalHoldStatus == LegalHoldStatusOn
			if v.VersionId != want[i].id || v.IsDeleteMarker != want[i].dm ||
				hold != want[i].hold || v.IsLatest != (i == 0) {
				t.Fatalf("%s: key %q version %d = {id:%s dm:%v hold:%v latest:%v}, model %+v",
					step, key, i, v.VersionId, v.IsDeleteMarker, hold, v.IsLatest, want[i])
			}
		}
		got, err := b.GetObject(modelBucket, key)
		if err != nil || got.VersionId != want[0].id {
			t.Fatalf("%s: GET %q = %v, %v; model head %+v", step, key, got, err, want[0])
		}
		if !want[0].dm {
			visible = append(visible, key)
		}
	}

	// ListObjectsV2 shows exactly the keys whose current version is live.
	list, err := b.ListObjectsV2(modelBucket, "", "", "", "", 1000)
	if err != nil {
		t.Fatalf("%s: ListObjectsV2: %v", step, err)
	}
	var listed []string
	for _, o := range list.Objects {
		listed = append(listed, o.Key)
	}
	sort.Strings(visible)
	if !slices.Equal(listed, visible) {
		t.Fatalf("%s: ListObjectsV2 = %v, model visible keys %v", step, listed, visible)
	}

	// ListObjectVersions returns every version, keys ascending, newest first.
	lv, err := b.ListObjectVersions(modelBucket, "", "", "", "", 1000)
	if err != nil {
		t.Fatalf("%s: ListObjectVersions: %v", step, err)
	}
	total := 0
	for _, versions := range m.keys {
		total += len(versions)
	}
	if lv.IsTruncated || len(lv.Versions)+len(lv.DeleteMarkers) != total {
		t.Fatalf("%s: ListObjectVersions returned %d entries (truncated=%v), model %d",
			step, len(lv.Versions)+len(lv.DeleteMarkers), lv.IsTruncated, total)
	}
}

// runVersioningModel drives the backend and the model with operations drawn
// from r, checking agreement after every step.
func runVersioningModel(t *testing.T, steps int, r *rand.Rand) {
	t.Helper()
	b := New()
	if err := b.CreateBucket(modelBucket); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	m := newVersioningModel()

	expectErr := func(step string, got, want error) {
		t.Helper()
		if want == nil && got != nil || want != nil && !errors.Is(got, want) {
			t.Fatalf("%s: error = %v, model expects %v", step, got, want)
		}
	}

	for i := range steps {
		key := modelKeys[r.IntN(len(modelKeys))]
		var step string
		switch op := r.IntN(10); op {
		case 0, 1, 2:
			step = fmt.Sprintf("step %d Put(%s)", i, key)
			obj, err := b.PutObject(modelBucket, key, []byte(step), PutObjectOptions{})
			if err != nil {
				t.Fatalf("%s: %v", step, err)
			}
			m.put(t, key, obj.VersionId)
		case 3:
			step = fmt.Sprintf("step %d Delete(%s)", i, key)
			res, err := b.DeleteObject(modelBucket, key, false)
			if err != nil {
				t.Fatalf("%s: %v", step, err)
			}
			m.delete(t, key, res)
		case 4:
			step = fmt.Sprintf("step %d DeleteObjects(%s)", i, key)
			res, err := b.DeleteObjects(modelBucket, []ObjectIdentifier{{Key: key}}, false)
			if err != nil || len(res) != 1 || res[0].Error != nil {
				t.Fatalf("%s: %+v, %v", step, res, err)
			}
			m.delete(t, key, &DeleteObjectVersionResult{
				VersionId:      res[0].DeleteMarkerVersionId,
				IsDeleteMarker: res[0].DeleteMarker,
			})
		case 5:
			id := m.pickVersionID(key, r)
			step = fmt.Sprintf("step %d DeleteVersion(%s, %s)", i, key, id)
			_, err := b.DeleteObjectVersion(modelBucket, key, id, false)
			expectErr(step, err, m.deleteVersion(key, id))
		case 6:
			status := []VersioningStatus{
				VersioningEnabled, VersioningSuspended, VersioningUnset,
			}[r.IntN(3)]
			step = fmt.Sprintf("step %d SetVersioning(%v)", i, status)
			err := b.SetBucketVersioning(modelBucket, status, MFADeleteDisabled)
			expectErr(step, err, m.setVersioning(status))
		case 7:
			if r.IntN(3) == 0 {
				// A rejected configuration must not change any state.
				step = fmt.Sprintf("step %d EnableObjectLock(invalid)", i)
				err := b.PutObjectLockConfiguration(modelBucket, &ObjectLockConfiguration{
					ObjectLockEnabled: "Bogus",
				})
				if err == nil {
					t.Fatalf("%s: invalid configuration accepted", step)
				}
				break
			}
			step = fmt.Sprintf("step %d EnableObjectLock", i)
			err := b.PutObjectLockConfiguration(modelBucket, &ObjectLockConfiguration{
				ObjectLockEnabled: "Enabled",
			})
			expectErr(step, err, m.enableLock())
		default:
			id := m.pickVersionID(key, r)
			on := r.IntN(2) == 0
			status := LegalHoldStatusOff
			if on {
				status = LegalHoldStatusOn
			}
			step = fmt.Sprintf("step %d LegalHold(%s, %s, %v)", i, key, id, on)
			err := b.PutObjectLegalHold(modelBucket, key, id, &ObjectLockLegalHold{Status: status})
			expectErr(step, err, m.setHold(key, id, on))
		}
		m.checkAgainst(t, b, step)
	}
}

func TestVersioningModelRandomSequences(t *testing.T) {
	for seed := range uint64(200) {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			runVersioningModel(t, 120, rand.New(rand.NewPCG(seed, 0x5eed)))
		})
	}
}

func FuzzVersioningModel(f *testing.F) {
	f.Add(uint64(1), uint64(2), uint8(60))
	f.Add(uint64(42), uint64(7), uint8(200))
	f.Fuzz(func(t *testing.T, s1, s2 uint64, steps uint8) {
		runVersioningModel(t, int(steps), rand.New(rand.NewPCG(s1, s2)))
	})
}
