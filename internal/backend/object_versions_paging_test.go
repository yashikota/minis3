package backend

import (
	"testing"
	"time"
)

// TestListObjectVersionsKeyMarkerPaging covers AWS-spec pagination for
// ListObjectVersions with KeyMarker / VersionIdMarker.
//
// AWS spec: KeyMarker alone skips all versions of the marker key and starts
// at the first key greater than the marker. KeyMarker with VersionIdMarker
// starts right after the exact (key, version-id) entry. A trailing marker
// returns an empty result.
func TestListObjectVersionsKeyMarkerPaging(t *testing.T) {
	setup := func(t *testing.T) (*Backend, string, []string, map[string][]string) {
		t.Helper()
		b := New()
		bucket := "versions-keymarker-paging"
		if err := b.CreateBucket(bucket); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := b.SetBucketVersioning(bucket, VersioningEnabled, MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		// key-a has two versions so we can test mid-key resume.
		// Small sleeps keep LastModified ordering deterministic
		// (sort is by key, then LastModified descending).
		a1, err := b.PutObject(bucket, "key-a", []byte("a1"), PutObjectOptions{})
		if err != nil {
			t.Fatalf("PutObject key-a v1 failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		a2, err := b.PutObject(bucket, "key-a", []byte("a2"), PutObjectOptions{})
		if err != nil {
			t.Fatalf("PutObject key-a v2 failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := b.PutObject(bucket, "key-b", []byte("b1"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject key-b failed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
		if _, err := b.PutObject(bucket, "key-c", []byte("c1"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject key-c failed: %v", err)
		}
		// Newest first within a key: a2 then a1.
		versionsByKey := map[string][]string{}
		full, err := b.ListObjectVersions(bucket, "", "", "", "", 10)
		if err != nil {
			t.Fatalf("ListObjectVersions full failed: %v", err)
		}
		_ = a1
		_ = a2
		for _, v := range full.Versions {
			versionsByKey[v.Key] = append(versionsByKey[v.Key], v.VersionId)
		}
		orderedKeys := []string{}
		for _, v := range full.Versions {
			orderedKeys = append(orderedKeys, v.Key+":"+v.VersionId)
		}
		return b, bucket, orderedKeys, versionsByKey
	}

	flatten := func(res *ListObjectVersionsResult) []string {
		got := []string{}
		for _, v := range res.Versions {
			got = append(got, v.Key+":"+v.VersionId)
		}
		for _, d := range res.DeleteMarkers {
			got = append(got, d.Key+":"+d.VersionId)
		}
		return got
	}

	t.Run("keyMarker alone advances to second page", func(t *testing.T) {
		b, bucket, _, _ := setup(t)
		// First page with maxKeys=1.
		page1, err := b.ListObjectVersions(bucket, "", "", "", "", 1)
		if err != nil {
			t.Fatalf("page1 failed: %v", err)
		}
		if !page1.IsTruncated || page1.NextKeyMarker == "" {
			t.Fatalf("expected truncated page1 with NextKeyMarker, got %+v", page1)
		}
		// Second page with keyMarker alone must not return the first
		// entry again (no infinite loop); it skips all versions of the
		// marker key.
		page2, err := b.ListObjectVersions(bucket, "", "", page1.NextKeyMarker, "", 10)
		if err != nil {
			t.Fatalf("page2 failed: %v", err)
		}
		for _, v := range page2.Versions {
			if v.Key == page1.NextKeyMarker {
				t.Fatalf(
					"keyMarker alone did not advance: page2 still contains marker key %q (page1=%+v page2=%+v)",
					v.Key,
					flatten(page1),
					flatten(page2),
				)
			}
		}
		if len(page2.Versions)+len(page2.DeleteMarkers) == 0 {
			t.Fatalf("expected second page to advance past %q, got empty", page1.NextKeyMarker)
		}
		// First entry of page2 must sort after the marker.
		first := ""
		if len(page2.Versions) > 0 {
			first = page2.Versions[0].Key
		} else {
			first = page2.DeleteMarkers[0].Key
		}
		if first <= page1.NextKeyMarker {
			t.Fatalf(
				"expected page2 to start after marker %q, got first key %q",
				page1.NextKeyMarker,
				first,
			)
		}
	})

	tests := []struct {
		name            string
		keyMarker       string
		versionIdMarker string
		maxKeys         int
		wantFirstKey    string // empty means expect empty result
		wantCount       int    // -1 means don't check count
		wantNoKey       string // key that must not appear
	}{
		{
			name:         "keyMarker alone skips whole marker key",
			keyMarker:    "key-a",
			maxKeys:      10,
			wantFirstKey: "key-b",
			wantCount:    2,
			wantNoKey:    "key-a",
		},
		{
			name:         "tail keyMarker alone returns empty",
			keyMarker:    "key-c",
			maxKeys:      10,
			wantFirstKey: "",
			wantCount:    0,
		},
		{
			name:         "after-all keyMarker returns empty",
			keyMarker:    "zzzz",
			maxKeys:      10,
			wantFirstKey: "",
			wantCount:    0,
		},
		{
			name:            "unknown versionId falls back to next key",
			keyMarker:       "key-a",
			versionIdMarker: "non-existent",
			maxKeys:         10,
			wantFirstKey:    "key-b",
			wantCount:       2,
			wantNoKey:       "key-a",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, bucket, _, _ := setup(t)
			res, err := b.ListObjectVersions(
				bucket,
				"",
				"",
				tc.keyMarker,
				tc.versionIdMarker,
				tc.maxKeys,
			)
			if err != nil {
				t.Fatalf("ListObjectVersions failed: %v", err)
			}
			got := len(res.Versions) + len(res.DeleteMarkers)
			if tc.wantCount >= 0 && got != tc.wantCount {
				t.Fatalf("expected %d entries, got %d (%+v)", tc.wantCount, got, flatten(res))
			}
			if tc.wantFirstKey == "" {
				if got != 0 {
					t.Fatalf("expected empty result, got %+v", flatten(res))
				}
				return
			}
			var first string
			if len(res.Versions) > 0 {
				first = res.Versions[0].Key
			} else {
				first = res.DeleteMarkers[0].Key
			}
			if first != tc.wantFirstKey {
				t.Fatalf(
					"expected first key %q, got %q (%+v)",
					tc.wantFirstKey,
					first,
					flatten(res),
				)
			}
			if tc.wantNoKey != "" {
				for _, v := range res.Versions {
					if v.Key == tc.wantNoKey {
						t.Fatalf(
							"marker key %q must be skipped, got %+v",
							tc.wantNoKey,
							flatten(res),
						)
					}
				}
			}
		})
	}

	t.Run("keyMarker with versionIdMarker resumes after exact version", func(t *testing.T) {
		b, bucket, ordered, byKey := setup(t)
		if len(byKey["key-a"]) < 2 {
			t.Fatalf("expected 2 versions for key-a, got %+v (ordered=%v)", byKey, ordered)
		}
		newestA := byKey["key-a"][0]
		res, err := b.ListObjectVersions(bucket, "", "", "key-a", newestA, 10)
		if err != nil {
			t.Fatalf("ListObjectVersions with markers failed: %v", err)
		}
		got := flatten(res)
		// Must resume with the older key-a version, not skip the whole key.
		if len(got) == 0 || res.Versions[0].Key != "key-a" {
			t.Fatalf(
				"expected resume within key-a after newest version, got %+v (ordered=%v)",
				got,
				ordered,
			)
		}
		if res.Versions[0].VersionId == newestA {
			t.Fatalf("exact marker version must be excluded, got %+v", got)
		}
		// Full suffix after the marker: remaining = total - 1.
		if len(got) != len(ordered)-1 {
			t.Fatalf(
				"expected %d entries after exact marker, got %d (%+v, ordered=%v)",
				len(ordered)-1,
				len(got),
				got,
				ordered,
			)
		}
	})
}
