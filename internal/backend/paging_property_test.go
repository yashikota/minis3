package backend

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Property tests for the four paginated list APIs. For random key sets,
// prefixes, delimiters and page sizes they check that:
//
//  1. a single unpaged call returns exactly the entries of an independent
//     oracle (keys under the prefix, rolled up at the first delimiter);
//  2. following the continuation markers page by page returns the same
//     entries in the same order, with no duplicates and no gaps;
//  3. every page holds at most max-keys entries, IsTruncated is set
//     exactly when entries remain, and paging terminates.
//
// formal/tla/S3ListPaging.tla model-checks the same marker rules
// exhaustively over a small key universe.

// listOracle computes the expected listing entries: rolled-up common
// prefixes are marked with a trailing "\x00CP" so they stay distinct from
// keys that look the same.
func listOracle(keys []string, prefix, delimiter string) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		entry := k
		if delimiter != "" {
			if idx := strings.Index(k[len(prefix):], delimiter); idx >= 0 {
				entry = prefix + k[len(prefix):][:idx+len(delimiter)] + "\x00CP"
			}
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSuffix(out[i], "\x00CP") < strings.TrimSuffix(out[j], "\x00CP")
	})
	return out
}

func randomKeys(r *rand.Rand) []string {
	const alphabet = "ab/"
	set := map[string]bool{}
	for range 1 + r.IntN(12) {
		n := 1 + r.IntN(4)
		var sb strings.Builder
		for range n {
			sb.WriteByte(alphabet[r.IntN(len(alphabet))])
		}
		set[sb.String()] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type pagingCase struct {
	keys      []string
	prefix    string
	delimiter string
}

func randomPagingCase(r *rand.Rand) pagingCase {
	return pagingCase{
		keys:      randomKeys(r),
		prefix:    []string{"", "", "a", "a/", "b"}[r.IntN(5)],
		delimiter: []string{"", "/", "/", "b"}[r.IntN(4)],
	}
}

func cpEntries(prefixes []string) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p+"\x00CP")
	}
	return out
}

func mergeSorted(keys, prefixes []string) []string {
	out := append(append([]string(nil), keys...), cpEntries(prefixes)...)
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSuffix(out[i], "\x00CP") < strings.TrimSuffix(out[j], "\x00CP")
	})
	return out
}

func checkPage(t *testing.T, api string, page []string, maxKeys int, truncated bool) {
	t.Helper()
	if len(page) > maxKeys {
		t.Fatalf("%s: page of %d entries exceeds max-keys %d", api, len(page), maxKeys)
	}
	if truncated && len(page) != maxKeys {
		t.Fatalf("%s: truncated page has %d entries, want %d", api, len(page), maxKeys)
	}
}

func checkPagedEqual(t *testing.T, api string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s: paged listing\n got %q\nwant %q", api, got, want)
	}
}

func checkListObjectsPaging(t *testing.T, c pagingCase, maxKeys int) {
	t.Helper()
	b := New()
	_ = b.CreateBucket("paging-bucket")
	for _, k := range c.keys {
		_, _ = b.PutObject("paging-bucket", k, []byte(k), PutObjectOptions{})
	}
	want := listOracle(c.keys, c.prefix, c.delimiter)

	// V1: marker is NextMarker with a delimiter, else the last key.
	full, _ := b.ListObjectsV1("paging-bucket", c.prefix, c.delimiter, "", 1000)
	checkPagedEqual(
		t,
		"ListObjectsV1 unpaged",
		mergeSorted(objectKeys(full.Objects), full.CommonPrefixes),
		want,
	)
	var got []string
	marker := ""
	for pages := 0; ; pages++ {
		if pages > len(want)+1 {
			t.Fatalf("ListObjectsV1: paging did not terminate")
		}
		res, _ := b.ListObjectsV1("paging-bucket", c.prefix, c.delimiter, marker, maxKeys)
		page := mergeSorted(objectKeys(res.Objects), res.CommonPrefixes)
		checkPage(t, "ListObjectsV1", page, maxKeys, res.IsTruncated)
		got = append(got, page...)
		if !res.IsTruncated {
			break
		}
		marker = res.NextMarker
		if marker == "" {
			marker = strings.TrimSuffix(page[len(page)-1], "\x00CP")
		}
	}
	checkPagedEqual(t, "ListObjectsV1", got, want)

	// V2: continuation tokens.
	got = nil
	token := ""
	for pages := 0; ; pages++ {
		if pages > len(want)+1 {
			t.Fatalf("ListObjectsV2: paging did not terminate")
		}
		res, _ := b.ListObjectsV2("paging-bucket", c.prefix, c.delimiter, token, "", maxKeys)
		page := mergeSorted(objectKeys(res.Objects), res.CommonPrefixes)
		checkPage(t, "ListObjectsV2", page, maxKeys, res.IsTruncated)
		if res.KeyCount != len(page) {
			t.Fatalf("ListObjectsV2: KeyCount %d, page has %d entries", res.KeyCount, len(page))
		}
		got = append(got, page...)
		if !res.IsTruncated {
			break
		}
		token = res.NextContinuationToken
	}
	checkPagedEqual(t, "ListObjectsV2", got, want)
}

func checkListObjectVersionsPaging(t *testing.T, c pagingCase, maxKeys int, r *rand.Rand) {
	t.Helper()
	b := New()
	_ = b.CreateBucket("paging-bucket")
	_ = b.SetBucketVersioning("paging-bucket", VersioningEnabled, MFADeleteDisabled)
	for _, k := range c.keys {
		for range 1 + r.IntN(3) {
			if r.IntN(4) == 0 {
				_, _ = b.DeleteObject("paging-bucket", k, false)
			} else {
				_, _ = b.PutObject("paging-bucket", k, []byte(k), PutObjectOptions{})
			}
		}
	}

	// Expected stream: oracle entries with each key expanded to its
	// versions, newest first.
	var want []string
	for _, e := range listOracle(c.keys, c.prefix, c.delimiter) {
		if strings.HasSuffix(e, "\x00CP") {
			want = append(want, e)
			continue
		}
		for _, v := range b.buckets["paging-bucket"].Objects[e].Versions {
			want = append(want, e+"@"+v.VersionId)
		}
	}

	entries := func(res *ListObjectVersionsResult) []string {
		all := append(append([]*Object(nil), res.Versions...), res.DeleteMarkers...)
		var out []string
		for _, p := range res.CommonPrefixes {
			out = append(out, p+"\x00CP")
		}
		// Re-establish the response order: keys ascending, then the stored
		// newest-first version order.
		for _, e := range want {
			for _, o := range all {
				if e == o.Key+"@"+o.VersionId {
					out = append(out, e)
				}
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			ki := strings.TrimSuffix(strings.SplitN(out[i], "@", 2)[0], "\x00CP")
			kj := strings.TrimSuffix(strings.SplitN(out[j], "@", 2)[0], "\x00CP")
			return ki < kj
		})
		return out
	}

	full, _ := b.ListObjectVersions("paging-bucket", c.prefix, c.delimiter, "", "", 1000)
	checkPagedEqual(t, "ListObjectVersions unpaged", entries(full), want)

	var got []string
	keyMarker, versionMarker := "", ""
	for pages := 0; ; pages++ {
		if pages > len(want)+1 {
			t.Fatalf("ListObjectVersions: paging did not terminate")
		}
		res, _ := b.ListObjectVersions(
			"paging-bucket", c.prefix, c.delimiter, keyMarker, versionMarker, maxKeys,
		)
		page := entries(res)
		checkPage(t, "ListObjectVersions", page, maxKeys, res.IsTruncated)
		got = append(got, page...)
		if !res.IsTruncated {
			if res.NextKeyMarker != "" || res.NextVersionIdMarker != "" {
				t.Fatalf("ListObjectVersions: next markers on the last page: %+v", res)
			}
			break
		}
		if res.NextKeyMarker == "" {
			t.Fatalf("ListObjectVersions: truncated page without NextKeyMarker")
		}
		keyMarker, versionMarker = res.NextKeyMarker, res.NextVersionIdMarker
	}
	checkPagedEqual(t, "ListObjectVersions", got, want)
}

func checkListMultipartUploadsPaging(t *testing.T, c pagingCase, maxKeys int, r *rand.Rand) {
	t.Helper()
	b := New()
	_ = b.CreateBucket("paging-bucket")
	uploadsByKey := map[string][]string{}
	for _, k := range c.keys {
		for range 1 + r.IntN(2) {
			u, _ := b.CreateMultipartUpload("paging-bucket", k, CreateMultipartUploadOptions{})
			uploadsByKey[k] = append(uploadsByKey[k], u.UploadId)
		}
	}
	// Same-key uploads are listed in initiation order.
	var want []string
	for _, e := range listOracle(c.keys, c.prefix, c.delimiter) {
		if strings.HasSuffix(e, "\x00CP") {
			want = append(want, e)
			continue
		}
		for _, id := range uploadsByKey[e] {
			want = append(want, e+"@"+id)
		}
	}
	entries := func(res *ListMultipartUploadsInternalResult) []string {
		var out []string
		for _, u := range res.Uploads {
			out = append(out, u.Key+"@"+u.UploadId)
		}
		out = append(out, cpEntries(res.CommonPrefixes)...)
		sort.SliceStable(out, func(i, j int) bool {
			ki := strings.TrimSuffix(strings.SplitN(out[i], "@", 2)[0], "\x00CP")
			kj := strings.TrimSuffix(strings.SplitN(out[j], "@", 2)[0], "\x00CP")
			return ki < kj
		})
		return out
	}

	var got []string
	opts := ListMultipartUploadsOptions{
		Prefix: c.prefix, Delimiter: c.delimiter, MaxUploads: maxKeys,
	}
	for pages := 0; ; pages++ {
		if pages > len(want)+1 {
			t.Fatalf("ListMultipartUploads: paging did not terminate")
		}
		res, _ := b.ListMultipartUploads("paging-bucket", opts)
		page := entries(res)
		checkPage(t, "ListMultipartUploads", page, maxKeys, res.IsTruncated)
		got = append(got, page...)
		if !res.IsTruncated {
			break
		}
		opts.KeyMarker, opts.UploadIdMarker = res.NextKeyMarker, res.NextUploadIdMarker
	}
	checkPagedEqual(t, "ListMultipartUploads", got, want)
}

func runPagingProperties(t *testing.T, r *rand.Rand) {
	t.Helper()
	c := randomPagingCase(r)
	maxKeys := 1 + r.IntN(4)
	t.Logf("keys=%q prefix=%q delimiter=%q max-keys=%d", c.keys, c.prefix, c.delimiter, maxKeys)
	checkListObjectsPaging(t, c, maxKeys)
	checkListObjectVersionsPaging(t, c, maxKeys, r)
	checkListMultipartUploadsPaging(t, c, maxKeys, r)
}

func TestListPagingProperties(t *testing.T) {
	t.Parallel()
	for seed := range uint64(300) {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			runPagingProperties(t, rand.New(rand.NewPCG(seed, 0x9a9e)))
		})
	}
}

func FuzzListPagingProperties(f *testing.F) {
	f.Add(uint64(1), uint64(1))
	f.Add(uint64(99), uint64(3))
	f.Fuzz(func(t *testing.T, s1, s2 uint64) {
		runPagingProperties(t, rand.New(rand.NewPCG(s1, s2)))
	})
}
