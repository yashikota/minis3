package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

// Regression tests for defects found in the spec audit.

func mustVersionedBucketWithObject(
	t *testing.T,
	b *backend.Backend,
	bucket, key string,
) *backend.Object {
	t.Helper()
	mustCreateBucket(t, b, bucket)
	if err := b.SetBucketVersioning(
		bucket,
		backend.VersioningEnabled,
		backend.MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning: %v", err)
	}
	obj, err := b.PutObject(bucket, key, []byte("v"), backend.PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	return obj
}

func TestConditionalHeadersFollowRFC9110Precedence(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	obj := mustVersionedBucketWithObject(t, b, "cond-bucket", "k")
	lastModified := obj.LastModified.Format(http.TimeFormat)
	old := "Mon, 01 Jan 2001 00:00:00 GMT"
	future := "Fri, 01 Jan 2100 00:00:00 GMT"

	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		// The object's own Last-Modified (second resolution) round-trips.
		{"if-unmodified-since own last-modified", map[string]string{"If-Unmodified-Since": lastModified}, 200},
		{"if-modified-since own last-modified", map[string]string{"If-Modified-Since": lastModified}, 304},
		{"if-unmodified-since old", map[string]string{"If-Unmodified-Since": old}, 412},
		{"if-modified-since old", map[string]string{"If-Modified-Since": old}, 200},
		// AWS: If-Match true + If-Unmodified-Since false returns 200.
		{"if-match wins over if-unmodified-since", map[string]string{
			"If-Match": obj.ETag, "If-Unmodified-Since": old,
		}, 200},
		{"if-match false", map[string]string{"If-Match": `"nope"`, "If-Unmodified-Since": future}, 412},
		// If-None-Match true (no match) + If-Modified-Since false returns 200.
		{"if-none-match wins over if-modified-since", map[string]string{
			"If-None-Match": `"nope"`, "If-Modified-Since": future,
		}, 200},
		{"if-none-match match", map[string]string{"If-None-Match": obj.ETag, "If-Modified-Since": old}, 304},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := doRequest(
					h,
					newRequest(method, "http://example.test/cond-bucket/k", "", tc.headers),
				)
				if w.Code != tc.want {
					t.Fatalf("%s: status = %d, want %d", method, w.Code, tc.want)
				}
			}
		})
	}
}

func TestCopySourceConditionalsFollowRFC9110Precedence(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	obj := mustVersionedBucketWithObject(t, b, "copy-cond", "src")
	old := "Mon, 01 Jan 2001 00:00:00 GMT"
	future := "Fri, 01 Jan 2100 00:00:00 GMT"
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		// AWS CopyObject: if-match true + if-unmodified-since false copies.
		{"if-match wins", map[string]string{
			"x-amz-copy-source-if-match":            obj.ETag,
			"x-amz-copy-source-if-unmodified-since": old,
		}, 200},
		{"if-none-match wins", map[string]string{
			"x-amz-copy-source-if-none-match":     `"nope"`,
			"x-amz-copy-source-if-modified-since": future,
		}, 200},
		{"if-none-match match", map[string]string{"x-amz-copy-source-if-none-match": obj.ETag}, 412},
		{"own last-modified", map[string]string{
			"x-amz-copy-source-if-unmodified-since": obj.LastModified.Format(http.TimeFormat),
		}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.headers["x-amz-copy-source"] = "/copy-cond/src"
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/copy-cond/dst", "", tc.headers),
			)
			requireStatus(t, w, tc.want)
		})
	}
}

func TestGetAndHeadDeleteMarkerVersionIs405(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustVersionedBucketWithObject(t, b, "dm-405", "k")
	dm, err := b.DeleteObject("dm-405", "k", false)
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	url := "http://example.test/dm-405/k?versionId=" + dm.VersionId

	w := doRequest(h, newRequest(http.MethodGet, url, "", nil))
	requireStatus(t, w, http.StatusMethodNotAllowed)
	requireS3ErrorCode(t, w, "MethodNotAllowed")
	if w.Header().Get("x-amz-delete-marker") != "true" || w.Header().Get("Last-Modified") == "" {
		t.Fatalf("missing delete marker headers: %v", w.Header())
	}

	w = doRequest(h, newRequest(http.MethodHead, url, "", nil))
	requireStatus(t, w, http.StatusMethodNotAllowed)

	// Without a version ID a current delete marker is still 404.
	w = doRequest(h, newRequest(http.MethodGet, "http://example.test/dm-405/k", "", nil))
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchKey")
}

func TestGetObjectRangeWithPartNumberIsInvalid(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "range-part")
	mustPutObject(t, b, "range-part", "k", "abcdef")
	w := doRequest(h, newRequest(
		http.MethodGet, "http://example.test/range-part/k?partNumber=1", "",
		map[string]string{"Range": "bytes=0-1"},
	))
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidRequest")
}

func TestPutBucketVersioningPreservesUnspecifiedFields(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "versioning-keep")
	put := func(body string, headers map[string]string) int {
		return doRequest(h, newRequest(
			http.MethodPut, "http://example.test/versioning-keep?versioning", body, headers,
		)).Code
	}
	if code := put(
		`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
		nil,
	); code != 200 {
		t.Fatalf("enable versioning: %d", code)
	}
	// A configuration without Status must not revert the bucket to unversioned.
	if code := put(`<VersioningConfiguration></VersioningConfiguration>`, nil); code != 200 {
		t.Fatalf("empty configuration: %d", code)
	}
	status, _, _ := b.GetBucketVersioning("versioning-keep")
	if status != backend.VersioningEnabled {
		t.Fatalf("status = %v, want Enabled", status)
	}

	mfa := map[string]string{"x-amz-mfa": "20899872 301749"}
	if code := put(
		`<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`,
		mfa,
	); code != 200 {
		t.Fatalf("enable MFA delete: %d", code)
	}
	// While MFA Delete is enabled, changing versioning needs x-amz-mfa...
	if code := put(
		`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
		nil,
	); code != 400 {
		t.Fatalf("suspend without MFA: %d, want 400", code)
	}
	// ...and omitting MfaDelete keeps it enabled.
	if code := put(
		`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
		mfa,
	); code != 200 {
		t.Fatalf("suspend with MFA: %d", code)
	}
	status, mfaDelete, _ := b.GetBucketVersioning("versioning-keep")
	if status != backend.VersioningSuspended || mfaDelete != backend.MFADeleteEnabled {
		t.Fatalf("status=%v mfa=%v, want Suspended/Enabled", status, mfaDelete)
	}
	if code := put(
		`<VersioningConfiguration><MfaDelete>Bogus</MfaDelete></VersioningConfiguration>`,
		mfa,
	); code != 400 {
		t.Fatalf("invalid MfaDelete: %d, want 400", code)
	}
	// Restating the current MfaDelete value on a bucket without MFA Delete
	// needs no header.
	mustCreateBucket(t, b, "versioning-plain")
	w := doRequest(h, newRequest(
		http.MethodPut,
		"http://example.test/versioning-plain?versioning",
		`<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>`,
		nil,
	))
	requireStatus(t, w, http.StatusOK)
}

func TestMFADeleteEnforcedForVersionDeletes(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	obj := mustVersionedBucketWithObject(t, b, "mfa-delete", "k")
	if err := b.SetBucketVersioning(
		"mfa-delete",
		backend.VersioningEnabled,
		backend.MFADeleteEnabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning: %v", err)
	}
	url := "http://example.test/mfa-delete/k?versionId=" + obj.VersionId

	w := doRequest(h, newRequest(http.MethodDelete, url, "", nil))
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "AccessDenied")

	body := fmt.Sprintf(`<Delete><Object><Key>k</Key><VersionId>%s</VersionId></Object>`+
		`<Object><Key>other</Key></Object></Delete>`, obj.VersionId)
	w = doRequest(
		h,
		newRequest(http.MethodPost, "http://example.test/mfa-delete?delete", body, nil),
	)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") ||
		!strings.Contains(w.Body.String(), "<Deleted><Key>other</Key>") {
		t.Fatalf(
			"expected per-entry AccessDenied and a deleted unversioned entry, got %s",
			w.Body.String(),
		)
	}
	if _, err := b.GetObjectVersion("mfa-delete", "k", obj.VersionId); err != nil {
		t.Fatalf("version deleted without MFA: %v", err)
	}

	// Deletes without a version ID only add delete markers and need no MFA.
	w = doRequest(h, newRequest(http.MethodDelete, "http://example.test/mfa-delete/k", "", nil))
	requireStatus(t, w, http.StatusNoContent)

	w = doRequest(
		h,
		newRequest(http.MethodDelete, url, "", map[string]string{"x-amz-mfa": "20899872 301749"}),
	)
	requireStatus(t, w, http.StatusNoContent)
}

func TestCompleteMultipartUploadUnknownUploadOnExistingKey(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "mpu-retry")
	mustPutObject(t, b, "mpu-retry", "k", "existing")
	body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`
	// An unknown upload ID is NoSuchUpload even when the key exists.
	w := doRequest(
		h,
		newRequest(http.MethodPost, "http://example.test/mpu-retry/k?uploadId=bogus", body, nil),
	)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchUpload")

	// A retried completion of a real upload succeeds with the same ETag.
	u, _ := b.CreateMultipartUpload("mpu-retry", "k", backend.CreateMultipartUploadOptions{})
	p, _ := b.UploadPart("mpu-retry", "k", u.UploadId, 1, []byte("data"))
	body = fmt.Sprintf(
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`,
		p.ETag,
	)
	url := "http://example.test/mpu-retry/k?uploadId=" + u.UploadId
	first := doRequest(h, newRequest(http.MethodPost, url, body, nil))
	requireStatus(t, first, http.StatusOK)
	second := doRequest(h, newRequest(http.MethodPost, url, body, nil))
	requireStatus(t, second, http.StatusOK)
	if first.Body.String() != second.Body.String() {
		t.Fatalf("retried completion differs:\n%s\n%s", first.Body.String(), second.Body.String())
	}
}

func TestCopyObjectRestoresPreviousVersionOntoSameKey(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	v1 := mustVersionedBucketWithObject(t, b, "restore-version", "k")
	if _, err := b.PutObject(
		"restore-version",
		"k",
		[]byte("v2"),
		backend.PutObjectOptions{},
	); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	// AWS documents copying a previous version onto its key as the way to
	// restore it, so this is not an illegal self-copy.
	w := doRequest(h, newRequest(http.MethodPut, "http://example.test/restore-version/k", "",
		map[string]string{"x-amz-copy-source": "/restore-version/k?versionId=" + v1.VersionId}))
	requireStatus(t, w, http.StatusOK)
	current, _ := b.GetObject("restore-version", "k")
	if string(current.Data) != "v" {
		t.Fatalf("current data = %q, want restored %q", current.Data, "v")
	}
	// Copying the current version onto itself is still illegal.
	w = doRequest(h, newRequest(
		http.MethodPut,
		"http://example.test/restore-version/k",
		"",
		map[string]string{
			"x-amz-copy-source": "/restore-version/k?versionId=" + current.VersionId,
		},
	))
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidRequest")
}

func TestCopyObjectValidatesDirectivesAndTags(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "copy-validate")
	mustPutObject(t, b, "copy-validate", "src", "x")
	for name, headers := range map[string]map[string]string{
		"metadata directive": {"x-amz-metadata-directive": "MOVE"},
		"tagging directive":  {"x-amz-tagging-directive": "MERGE"},
		"replacement tags": {
			"x-amz-tagging-directive": "REPLACE",
			"x-amz-tagging":           strings.Repeat("k", 129) + "=v",
		},
	} {
		t.Run(name, func(t *testing.T) {
			headers["x-amz-copy-source"] = "/copy-validate/src"
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/copy-validate/dst", "", headers),
			)
			requireStatus(t, w, http.StatusBadRequest)
		})
	}
}

func TestListingsReportObjectOwner(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "owner-list")
	alt := backend.OwnerForAccessKey("minis3-alt-access-key")
	if _, err := b.PutObject(
		"owner-list",
		"k",
		[]byte("x"),
		backend.PutObjectOptions{Owner: alt},
	); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	for _, url := range []string{
		"http://example.test/owner-list",
		"http://example.test/owner-list?list-type=2&fetch-owner=true",
		"http://example.test/owner-list?versions",
	} {
		w := doRequest(h, newRequest(http.MethodGet, url, "", nil))
		requireStatus(t, w, http.StatusOK)
		if !strings.Contains(w.Body.String(), "<ID>"+alt.ID+"</ID>") {
			t.Fatalf("%s: owner %s missing from %s", url, alt.ID, w.Body.String())
		}
	}
}

func TestListObjectsCapsMaxKeysAt1000(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "max-keys-cap")
	for i := range 1001 {
		mustPutObject(t, b, "max-keys-cap", fmt.Sprintf("k%04d", i), "x")
	}
	w := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/max-keys-cap?list-type=2&max-keys=5000",
			"",
			nil,
		),
	)
	requireStatus(t, w, http.StatusOK)
	if got := strings.Count(w.Body.String(), "<Contents>"); got != 1000 ||
		!strings.Contains(w.Body.String(), "<IsTruncated>true</IsTruncated>") {
		t.Fatalf("returned %d keys, want 1000 and truncated", got)
	}
}

func TestListObjectVersionsChecksAccess(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "versions-private")
	b.SetBucketOwner("versions-private", "minis3-access-key")
	w := doRequest(
		h,
		newRequest(http.MethodGet, "http://example.test/versions-private?versions", "",
			map[string]string{"Authorization": authHeader("minis3-alt-access-key")}),
	)
	requireStatus(t, w, http.StatusForbidden)
	requireS3ErrorCode(t, w, "AccessDenied")
}

func TestIAMCredentialsAreScopedPerHandler(t *testing.T) {
	t.Parallel()
	// Two minis3 instances in one process (e.g. parallel tests) must each
	// resolve their own IAM access keys.
	h1, b1 := newTestHandler(t)
	_, _ = newTestHandler(t)
	if _, err := b1.CreateIAMUser("alice", "/"); err != nil {
		t.Fatalf("CreateIAMUser: %v", err)
	}
	key, err := b1.CreateIAMAccessKey("alice")
	if err != nil {
		t.Fatalf("CreateIAMAccessKey: %v", err)
	}
	if secret, ok := h1.lookupCredential(key.AccessKeyId); !ok || secret != key.SecretAccessKey {
		t.Fatalf("first handler lost its IAM key after a second handler was created")
	}
	if secret, ok := h1.lookupCredential("test"); !ok || secret != "test" {
		t.Fatal("static credentials must resolve through the handler")
	}
	r := newRequest(http.MethodGet, "http://example.test/", "", nil)
	if _, ok := lookupCredential(r, key.AccessKeyId); ok {
		t.Fatal("request without a handler resolved a handler-scoped IAM key")
	}
	r = r.WithContext(
		context.WithValue(r.Context(), credentialLookupContextKey{}, h1.lookupCredential),
	)
	if secret, ok := lookupCredential(r, key.AccessKeyId); !ok || secret != key.SecretAccessKey {
		t.Fatal("request carrying the handler lookup did not resolve its IAM key")
	}
}

func TestConcurrentDeleteAndPutDoNotRace(t *testing.T) {
	t.Parallel()
	// Run with -race: DELETE preconditions used to read the bucket's object
	// map without the backend lock.
	h, b := newTestHandler(t)
	mustVersionedBucketWithObject(t, b, "race-bucket", "k")
	if _, err := b.DeleteObject("race-bucket", "k", false); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			doRequest(
				h,
				newRequest(http.MethodDelete, "http://example.test/race-bucket/k", "", nil),
			)
		}()
		go func() {
			defer wg.Done()
			doRequest(h, newRequest(http.MethodPut, "http://example.test/race-bucket/k", "x", nil))
		}()
		go func() {
			defer wg.Done()
			doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/race-bucket/other", "x", nil),
			)
		}()
	}
	wg.Wait()
}

func TestCopyFromDeleteMarkerVersionIs400(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustVersionedBucketWithObject(t, b, "copy-dm", "src")
	dm, _ := b.DeleteObject("copy-dm", "src", false)
	u, _ := b.CreateMultipartUpload("copy-dm", "dst", backend.CreateMultipartUploadOptions{})
	source := "/copy-dm/src?versionId=" + dm.VersionId
	for name, url := range map[string]string{
		"CopyObject":     "http://example.test/copy-dm/dst",
		"UploadPartCopy": "http://example.test/copy-dm/dst?partNumber=1&uploadId=" + u.UploadId,
	} {
		t.Run(name, func(t *testing.T) {
			w := doRequest(
				h,
				newRequest(http.MethodPut, url, "", map[string]string{"x-amz-copy-source": source}),
			)
			requireStatus(t, w, http.StatusBadRequest)
			requireS3ErrorCode(t, w, "InvalidRequest")
		})
	}
	w := doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/copy-dm/dst?partNumber=1&uploadId="+u.UploadId,
			"",
			map[string]string{"x-amz-copy-source": "/copy-dm/src?versionId=missing"},
		),
	)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchVersion")

	// Copy-source conditionals on a current delete marker: 404 NoSuchKey.
	w = doRequest(
		h,
		newRequest(http.MethodPut, "http://example.test/copy-dm/dst", "", map[string]string{
			"x-amz-copy-source":          "/copy-dm/src",
			"x-amz-copy-source-if-match": "*",
		}),
	)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchKey")

	// The version can vanish between the handler's checks and the copy.
	restore := h.hooks.copyPart
	t.Cleanup(func() { h.hooks.copyPart = restore })
	h.hooks.copyPart = func(*Handler, string, string, string, string, string, string, int, int64, int64) (*backend.PartInfo, error) {
		return nil, backend.ErrVersionNotFound
	}
	w = doRequest(
		h,
		newRequest(
			http.MethodPut,
			"http://example.test/copy-dm/dst?partNumber=1&uploadId="+u.UploadId,
			"",
			map[string]string{"x-amz-copy-source": "/copy-dm/src"},
		),
	)
	requireStatus(t, w, http.StatusNotFound)
	requireS3ErrorCode(t, w, "NoSuchVersion")
}

func TestIsNoncurrentVersionMissingKey(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)
	if h.isNoncurrentVersion("no-bucket", "k", "v1") {
		t.Fatal("missing key must not count as a noncurrent version")
	}
}
