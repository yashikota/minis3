package handler

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestDefaultCredentialLookupAndSourceAccountBranches(t *testing.T) {
	if secret, ok := defaultCredentialLookup("test"); !ok || secret != "test" {
		t.Fatalf("defaultCredentialLookup(test) = (%q,%v), want (test,true)", secret, ok)
	}
	if _, ok := defaultCredentialLookup("missing-access-key"); ok {
		t.Fatal("defaultCredentialLookup(missing) should not resolve")
	}

	if got := sourceAccountIDForLogging("root-access-key"); got != "123456789012" {
		t.Fatalf("sourceAccountIDForLogging(root-access-key) = %q", got)
	}
	if got := sourceAccountIDForLogging("altroot-access-key"); got != "210987654321" {
		t.Fatalf("sourceAccountIDForLogging(altroot-access-key) = %q", got)
	}
}

func TestHandleIAMGetUserAltRootBranch(t *testing.T) {
	h, _ := newTestHandler(t)

	w := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/?Action=GetUser",
			"",
			map[string]string{"Authorization": authHeader("altroot-access-key")},
		),
	)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "<Arn>arn:aws:iam::210987654321:root</Arn>") {
		t.Fatalf("unexpected IAM GetUser response: %s", w.Body.String())
	}
}

func TestPutBucketOwnershipAndPostBucketLoggingRemainingBranches(t *testing.T) {
	t.Run("ownership controls reject enforced mode with non-private ACL", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "own-branch")
		b.SetBucketOwner("own-branch", "minis3-access-key")
		if err := b.PutBucketACL("own-branch", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/own-branch?ownershipControls",
				`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidBucketAclWithObjectOwnership")
	})

	t.Run("post bucket logging access denied", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "post-denied")
		b.SetBucketOwner("post-denied", "minis3-access-key")

		w := doRequest(
			h,
			newRequest(http.MethodPost, "http://example.test/post-denied?logging", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("post bucket logging flush error", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "post-src")
		mustCreateBucket(t, b, "post-dst")
		b.SetBucketOwner("post-src", "minis3-access-key")
		b.SetBucketOwner("post-dst", "minis3-access-key")
		if err := b.PutBucketPolicy("post-dst", `{"Statement":[]}`, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		h.loggingMu.Lock()
		h.pendingLogBatches["post-flush-error"] = &serverAccessLogBatch{
			TargetBucket: "post-dst",
			TargetPrefix: "logs/",
			FirstEventAt: time.Now().UTC().Add(-time.Minute),
			Entries: []serverAccessLogEntry{{
				SourceBucket: "post-src",
				SourceAccount: sourceAccountIDForLogging(
					"minis3-access-key",
				),
				Line: "line",
			}},
		}
		h.loggingMu.Unlock()

		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/post-src?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})

	t.Run("post bucket logging marshal error", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "post-marshal")
		b.SetBucketOwner("post-marshal", "minis3-access-key")

		origMarshal := xmlMarshalFn
		xmlMarshalFn = func(any) ([]byte, error) { return nil, errors.New("marshal boom") }
		t.Cleanup(func() {
			xmlMarshalFn = origMarshal
		})

		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/post-marshal?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
	})
}

func TestLoggingConditionValuesAdditionalBranches(t *testing.T) {
	values, found := loggingConditionValues(
		map[string]any{"ArnLike": "not-a-map"},
		[]string{"ArnLike"},
		"aws:SourceArn",
	)
	if found || len(values) != 0 {
		t.Fatalf("loggingConditionValues non-map operator = (%v,%v), want (false,empty)", found, values)
	}

	values, found = loggingConditionValues(
		map[string]any{"ArnLike": map[string]any{"other": "x"}},
		[]string{"ArnLike"},
		"aws:SourceArn",
	)
	if found || len(values) != 0 {
		t.Fatalf("loggingConditionValues missing condition key = (%v,%v), want (false,empty)", found, values)
	}
}

func TestLoggingHelperRemainingBranches(t *testing.T) {
	if got := normalizeBucketNameForRequestAccessKey(":bucket", ""); got != "bucket" {
		t.Fatalf("normalizeBucketNameForRequestAccessKey(:bucket) = %q", got)
	}
	if queryHasInsensitive(nil, "x") {
		t.Fatal("queryHasInsensitive(nil) must be false")
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/?Alpha=1&Beta=2", nil)
	if !queryHasInsensitive(req, "alpha") {
		t.Fatal("queryHasInsensitive should match case-insensitively")
	}
	if got := queryValueInsensitive(nil, "alpha"); got != "" {
		t.Fatalf("queryValueInsensitive(nil) = %q, want empty", got)
	}
	if got := queryValueInsensitive(req, "alpha"); got != "1" {
		t.Fatalf("queryValueInsensitive(alpha) = %q, want 1", got)
	}
	if got := queryValueInsensitive(req, "missing"); got != "" {
		t.Fatalf("queryValueInsensitive(missing) = %q, want empty", got)
	}

	if got := normalizeLoggingType("journal"); got != backend.BucketLoggingTypeJournal {
		t.Fatalf("normalizeLoggingType(journal) = %q", got)
	}

	filter := &backend.LoggingFilter{
		Key: &backend.LoggingKeyFilter{
			FilterRules: []backend.FilterRule{
				{Name: "prefix", Value: "a/"},
				{Name: "suffix", Value: ".log"},
			},
		},
	}
	if got := loggingFilterSignature(filter); !strings.Contains(got, "prefix=a/") {
		t.Fatalf("loggingFilterSignature unexpected: %q", got)
	}

	if !matchesLoggingFilter("-", filter) {
		t.Fatal("matchesLoggingFilter('-', filter) must be true")
	}
	if !matchesLoggingFilter("a/file.log", filter) {
		t.Fatal("matchesLoggingFilter should match configured prefix/suffix")
	}
	if matchesLoggingFilter("x/file.log", filter) {
		t.Fatal("matchesLoggingFilter should fail prefix mismatch")
	}
	if matchesLoggingFilter("a/file.txt", filter) {
		t.Fatal("matchesLoggingFilter should fail suffix mismatch")
	}

	if !shouldLogJournalOperation("REST.PUT.ACL") {
		t.Fatal("shouldLogJournalOperation(REST.PUT.ACL) should be true")
	}
	if !shouldLogJournalOperation("REST.GET.OBJECT") {
		t.Fatal("shouldLogJournalOperation for object op should be true")
	}
	if shouldLogJournalOperation("REST.GET.BUCKET") {
		t.Fatal("shouldLogJournalOperation for non-object op should be false")
	}
}

func TestLoggingJournalMetadataAndHookDefaultBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "journal-meta")
	mustPutObject(t, b, "journal-meta", "k", "payload")

	if _, err := getObjectVersionForLoggingFn(h, "journal-meta", "k", ""); err != nil {
		t.Fatalf("getObjectVersionForLoggingFn default failed: %v", err)
	}

	t.Run("fallback from specific version to latest", func(t *testing.T) {
		orig := getObjectVersionForLoggingFn
		defer func() { getObjectVersionForLoggingFn = orig }()

		calls := 0
		getObjectVersionForLoggingFn = func(
			_ *Handler,
			_ string,
			_ string,
			versionID string,
		) (*backend.Object, error) {
			calls++
			if versionID != "" {
				return nil, errors.New("version not found")
			}
			return &backend.Object{Size: 7, VersionId: "null", ETag: ""}, nil
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.test/?versionId=v1", nil)
		size, versionID, etag := h.loggingJournalMetadata("journal-meta", "k", req)
		if size != "7" || versionID != "-" || etag != "-" {
			t.Fatalf(
				"loggingJournalMetadata fallback = (%q,%q,%q), want (7,-,-)",
				size,
				versionID,
				etag,
			)
		}
		if calls != 2 {
			t.Fatalf("loggingJournalMetadata fallback calls = %d, want 2", calls)
		}
	})

	t.Run("object lookup failure returns placeholders", func(t *testing.T) {
		orig := getObjectVersionForLoggingFn
		defer func() { getObjectVersionForLoggingFn = orig }()

		getObjectVersionForLoggingFn = func(*Handler, string, string, string) (*backend.Object, error) {
			return nil, errors.New("boom")
		}
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		size, versionID, etag := h.loggingJournalMetadata("journal-meta", "k", req)
		if size != "-" || versionID != "-" || etag != "-" {
			t.Fatalf(
				"loggingJournalMetadata failure = (%q,%q,%q), want (-,-,-)",
				size,
				versionID,
				etag,
			)
		}
	})

	t.Run("returns explicit version and etag", func(t *testing.T) {
		orig := getObjectVersionForLoggingFn
		defer func() { getObjectVersionForLoggingFn = orig }()

		getObjectVersionForLoggingFn = func(*Handler, string, string, string) (*backend.Object, error) {
			return &backend.Object{Size: 9, VersionId: "v2", ETag: "\"etag\""}, nil
		}
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		size, versionID, etag := h.loggingJournalMetadata("journal-meta", "k", req)
		if size != "9" || versionID != "v2" || etag != "\"etag\"" {
			t.Fatalf(
				"loggingJournalMetadata = (%q,%q,%q), want (9,v2,\"etag\")",
				size,
				versionID,
				etag,
			)
		}
	})
}

func TestEmitServerAccessLogJournalBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "journal-src")
	mustCreateBucket(t, b, "journal-dst")
	b.SetBucketOwner("journal-src", "minis3-access-key")
	b.SetBucketOwner("journal-dst", "minis3-access-key")
	mustPutObject(t, b, "journal-src", "allow/k", "v")

	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
		return
	}
	mustPutBucketPolicy(
		t,
		b,
		"journal-dst",
		allowLoggingPolicy("journal-src", "journal-dst", "logs/", owner.ID),
	)
	if err := b.PutBucketLogging("journal-src", &backend.BucketLoggingStatus{
		LoggingEnabled: &backend.LoggingEnabled{
			TargetBucket: "journal-dst",
			TargetPrefix: "logs/",
			LoggingType:  backend.BucketLoggingTypeJournal,
			Filter: &backend.LoggingFilter{
				Key: &backend.LoggingKeyFilter{
					FilterRules: []backend.FilterRule{{
						Name:  "prefix",
						Value: "allow/",
					}},
				},
			},
		},
	}); err != nil {
		t.Fatalf("PutBucketLogging failed: %v", err)
	}

	// Non-object journal operation should be skipped.
	reqBucket := newRequest(
		http.MethodGet,
		"http://example.test/journal-src",
		"",
		map[string]string{"Authorization": authHeader("minis3-access-key")},
	)
	h.emitServerAccessLog(reqBucket, http.StatusOK, 1, "r1", "h1")

	// Filter mismatch should skip entry.
	reqFilteredOut := newRequest(
		http.MethodPut,
		"http://example.test/journal-src/deny/k",
		"v",
		map[string]string{"Authorization": authHeader("minis3-access-key")},
	)
	h.emitServerAccessLog(reqFilteredOut, http.StatusOK, 1, "r2", "h2")

	// Filter match should emit journal line.
	reqMatched := newRequest(
		http.MethodPut,
		"http://example.test/journal-src/allow/k",
		"v",
		map[string]string{"Authorization": authHeader("minis3-access-key")},
	)
	h.emitServerAccessLog(reqMatched, http.StatusOK, 1, "r3", "h3")

	h.loggingMu.Lock()
	defer h.loggingMu.Unlock()
	totalEntries := 0
	for _, batch := range h.pendingLogBatches {
		totalEntries += len(batch.Entries)
	}
	if totalEntries == 0 {
		t.Fatal("expected journal log entry after filter match")
	}
}

func TestFlushLogBatchAndForceFlushErrorBranches(t *testing.T) {
	t.Run("flush if due returns error when batch flush fails", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "flush-src")
		mustCreateBucket(t, b, "flush-dst")
		b.SetBucketOwner("flush-src", "minis3-access-key")
		b.SetBucketOwner("flush-dst", "minis3-access-key")
		if err := b.PutBucketPolicy("flush-dst", `{"Statement":[]}`, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		h.loggingMu.Lock()
		h.pendingLogBatches["flush-if-due-error"] = &serverAccessLogBatch{
			TargetBucket: "flush-dst",
			TargetPrefix: "logs/",
			FirstEventAt: time.Now().UTC().Add(-10 * time.Second),
			Entries: []serverAccessLogEntry{{
				SourceBucket: "flush-src",
				Line:         "line",
			}},
		}
		h.loggingMu.Unlock()

		if err := h.flushServerAccessLogsIfDue("flush-src"); err == nil {
			t.Fatal("flushServerAccessLogsIfDue should return an error")
		}
	})

	t.Run("flush batch PutObject bucket-not-found branch", func(t *testing.T) {
		h, _ := newTestHandler(t)
		_, err := h.flushServerAccessLogBatch(&serverAccessLogBatch{
			TargetBucket: "missing-target",
			TargetPrefix: "logs/",
			Entries: []serverAccessLogEntry{{
				SourceBucket: "",
				Line:         "line",
			}},
		}, time.Now().UTC())
		if err != nil {
			t.Fatalf("flushServerAccessLogBatch bucket-not-found path failed: %v", err)
		}
	})

	t.Run("force flush returns error when underlying flush fails", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "force-src")
		mustCreateBucket(t, b, "force-dst")
		b.SetBucketOwner("force-src", "minis3-access-key")
		b.SetBucketOwner("force-dst", "minis3-access-key")
		if err := b.PutBucketPolicy("force-dst", `{"Statement":[]}`, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		h.loggingMu.Lock()
		h.pendingLogBatches["force-flush-error"] = &serverAccessLogBatch{
			TargetBucket: "force-dst",
			TargetPrefix: "logs/",
			Entries: []serverAccessLogEntry{{
				SourceBucket: "force-src",
				Line:         "line",
			}},
		}
		h.loggingMu.Unlock()

		if _, err := h.forceFlushServerAccessLogs("force-src"); err == nil {
			t.Fatal("forceFlushServerAccessLogs should return an error")
		}
	})
}

func TestMapRequestToLoggingOperationRemainingBranches(t *testing.T) {
	tests := []struct {
		method string
		target string
		key    string
		want   string
	}{
		{
			method: http.MethodDelete,
			target: "http://example.test/bucket",
			key:    "",
			want:   "REST.DELETE.BUCKET",
		},
		{
			method: http.MethodPost,
			target: "http://example.test/bucket/key?restore",
			key:    "key",
			want:   "REST.POST.OBJECT_RESTORE",
		},
		{
			method: http.MethodPut,
			target: "http://example.test/bucket/key?acl",
			key:    "key",
			want:   "REST.PUT.ACL",
		},
		{
			method: http.MethodPut,
			target: "http://example.test/bucket/key?tagging",
			key:    "key",
			want:   "REST.PUT.OBJECT_TAGGING",
		},
		{
			method: http.MethodDelete,
			target: "http://example.test/bucket/key?tagging",
			key:    "key",
			want:   "REST.DELETE.OBJECT_TAGGING",
		},
		{
			method: http.MethodPut,
			target: "http://example.test/bucket/key?legal-hold",
			key:    "key",
			want:   "REST.PUT.LEGAL_HOLD",
		},
		{
			method: http.MethodPut,
			target: "http://example.test/bucket/key?retention",
			key:    "key",
			want:   "REST.PUT.RETENTION",
		},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		if got := mapRequestToLoggingOperation(req, tc.key); got != tc.want {
			t.Fatalf("mapRequestToLoggingOperation(%s,%s) = %q, want %q", tc.method, tc.target, got, tc.want)
		}
	}
}

func TestCheckAccessRemainingBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "access-remain")
	b.SetBucketOwner("access-remain", "minis3-access-key")
	mustPutObject(t, b, "access-remain", "k", "v")

	reqOwner := httptest.NewRequest(http.MethodGet, "http://example.test/access-remain/k", nil)
	reqOwner.Header.Set("Authorization", authHeader("minis3-access-key"))
	reqOther := httptest.NewRequest(http.MethodGet, "http://example.test/access-remain/k", nil)
	reqOther.Header.Set("Authorization", authHeader("tenant-access-key"))

	t.Run("allow statement mismatch denies before ACL fallback", func(t *testing.T) {
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::access-remain/*","Condition":{"StringEquals":{"aws:SourceIp":"192.0.2.1"}}}]}`
		if err := b.PutBucketPolicy("access-remain", policy, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
		if err := b.PutBucketACL("access-remain", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		if h.checkAccess(reqOther, "access-remain", "s3:GetObject", "k") {
			t.Fatal("checkAccess should deny when allow statement exists but conditions do not match")
		}
	})

	t.Run("GetObjectAcl and PutObjectAcl fallback bucket ACL errors", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-remain"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:GetObjectAcl", "k") {
			t.Fatal("GetObjectAcl should be denied when bucket ACL fallback fails")
		}
		if h.checkAccess(reqOther, "access-remain", "s3:PutObjectAcl", "k") {
			t.Fatal("PutObjectAcl should be denied when bucket ACL fallback fails")
		}
	})

	t.Run("GetObjectTagging branches", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-remain"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		if h.checkAccess(reqOther, "access-remain", "s3:GetObjectTagging", "") {
			t.Fatal("GetObjectTagging with empty key should be denied")
		}

		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:GetObjectTagging", "k") {
			t.Fatal("GetObjectTagging should be denied when fallback bucket ACL lookup fails")
		}
	})

	t.Run("GetObjectTagging fallback allows read and non-notfound denies", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-remain"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return backend.CannedACLToPolicy("public-read"), nil
			},
		)
		if !h.checkAccess(reqOther, "access-remain", "s3:GetObjectTagging", "k") {
			t.Fatal("GetObjectTagging should allow when fallback bucket ACL grants read")
		}

		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("other object acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:GetObjectTagging", "k") {
			t.Fatal("GetObjectTagging should deny on non-notfound object ACL errors")
		}
	})

	t.Run("RestoreObject branches", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-remain"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		if h.checkAccess(reqOther, "access-remain", "s3:RestoreObject", "") {
			t.Fatal("RestoreObject with empty key should be denied")
		}

		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:RestoreObject", "k") {
			t.Fatal("RestoreObject should deny when bucket ACL lookup fails")
		}

		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return backend.CannedACLToPolicy("public-read-write"), nil
			},
		)
		if !h.checkAccess(reqOther, "access-remain", "s3:RestoreObject", "k") {
			t.Fatal("RestoreObject should allow when bucket ACL grants write")
		}
	})

	t.Run("delete/tagging write branches", func(t *testing.T) {
		if err := b.DeleteBucketPolicy("access-remain"); err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}
		if h.checkAccess(reqOther, "access-remain", "s3:DeleteObject", "") {
			t.Fatal("DeleteObject with empty key should be denied")
		}

		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("bucket acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:DeleteObject", "k") {
			t.Fatal("DeleteObject should deny when fallback bucket ACL lookup fails")
		}

		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, backend.ErrObjectNotFound
			},
		)
		patchBucketACLForAccessCheckForTest(
			t,
			func(*Handler, string) (*backend.AccessControlPolicy, error) {
				return backend.CannedACLToPolicy("public-read-write"), nil
			},
		)
		if !h.checkAccess(reqOther, "access-remain", "s3:DeleteObject", "k") {
			t.Fatal("DeleteObject should allow when fallback bucket ACL grants write")
		}

		patchObjectACLForAccessCheckForTest(
			t,
			func(*Handler, string, string, string) (*backend.AccessControlPolicy, error) {
				return nil, errors.New("object acl error")
			},
		)
		if h.checkAccess(reqOther, "access-remain", "s3:DeleteObject", "k") {
			t.Fatal("DeleteObject should deny on non-notfound object ACL errors")
		}
	})
}

func TestCheckAccessWithContextRestrictPublicBucketsBranch(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "ctx-restrict")
	b.SetBucketOwner("ctx-restrict", "minis3-access-key")
	if err := b.PutBucketPolicy(
		"ctx-restrict",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::ctx-restrict/*"}]}`,
		false,
	); err != nil {
		t.Fatalf("PutBucketPolicy failed: %v", err)
	}
	if err := b.PutPublicAccessBlock("ctx-restrict", &backend.PublicAccessBlockConfiguration{
		RestrictPublicBuckets: true,
	}); err != nil {
		t.Fatalf("PutPublicAccessBlock failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/ctx-restrict/k", nil)
	req.Header.Set("Authorization", authHeader("tenant-access-key"))
	if h.checkAccessWithContext(req, "ctx-restrict", "s3:GetObject", "k", backend.PolicyEvalContext{}) {
		t.Fatal("checkAccessWithContext should deny non-owner access with RestrictPublicBuckets")
	}
}

func TestBucketPolicyOwnerDenyExemptionBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "deny-owner-exempt")
	b.SetBucketOwner("deny-owner-exempt", "minis3-access-key")

	denyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:GetBucketPolicy","s3:PutBucketPolicy","s3:DeleteBucketPolicy"],"Resource":"arn:aws:s3:::deny-owner-exempt"}]}`
	if err := b.PutBucketPolicy("deny-owner-exempt", denyPolicy, false); err != nil {
		t.Fatalf("PutBucketPolicy failed: %v", err)
	}

	ownerReq := httptest.NewRequest(http.MethodGet, "http://example.test/deny-owner-exempt?policy", nil)
	ownerReq.Header.Set("Authorization", authHeader("minis3-access-key"))

	if !h.checkAccess(ownerReq, "deny-owner-exempt", "s3:GetBucketPolicy", "") {
		t.Fatal("checkAccess should allow bucket owner for policy management deny exemption")
	}
	if !h.checkAccessWithContext(
		ownerReq,
		"deny-owner-exempt",
		"s3:GetBucketPolicy",
		"",
		backend.PolicyEvalContext{},
	) {
		t.Fatal(
			"checkAccessWithContext should allow bucket owner for policy management deny exemption",
		)
	}
}

func TestACLFromGrantHeadersOwnerNilBranch(t *testing.T) {
	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
		return
	}
	req := httptest.NewRequest(http.MethodPut, "http://example.test/b", nil)
	req.Header.Set("x-amz-grant-read", "id="+owner.ID)
	acl, err := aclFromGrantHeaders(req, nil)
	if err != nil {
		t.Fatalf("aclFromGrantHeaders failed: %+v", err)
	}
	if acl == nil || acl.Owner == nil {
		t.Fatalf("aclFromGrantHeaders returned nil ACL/owner: %+v", acl)
	}
}

func TestUploadPartCopyRemainingBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-remain")
	mustPutObject(t, b, "src-remain", "src", "source-data")
	if err := b.PutObjectACL("src-remain", "src", "", backend.CannedACLToPolicy("public-read")); err != nil {
		t.Fatalf("PutObjectACL failed: %v", err)
	}
	mustPublicWriteBucket(t, b, "dst-remain", "dst-owner")

	t.Run("validateSSEHeaders rejection", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-remain",
			"sse-invalid",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-remain/sse-invalid?uploadId="+url.QueryEscape(uploadID)+"&partNumber=1",
				"",
				map[string]string{
					"Authorization":                authHeader("dst-owner"),
					"x-amz-copy-source":            "/src-remain/src",
					"x-amz-server-side-encryption": "invalid",
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
	})

	t.Run("validateMultipartSSECustomerHeaders rejection", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-remain",
			"dest-ssec",
			map[string]string{
				"Authorization": authHeader("dst-owner"),
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
				"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-remain/dest-ssec?uploadId="+url.QueryEscape(uploadID)+"&partNumber=1",
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-remain/src",
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
	})

	t.Run("validateCopySourceSSECustomerHeaders rejection", func(t *testing.T) {
		if _, err := b.PutObject(
			"src-remain",
			"src-ssec",
			[]byte("source-data"),
			backend.PutObjectOptions{
				SSECustomerAlgorithm: "AES256",
				SSECustomerKeyMD5:    "abc",
			},
		); err != nil {
			t.Fatalf("PutObject src-ssec failed: %v", err)
		}
		if err := b.PutObjectACL(
			"src-remain",
			"src-ssec",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL src-ssec failed: %v", err)
		}
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-remain",
			"ssec-source",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-remain/ssec-source?uploadId="+url.QueryEscape(uploadID)+"&partNumber=1",
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-remain/src-ssec",
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
	})

	t.Run("copyPart source bucket not found mapping", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-remain",
			"source-bucket-missing",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		origCopyPart := copyPartFn
		copyPartFn = func(
			*Handler,
			string,
			string,
			string,
			string,
			string,
			string,
			int,
			int64,
			int64,
		) (*backend.PartInfo, error) {
			return nil, backend.ErrSourceBucketNotFound
		}
		t.Cleanup(func() {
			copyPartFn = origCopyPart
		})

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-remain/source-bucket-missing?uploadId="+
					url.QueryEscape(uploadID)+"&partNumber=1",
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-remain/src",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("copyPart source object not found mapping", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"dst-remain",
			"source-object-missing",
			map[string]string{"Authorization": authHeader("dst-owner")},
		)
		origCopyPart := copyPartFn
		copyPartFn = func(
			*Handler,
			string,
			string,
			string,
			string,
			string,
			string,
			int,
			int64,
			int64,
		) (*backend.PartInfo, error) {
			return nil, backend.ErrSourceObjectNotFound
		}
		t.Cleanup(func() {
			copyPartFn = origCopyPart
		})

		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst-remain/source-object-missing?uploadId="+
					url.QueryEscape(uploadID)+"&partNumber=1",
				"",
				map[string]string{
					"Authorization":     authHeader("dst-owner"),
					"x-amz-copy-source": "/src-remain/src",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})
}

func TestObjectRemainingBranches(t *testing.T) {
	t.Run("setRestoreHeader ongoing", func(t *testing.T) {
		w := httptest.NewRecorder()
		expiry := time.Now().UTC().Add(24 * time.Hour)
		setRestoreHeader(w, &backend.Object{
			RestoreExpiryDate: &expiry,
			RestoreOngoing:    true,
		})
		if got := w.Header().Get("x-amz-restore"); got != `ongoing-request="true"` {
			t.Fatalf("x-amz-restore = %q, want ongoing true", got)
		}
	})

	t.Run("containsUnreadableURIKeyRune detects control characters", func(t *testing.T) {
		if !containsUnreadableURIKeyRune("bad\x00key") {
			t.Fatal("containsUnreadableURIKeyRune should detect control character")
		}
	})

	t.Run("handleObject invalid URI and flush error path", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-remain")
		b.SetBucketOwner("obj-remain", "minis3-access-key")

		wInvalid := httptest.NewRecorder()
		h.handleObject(
			wInvalid,
			httptest.NewRequest(http.MethodGet, "http://example.test/obj-remain/ignored", nil),
			"obj-remain",
			"bad\x00key",
		)
		requireStatus(t, wInvalid, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalid, "InvalidURI")

		mustCreateBucket(t, b, "obj-remain-log-target")
		b.SetBucketOwner("obj-remain-log-target", "minis3-access-key")
		if err := b.PutBucketPolicy("obj-remain-log-target", `{"Statement":[]}`, false); err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}
		h.loggingMu.Lock()
		h.pendingLogBatches["obj-put-flush-error"] = &serverAccessLogBatch{
			TargetBucket: "obj-remain-log-target",
			TargetPrefix: "logs/",
			FirstEventAt: time.Now().UTC().Add(-time.Minute),
			Entries: []serverAccessLogEntry{{
				SourceBucket: "obj-remain",
				Line:         "line",
			}},
		}
		h.loggingMu.Unlock()

		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj-remain/k",
				"payload",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPut, http.StatusForbidden)
		requireS3ErrorCode(t, wPut, "AccessDenied")
	})

	t.Run("archived object without read-through returns forbidden invalid state", func(t *testing.T) {
		t.Setenv("MINIS3_CLOUD_ALLOW_READ_THROUGH", "false")
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-archive")
		b.SetBucketOwner("obj-archive", "minis3-access-key")
		if _, err := b.PutObject(
			"obj-archive",
			"cold",
			[]byte("payload"),
			backend.PutObjectOptions{StorageClass: "GLACIER"},
		); err != nil {
			t.Fatalf("PutObject GLACIER failed: %v", err)
		}

		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj-archive/cold",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "InvalidObjectState")
	})

	t.Run("restore object access denied and read/internal errors", func(t *testing.T) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, "obj-restore-remain")
		b.SetBucketOwner("obj-restore-remain", "minis3-access-key")
		if _, err := b.PutObject(
			"obj-restore-remain",
			"cold",
			[]byte("payload"),
			backend.PutObjectOptions{StorageClass: "GLACIER"},
		); err != nil {
			t.Fatalf("PutObject GLACIER failed: %v", err)
		}

		wDenied := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/obj-restore-remain/cold?restore",
				"",
				nil,
			),
		)
		requireStatus(t, wDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wDenied, "AccessDenied")

		reqReadErr := newRequest(
			http.MethodPost,
			"http://example.test/obj-restore-remain/cold?restore",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		reqReadErr.Body = io.NopCloser(failingReader{})
		wReadErr := doRequest(h, reqReadErr)
		requireStatus(t, wReadErr, http.StatusInternalServerError)
		requireS3ErrorCode(t, wReadErr, "InternalError")

		origRestore := restoreObjectFn
		restoreObjectFn = func(*Handler, string, string, string, int) (*backend.RestoreObjectResult, error) {
			return nil, errors.New("restore boom")
		}
		t.Cleanup(func() {
			restoreObjectFn = origRestore
		})
		wInternal := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/obj-restore-remain/cold?restore",
				"<RestoreRequest><Days>2</Days></RestoreRequest>",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wInternal, http.StatusInternalServerError)
		requireS3ErrorCode(t, wInternal, "InternalError")
	})
}
