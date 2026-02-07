package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestPutObjectSetsLifecycleExpirationHeader(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "lifecycle-header-put")

	cfg := &backend.LifecycleConfiguration{
		Rules: []backend.LifecycleRule{
			{
				ID:     "rule1",
				Status: backend.LifecycleStatusEnabled,
				Prefix: "days1/",
				Expiration: &backend.LifecycleExpiration{
					Days: 1,
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-header-put", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	req := newRequest(
		http.MethodPut,
		"http://example.test/lifecycle-header-put/days1/foo",
		"bar",
		map[string]string{"Authorization": authHeader("minis3-access-key")},
	)
	w := doRequest(h, req)
	requireStatus(t, w, http.StatusOK)

	exp := w.Header().Get("x-amz-expiration")
	if exp == "" {
		t.Fatal("expected x-amz-expiration header to be set")
	}
	if !strings.Contains(exp, `rule-id="rule1"`) {
		t.Fatalf("unexpected x-amz-expiration header: %q", exp)
	}
}

func TestHeadObjectLifecycleExpirationHeaderRespectsTagFilter(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "lifecycle-header-head")
	if _, err := b.PutObject(
		"lifecycle-header-head",
		"obj",
		[]byte("body"),
		backend.PutObjectOptions{
			Tags: map[string]string{"key1": "tag1", "key5": "tag5"},
		},
	); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	matching := &backend.LifecycleConfiguration{
		Rules: []backend.LifecycleRule{
			{
				ID:     "rule1",
				Status: backend.LifecycleStatusEnabled,
				Expiration: &backend.LifecycleExpiration{
					Days: 1,
				},
				Filter: &backend.LifecycleFilter{
					Tag: &backend.Tag{Key: "key1", Value: "tag1"},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-header-head", matching); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration matching failed: %v", err)
	}
	obj, err := b.GetObject("lifecycle-header-head", "obj")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	cfg, err := b.GetBucketLifecycleConfiguration("lifecycle-header-head")
	if err != nil {
		t.Fatalf("GetBucketLifecycleConfiguration failed: %v", err)
	}
	if ruleID, _, ok := findLifecycleExpirationForObject(cfg, "obj", obj); !ok ||
		ruleID != "rule1" {
		t.Fatalf("expected lifecycle match for rule1, got ok=%v ruleID=%q", ok, ruleID)
	}

	wMatch := doRequest(
		h,
		newRequest(
			http.MethodHead,
			"http://example.test/lifecycle-header-head/obj",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wMatch, http.StatusOK)
	if exp := wMatch.Header().Get("x-amz-expiration"); exp == "" {
		t.Fatalf(
			"expected x-amz-expiration header for matching tag filter, headers=%v",
			wMatch.Header(),
		)
	}

	nonMatching := &backend.LifecycleConfiguration{
		Rules: []backend.LifecycleRule{
			{
				ID:     "rule1",
				Status: backend.LifecycleStatusEnabled,
				Expiration: &backend.LifecycleExpiration{
					Days: 1,
				},
				Filter: &backend.LifecycleFilter{
					Tag: &backend.Tag{Key: "key2", Value: "tag1"},
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-header-head", nonMatching); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration non-matching failed: %v", err)
	}

	wNoMatch := doRequest(
		h,
		newRequest(
			http.MethodHead,
			"http://example.test/lifecycle-header-head/obj",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wNoMatch, http.StatusOK)
	if exp := wNoMatch.Header().Get("x-amz-expiration"); exp != "" {
		t.Fatalf("expected no x-amz-expiration header for non-matching filter, got %q", exp)
	}
}

func TestLifecycleHeaderHelperBranches(t *testing.T) {
	t.Run("lifecycleExpiryDate branches", func(t *testing.T) {
		base := time.Date(2026, 2, 7, 12, 0, 0, 0, time.UTC)

		if _, ok := lifecycleExpiryDate(nil, base); ok {
			t.Fatal("nil expiration must not produce expiry date")
		}

		if got, ok := lifecycleExpiryDate(&backend.LifecycleExpiration{Days: 2}, base); !ok {
			t.Fatal("days-based expiration should be valid")
		} else {
			want := base.AddDate(0, 0, 2).Add(time.Second)
			if !got.Equal(want) {
				t.Fatalf("days expiry = %v, want %v", got, want)
			}
		}

		if got, ok := lifecycleExpiryDate(&backend.LifecycleExpiration{Date: "2026-03-01"}, base); !ok {
			t.Fatal("date-based expiration should be valid")
		} else if got.UTC().Format("2006-01-02") != "2026-03-01" {
			t.Fatalf("date expiry = %v, want 2026-03-01", got)
		}

		if _, ok := lifecycleExpiryDate(&backend.LifecycleExpiration{Date: "bad-date"}, base); ok {
			t.Fatal("invalid date must not produce expiry date")
		}

		if _, ok := lifecycleExpiryDate(&backend.LifecycleExpiration{}, base); ok {
			t.Fatal("empty expiration must not produce expiry date")
		}
	})

	t.Run("lifecycleRuleMatchesObjectForHeader branches", func(t *testing.T) {
		obj := &backend.Object{
			Size: 10,
			Tags: map[string]string{"k1": "v1", "k2": "v2"},
		}

		if lifecycleRuleMatchesObjectForHeader(backend.LifecycleRule{}, "a/b", nil) {
			t.Fatal("nil object must not match")
		}
		if !lifecycleRuleMatchesObjectForHeader(backend.LifecycleRule{}, "a/b", obj) {
			t.Fatal("rule without filter should match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{Prefix: "x/"},
			"a/b",
			obj,
		) {
			t.Fatal("prefix mismatch should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{Prefix: "x/"},
			},
			"a/b",
			obj,
		) {
			t.Fatal("filter prefix mismatch should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{ObjectSizeGreaterThan: 10},
			},
			"a/b",
			obj,
		) {
			t.Fatal("greater-than size boundary should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{ObjectSizeLessThan: 10},
			},
			"a/b",
			obj,
		) {
			t.Fatal("less-than size boundary should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{Tag: &backend.Tag{Key: "k1", Value: "wrong"}},
			},
			"a/b",
			obj,
		) {
			t.Fatal("tag mismatch should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{
					And: &backend.LifecycleFilterAnd{Prefix: "x/"},
				},
			},
			"a/b",
			obj,
		) {
			t.Fatal("and prefix mismatch should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{
					And: &backend.LifecycleFilterAnd{ObjectSizeGreaterThan: 10},
				},
			},
			"a/b",
			obj,
		) {
			t.Fatal("and size mismatch should not match")
		}
		if lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Filter: &backend.LifecycleFilter{
					And: &backend.LifecycleFilterAnd{
						Tags: []backend.Tag{{Key: "k1", Value: "v1"}, {Key: "k2", Value: "nope"}},
					},
				},
			},
			"a/b",
			obj,
		) {
			t.Fatal("and tag mismatch should not match")
		}
		if !lifecycleRuleMatchesObjectForHeader(
			backend.LifecycleRule{
				Prefix: "a/",
				Filter: &backend.LifecycleFilter{
					Prefix: "a/",
					Tag:    &backend.Tag{Key: "k1", Value: "v1"},
					And: &backend.LifecycleFilterAnd{
						Prefix: "a/",
						Tags: []backend.Tag{
							{Key: "k1", Value: "v1"},
							{Key: "k2", Value: "v2"},
						},
						ObjectSizeGreaterThan: 1,
						ObjectSizeLessThan:    100,
					},
				},
			},
			"a/b",
			obj,
		) {
			t.Fatal("fully matching rule should match")
		}
	})

	t.Run("tag and size helper branches", func(t *testing.T) {
		tag := backend.Tag{Key: "k", Value: "v"}
		if lifecycleObjectHasTagForHeader(nil, tag) {
			t.Fatal("nil object must not match tag")
		}
		if lifecycleObjectHasTagForHeader(&backend.Object{}, tag) {
			t.Fatal("object without tags must not match tag")
		}
		if lifecycleObjectHasTagForHeader(
			&backend.Object{Tags: map[string]string{"k": "v"}},
			backend.Tag{},
		) {
			t.Fatal("empty tag key must not match")
		}
		if lifecycleObjectHasTagForHeader(
			&backend.Object{Tags: map[string]string{"x": "v"}},
			tag,
		) {
			t.Fatal("missing key must not match")
		}
		if !lifecycleObjectHasTagForHeader(
			&backend.Object{Tags: map[string]string{"k": "v"}},
			tag,
		) {
			t.Fatal("matching key/value should match")
		}

		if lifecycleObjectSizeMatchForHeader(10, 10, 0) {
			t.Fatal("greater-than boundary should fail")
		}
		if lifecycleObjectSizeMatchForHeader(10, 0, 10) {
			t.Fatal("less-than boundary should fail")
		}
		if !lifecycleObjectSizeMatchForHeader(10, 1, 100) {
			t.Fatal("size within boundaries should match")
		}
	})

	t.Run("findLifecycleExpirationForObject branches", func(t *testing.T) {
		base := time.Date(2026, 2, 7, 12, 0, 0, 0, time.UTC)
		obj := &backend.Object{
			Size:         10,
			Tags:         map[string]string{"k1": "v1"},
			LastModified: base,
		}

		if _, _, ok := findLifecycleExpirationForObject(nil, "obj", obj); ok {
			t.Fatal("nil config must not match")
		}
		cfg := &backend.LifecycleConfiguration{
			Rules: []backend.LifecycleRule{
				{
					ID:         "disabled",
					Status:     backend.LifecycleStatusDisabled,
					Expiration: &backend.LifecycleExpiration{Days: 1},
				},
				{ID: "noexp", Status: backend.LifecycleStatusEnabled},
				{
					ID:         "bad-date",
					Status:     backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{Date: "not-a-date"},
				},
				{
					ID:         "match",
					Status:     backend.LifecycleStatusEnabled,
					Expiration: &backend.LifecycleExpiration{Days: 1},
				},
			},
		}
		if _, _, ok := findLifecycleExpirationForObject(cfg, "obj", nil); ok {
			t.Fatal("nil object must not match")
		}

		ruleID, _, ok := findLifecycleExpirationForObject(cfg, "obj", obj)
		if !ok || ruleID != "match" {
			t.Fatalf("expected final matching rule, got ok=%v ruleID=%q", ok, ruleID)
		}
	})
}
