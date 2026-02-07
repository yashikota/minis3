package handler

import (
	"net/http"
	"strings"
	"testing"

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
