package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestHandleRequestAppliesLifecycleOnInterval(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "lifecycle-interval")
	mustPutObject(t, b, "lifecycle-interval", "past/foo", "data")

	cfg := &backend.LifecycleConfiguration{
		Rules: []backend.LifecycleRule{
			{
				ID:     "rule1",
				Status: backend.LifecycleStatusEnabled,
				Prefix: "past/",
				Expiration: &backend.LifecycleExpiration{
					Date: "2015-01-01",
				},
			},
		},
	}
	if err := b.PutBucketLifecycleConfiguration("lifecycle-interval", cfg); err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
	}

	h.lifecycleMu.Lock()
	h.lastLifecycleApply = time.Now().UTC()
	h.lifecycleMu.Unlock()

	wNotDue := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/lifecycle-interval",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wNotDue, http.StatusOK)
	if _, err := b.GetObject("lifecycle-interval", "past/foo"); err != nil {
		t.Fatalf("expected object to remain before interval elapses, got %v", err)
	}

	h.lifecycleMu.Lock()
	h.lastLifecycleApply = time.Now().UTC().Add(-11 * time.Second)
	h.lifecycleMu.Unlock()

	wDue := doRequest(
		h,
		newRequest(
			http.MethodGet,
			"http://example.test/lifecycle-interval",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, wDue, http.StatusOK)
	if _, err := b.GetObject("lifecycle-interval", "past/foo"); err == nil {
		t.Fatal("expected object to be expired after interval elapsed")
	}
}
