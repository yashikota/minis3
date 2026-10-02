package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

// TestExpectedBucketOwnerUsesRealOwner verifies that x-amz-expected-bucket-owner
// is compared against the actual bucket owner instead of only DefaultOwner.
func TestExpectedBucketOwnerUsesRealOwner(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "expowner-alt")
	b.SetBucketOwner("expowner-alt", "minis3-alt-access-key")

	altOwnerID := backend.OwnerForAccessKey("minis3-alt-access-key").ID
	defaultOwnerID := backend.DefaultOwner().ID
	if altOwnerID == defaultOwnerID {
		t.Fatalf(
			"test precondition failed: alt owner %q must differ from default %q",
			altOwnerID,
			defaultOwnerID,
		)
	}

	t.Run("correct owner id passes for bucket op", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/expowner-alt", "", map[string]string{
			"Authorization":               authHeader("minis3-alt-access-key"),
			"x-amz-expected-bucket-owner": altOwnerID,
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("wrong owner id denied for bucket op", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/expowner-alt", "", map[string]string{
			"Authorization":               authHeader("minis3-alt-access-key"),
			"x-amz-expected-bucket-owner": "mismatch",
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("default owner id denied for alt-owned bucket", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/expowner-alt", "", map[string]string{
			"Authorization":               authHeader("minis3-alt-access-key"),
			"x-amz-expected-bucket-owner": defaultOwnerID,
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("correct owner id passes for object op", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/expowner-alt/key",
			"hello",
			map[string]string{
				"Authorization":               authHeader("minis3-alt-access-key"),
				"x-amz-expected-bucket-owner": altOwnerID,
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("wrong owner id denied for object op", func(t *testing.T) {
		req := newRequest(
			http.MethodPut,
			"http://example.test/expowner-alt/key2",
			"hello",
			map[string]string{
				"Authorization":               authHeader("minis3-alt-access-key"),
				"x-amz-expected-bucket-owner": "mismatch",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("missing bucket falls back to default owner", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/expowner-missing",
			"",
			map[string]string{
				"x-amz-expected-bucket-owner": defaultOwnerID,
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("missing bucket with mismatch denied", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/expowner-missing",
			"",
			map[string]string{
				"x-amz-expected-bucket-owner": "mismatch",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("service level ignores expected owner", func(t *testing.T) {
		req := newRequest(http.MethodGet, "http://example.test/", "", map[string]string{
			"x-amz-expected-bucket-owner": "mismatch",
		})
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})
}
