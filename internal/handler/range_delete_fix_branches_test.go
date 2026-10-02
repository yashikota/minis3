package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestParseRangeHeaderZeroSize(t *testing.T) {
	for _, header := range []string{"bytes=-1", "bytes=0-", "bytes=0-0"} {
		if _, _, err := parseRangeHeader(header, 0); err == nil {
			t.Fatalf("parseRangeHeader(%q, 0) should fail", header)
		}
	}
}

func TestGetEmptyObjectRangeReturns416(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "range-zero")
	mustPutObject(t, b, "range-zero", "empty", "")

	for _, header := range []string{"bytes=-1", "bytes=0-"} {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/range-zero/empty",
				"",
				map[string]string{"Range": header},
			),
		)
		requireStatus(t, w, http.StatusRequestedRangeNotSatisfiable)
		requireS3ErrorCode(t, w, "InvalidRange")
	}
}

func TestDeleteNonexistentKeyWithVersionIdReturns204(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "delete-missing-versioned")
	if err := b.SetBucketVersioning(
		"delete-missing-versioned",
		backend.VersioningEnabled,
		backend.MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning failed: %v", err)
	}

	w := doRequest(
		h,
		newRequest(
			http.MethodDelete,
			"http://example.test/delete-missing-versioned/missing?versionId=some-version-id",
			"",
			nil,
		),
	)
	requireStatus(t, w, http.StatusNoContent)
}
