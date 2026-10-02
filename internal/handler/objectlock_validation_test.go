package handler

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestPutObjectObjectLockValidation(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-bucket")
	b.SetBucketOwner("lock-bucket", "minis3-access-key")

	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name       string
		mode       string
		date       string
		withDate   bool
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid mode FOO",
			mode:       "FOO",
			date:       future,
			withDate:   true,
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidRequest",
		},
		{
			name:       "mode without date",
			mode:       backend.RetentionModeGovernance,
			withDate:   false,
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidRequest",
		},
		{
			name:       "unparsable date",
			mode:       backend.RetentionModeGovernance,
			date:       "not-a-date",
			withDate:   true,
			wantStatus: http.StatusBadRequest,
			wantCode:   "InvalidArgument",
		},
		{
			name:       "governance success",
			mode:       backend.RetentionModeGovernance,
			date:       future,
			withDate:   true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "compliance success",
			mode:       backend.RetentionModeCompliance,
			date:       future,
			withDate:   true,
			wantStatus: http.StatusOK,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{
				"Authorization": authHeader("minis3-access-key"),
			}
			if tc.mode != "" {
				headers["x-amz-object-lock-mode"] = tc.mode
			}
			if tc.withDate {
				headers["x-amz-object-lock-retain-until-date"] = tc.date
			}
			key := fmt.Sprintf("put-validation-%d", i)
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/lock-bucket/"+key, "data", headers),
			)
			requireStatus(t, w, tc.wantStatus)
			if tc.wantCode != "" {
				requireS3ErrorCode(t, w, tc.wantCode)
			}
		})
	}
}

func TestCreateMultipartObjectLockValidation(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-mpu")
	b.SetBucketOwner("lock-mpu", "minis3-access-key")

	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name       string
		mode       string
		date       string
		withDate   bool
		wantStatus int
		wantCode   string
	}{
		{"invalid mode FOO", "FOO", future, true, http.StatusBadRequest, "InvalidRequest"},
		{
			"mode without date",
			backend.RetentionModeGovernance,
			"",
			false,
			http.StatusBadRequest,
			"InvalidRequest",
		},
		{
			"unparsable date",
			backend.RetentionModeGovernance,
			"not-a-date",
			true,
			http.StatusBadRequest,
			"InvalidArgument",
		},
		{
			"governance success",
			backend.RetentionModeGovernance,
			future,
			true,
			http.StatusOK,
			"",
		},
		{
			"compliance success",
			backend.RetentionModeCompliance,
			future,
			true,
			http.StatusOK,
			"",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{
				"Authorization": authHeader("minis3-access-key"),
			}
			if tc.mode != "" {
				headers["x-amz-object-lock-mode"] = tc.mode
			}
			if tc.withDate {
				headers["x-amz-object-lock-retain-until-date"] = tc.date
			}
			key := fmt.Sprintf("mpu-validation-%d", i)
			w := doRequest(
				h,
				newRequest(http.MethodPost, "http://example.test/lock-mpu/"+key+"?uploads", "", headers),
			)
			requireStatus(t, w, tc.wantStatus)
			if tc.wantCode != "" {
				requireS3ErrorCode(t, w, tc.wantCode)
			}
		})
	}
}

func TestCopyObjectObjectLockValidation(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "lock-src")
	mustCreateObjectLockBucket(t, b, "lock-dst")
	b.SetBucketOwner("lock-src", "minis3-access-key")
	b.SetBucketOwner("lock-dst", "minis3-access-key")
	mustPutObject(t, b, "lock-src", "src", "data")

	future := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)

	cases := []struct {
		name       string
		mode       string
		date       string
		withDate   bool
		wantStatus int
		wantCode   string
	}{
		{"invalid mode FOO", "FOO", future, true, http.StatusBadRequest, "InvalidRequest"},
		{
			"mode without date",
			backend.RetentionModeGovernance,
			"",
			false,
			http.StatusBadRequest,
			"InvalidRequest",
		},
		{
			"unparsable date",
			backend.RetentionModeGovernance,
			"not-a-date",
			true,
			http.StatusBadRequest,
			"InvalidArgument",
		},
		{
			"governance success",
			backend.RetentionModeGovernance,
			future,
			true,
			http.StatusOK,
			"",
		},
		{
			"compliance success",
			backend.RetentionModeCompliance,
			future,
			true,
			http.StatusOK,
			"",
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{
				"Authorization":     authHeader("minis3-access-key"),
				"x-amz-copy-source": "/lock-src/src",
			}
			if tc.mode != "" {
				headers["x-amz-object-lock-mode"] = tc.mode
			}
			if tc.withDate {
				headers["x-amz-object-lock-retain-until-date"] = tc.date
			}
			key := fmt.Sprintf("copy-validation-%d", i)
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/lock-dst/"+key, "", headers),
			)
			requireStatus(t, w, tc.wantStatus)
			if tc.wantCode != "" {
				requireS3ErrorCode(t, w, tc.wantCode)
			}
		})
	}
}
