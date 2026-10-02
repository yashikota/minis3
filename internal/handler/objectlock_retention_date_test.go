package handler

import (
	"fmt"
	"net/http"
	"testing"
)

func TestPutObjectRetentionDateFormatsBranch(t *testing.T) {
	validDates := []string{
		"2030-06-01T00:00:00Z",
		"2030-06-01T00:00:00.000Z",
		"2030-06-01T00:00:00.123Z",
		"2030-06-01T00:00:00.123456789Z",
		"2030-06-01T00:00:00+00:00",
		"2030-06-01T09:00:00+09:00",
	}

	for _, date := range validDates {
		t.Run("valid/"+date, func(t *testing.T) {
			h, b := newTestHandler(t)
			mustCreateObjectLockBucket(t, b, "retdate-bucket")
			mustPutObject(t, b, "retdate-bucket", "obj", "data")
			payload := fmt.Sprintf(
				`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
				date,
			)
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/retdate-bucket/obj?retention", payload, nil),
			)
			requireStatus(t, w, http.StatusOK)
		})
	}

	invalidDates := []string{
		"invalid-date",
		"2030-13-01T00:00:00Z",
		"2030-01-01",
		"tomorrow",
	}

	for _, date := range invalidDates {
		t.Run("invalid/"+date, func(t *testing.T) {
			h, b := newTestHandler(t)
			mustCreateObjectLockBucket(t, b, "retdate-bucket")
			mustPutObject(t, b, "retdate-bucket", "obj", "data")
			payload := fmt.Sprintf(
				`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
				date,
			)
			w := doRequest(
				h,
				newRequest(http.MethodPut, "http://example.test/retdate-bucket/obj?retention", payload, nil),
			)
			requireStatus(t, w, http.StatusBadRequest)
			requireS3ErrorCode(t, w, "InvalidRequest")
		})
	}
}
