package backend

import (
	"errors"
	"testing"
	"time"
)

func TestParseRetainUntilDateFormats(t *testing.T) {
	valid := []string{
		// RFC3339 (SDK default) and plain Zulu.
		"2030-01-02T15:04:05Z",
		"2030-01-02T15:04:05+00:00",
		"2030-01-02T15:04:05+09:00",
		// RFC3339Nano (fractional seconds with offset/Zulu).
		"2030-01-02T15:04:05.123456789Z",
		"2030-01-02T15:04:05.123456789+00:00",
		// Millisecond Zulu variant seen in the wild.
		"2030-01-02T15:04:05.000Z",
		"2030-01-02T15:04:05.123Z",
	}

	for _, input := range valid {
		t.Run(input, func(t *testing.T) {
			got, err := ParseRetainUntilDate(input)
			if err != nil {
				t.Fatalf("ParseRetainUntilDate(%q) failed: %v", input, err)
			}
			if got.IsZero() {
				t.Fatalf("ParseRetainUntilDate(%q) returned zero time", input)
			}
		})
	}

	invalid := []string{
		"invalid-date",
		"2030-13-01T00:00:00Z",
		"2030-01-01",
		"01/02/2030",
		"2030-01-02 15:04:05",
		"",
	}

	for _, input := range invalid {
		t.Run("invalid/"+input, func(t *testing.T) {
			if _, err := ParseRetainUntilDate(input); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ParseRetainUntilDate(%q) = %v, want ErrInvalidRequest", input, err)
			}
		})
	}
}

func TestPutObjectRetentionRetainUntilDateFormats(t *testing.T) {
	validDates := []string{
		"2030-06-01T00:00:00Z",           // RFC3339 / plain Zulu
		"2030-06-01T00:00:00.000Z",       // millisecond Zulu
		"2030-06-01T00:00:00.123Z",       // millisecond Zulu with millis
		"2030-06-01T00:00:00.123456789Z", // RFC3339Nano
		"2030-06-01T00:00:00+00:00",      // numeric offset
		"2030-06-01T09:00:00+09:00",      // non-UTC offset
	}

	for _, date := range validDates {
		t.Run("valid/"+date, func(t *testing.T) {
			b := New()
			if err := b.CreateBucketWithObjectLock("retdate-bucket"); err != nil {
				t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
			}
			obj, err := b.PutObject("retdate-bucket", "obj", []byte("data"), PutObjectOptions{})
			if err != nil {
				t.Fatalf("PutObject failed: %v", err)
			}
			if err := b.PutObjectRetention(
				"retdate-bucket",
				"obj",
				obj.VersionId,
				&ObjectLockRetention{Mode: RetentionModeGovernance, RetainUntilDate: date},
				false,
			); err != nil {
				t.Fatalf("PutObjectRetention(%q) failed: %v", date, err)
			}
			got, err := b.GetObjectRetention("retdate-bucket", "obj", obj.VersionId)
			if err != nil {
				t.Fatalf("GetObjectRetention failed: %v", err)
			}
			if got.Mode != RetentionModeGovernance {
				t.Fatalf("unexpected mode: %q", got.Mode)
			}
			want, err := ParseRetainUntilDate(date)
			if err != nil {
				t.Fatalf("ParseRetainUntilDate(%q) failed: %v", date, err)
			}
			want = want.UTC().Truncate(time.Second)
			stored, err := ParseRetainUntilDate(got.RetainUntilDate)
			if err != nil {
				t.Fatalf("stored date %q is not parseable: %v", got.RetainUntilDate, err)
			}
			if !stored.Equal(want) {
				t.Fatalf("stored date = %v, want %v", stored, want)
			}
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
			b := New()
			if err := b.CreateBucketWithObjectLock("retdate-bucket"); err != nil {
				t.Fatalf("CreateBucketWithObjectLock failed: %v", err)
			}
			obj, err := b.PutObject("retdate-bucket", "obj", []byte("data"), PutObjectOptions{})
			if err != nil {
				t.Fatalf("PutObject failed: %v", err)
			}
			err = b.PutObjectRetention(
				"retdate-bucket",
				"obj",
				obj.VersionId,
				&ObjectLockRetention{Mode: RetentionModeGovernance, RetainUntilDate: date},
				false,
			)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("PutObjectRetention(%q) = %v, want ErrInvalidRequest", date, err)
			}
		})
	}
}
