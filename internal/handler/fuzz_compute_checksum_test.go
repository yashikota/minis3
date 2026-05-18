package handler

import (
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzComputePartChecksums(f *testing.F) {
	f.Add([]byte("hello world"), "CRC32")
	f.Add([]byte("test data"), "CRC32C")
	f.Add([]byte{0, 1, 2, 3}, "SHA1")
	f.Add([]byte("content"), "SHA256")
	f.Add([]byte{}, "CRC64NVME")
	f.Add([]byte("x"), "unknown")
	f.Add([]byte("data"), "")

	f.Fuzz(func(t *testing.T, data []byte, algorithm string) {
		if len(data) > 1024*1024 {
			return
		}
		_ = computePartChecksums(data, algorithm)
	})
}

func FuzzLoggingRollInterval(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(300))
	f.Add(int64(3600))
	f.Add(int64(-1))
	f.Add(int64(86400))

	f.Fuzz(func(t *testing.T, rollTime int64) {
		if rollTime > 1e9 {
			return
		}
		logging := &backend.LoggingEnabled{
			ObjectRollTime: int(rollTime),
		}
		result := loggingRollInterval(logging)
		if result <= 0 && rollTime > 0 {
			t.Errorf("expected positive duration for rollTime=%d, got %v", rollTime, result)
		}
	})
}

func FuzzLoggingRollIntervalNil(f *testing.F) {
	f.Add(true)
	f.Add(false)

	f.Fuzz(func(t *testing.T, isNil bool) {
		if isNil {
			result := loggingRollInterval(nil)
			if result <= 0 {
				t.Error("expected positive default duration for nil logging")
			}
		} else {
			result := loggingRollInterval(&backend.LoggingEnabled{})
			_ = result
		}
	})
}

func FuzzIsObjectRestored(f *testing.F) {
	f.Add(int64(0), false)
	f.Add(int64(1800000000), false)
	f.Add(int64(1700000000), true)

	f.Fuzz(func(t *testing.T, expiryUnix int64, ongoing bool) {
		if expiryUnix < 0 || expiryUnix > 1e12 {
			return
		}
		obj := &backend.Object{
			RestoreOngoing: ongoing,
		}
		if expiryUnix > 0 {
			expiry := time.Unix(expiryUnix, 0)
			obj.RestoreExpiryDate = &expiry
		}
		_ = isObjectRestored(obj)
	})
}
