package backend

import (
	"testing"
	"time"
)

func FuzzIsObjectLocked(f *testing.F) {
	f.Add("ON", "COMPLIANCE", int64(1800000000), true)
	f.Add("OFF", "GOVERNANCE", int64(1700000000), false)
	f.Add("ON", "", int64(0), false)
	f.Add("", "COMPLIANCE", int64(1800000000), true)
	f.Add("OFF", "GOVERNANCE", int64(1800000000), true)

	f.Fuzz(func(t *testing.T, legalHold, retentionMode string, retainUntilUnix int64, bypassGovernance bool) {
		if retainUntilUnix < 0 || retainUntilUnix > 1e12 {
			return
		}
		obj := &Object{
			LegalHoldStatus: legalHold,
			RetentionMode:   retentionMode,
		}
		if retainUntilUnix > 0 {
			t2 := time.Unix(retainUntilUnix, 0)
			obj.RetainUntilDate = &t2
		}
		_ = isObjectLocked(obj, bypassGovernance)
	})
}

func FuzzGenerateVersionId(f *testing.F) {
	f.Add(1)
	f.Add(10)
	f.Add(100)

	f.Fuzz(func(t *testing.T, _ int) {
		result := GenerateVersionId()
		if len(result) == 0 {
			t.Error("empty version id")
		}
	})
}
