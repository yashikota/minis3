package handler

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzSetPartChecksumResponseHeaders(f *testing.F) {
	f.Add("FULL_OBJECT", "crc32val", "", "", "", "")
	f.Add("COMPOSITE", "", "crc32c", "", "", "")
	f.Add("", "", "", "crc64val", "", "")
	f.Add("FULL_OBJECT", "", "", "", "sha1val", "sha256val")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, checksumType, crc32, crc32c, crc64, sha1, sha256 string) {
		part := &backend.ObjectPart{
			ChecksumCRC32:     crc32,
			ChecksumCRC32C:    crc32c,
			ChecksumCRC64NVME: crc64,
			ChecksumSHA1:      sha1,
			ChecksumSHA256:    sha256,
		}
		recorder := httptest.NewRecorder()
		setPartChecksumResponseHeaders(recorder, checksumType, part)
	})
}

func FuzzGetPartData(f *testing.F) {
	f.Add([]byte("hello world"), 1, false, 0, int64(0))
	f.Add([]byte("part1part2"), 1, true, 1, int64(5))
	f.Add([]byte("part1part2"), 2, true, 2, int64(5))
	f.Add([]byte("data"), 5, false, 0, int64(0))
	f.Add([]byte{}, 1, false, 0, int64(0))

	f.Fuzz(func(t *testing.T, data []byte, partNumber int, hasParts bool, pn int, pSize int64) {
		if len(data) > 1024*1024 || partNumber <= 0 || partNumber > 10000 {
			return
		}
		if pSize < 0 {
			return
		}
		obj := &backend.Object{
			Data: data,
			Size: int64(len(data)),
		}
		if hasParts && pn > 0 && pSize > 0 {
			obj.Parts = []backend.ObjectPart{
				{PartNumber: pn, Size: pSize},
			}
		}
		_, _, _, _ = getPartData(obj, partNumber)
	})
}

func FuzzSetRestoreHeader(f *testing.F) {
	f.Add(int64(1800000000), false)
	f.Add(int64(1800000000), true)
	f.Add(int64(0), false)

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
		recorder := httptest.NewRecorder()
		setRestoreHeader(recorder, obj)
	})
}

func FuzzIsObjectRestoredExtended(f *testing.F) {
	f.Add(int64(0), false, false)
	f.Add(int64(1800000000), false, true)
	f.Add(int64(1700000000), true, false)
	f.Add(int64(1700000000), false, false)

	f.Fuzz(func(t *testing.T, expiryUnix int64, ongoing, hasExpiry bool) {
		if expiryUnix < 0 || expiryUnix > 1e12 {
			return
		}
		obj := &backend.Object{
			RestoreOngoing: ongoing,
		}
		if hasExpiry {
			expiry := time.Unix(expiryUnix, 0)
			obj.RestoreExpiryDate = &expiry
		}
		_ = isObjectRestored(obj)
	})
}
