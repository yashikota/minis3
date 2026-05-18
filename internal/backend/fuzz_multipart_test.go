package backend

import "testing"

func FuzzNormalizeCompleteParts(f *testing.F) {
	f.Add(1, "\"etag1\"", "crc1", 2, "\"etag2\"", "crc2")
	f.Add(1, "etag-no-quotes", "", 2, "etag2", "")
	f.Add(0, "", "", 0, "", "")
	f.Add(1, "\"abc\"", "checksum", 1, "\"abc\"", "checksum")

	f.Fuzz(func(t *testing.T, pn1 int, etag1, crc1 string, pn2 int, etag2, crc2 string) {
		parts := []CompletePart{
			{PartNumber: pn1, ETag: etag1, ChecksumCRC32: crc1},
			{PartNumber: pn2, ETag: etag2, ChecksumCRC32: crc2},
		}
		_ = normalizeCompleteParts(parts)
	})
}
