package handler

import "testing"

func FuzzInferChecksumAlgorithmFromTrailer(f *testing.F) {
	f.Add("x-amz-checksum-crc32")
	f.Add("x-amz-checksum-crc32c")
	f.Add("x-amz-checksum-crc64nvme")
	f.Add("x-amz-checksum-sha1")
	f.Add("x-amz-checksum-sha256")
	f.Add("")
	f.Add("x-amz-checksum-unknown")
	f.Add("X-Amz-Checksum-CRC32C")
	f.Add("  x-amz-checksum-sha256  ")
	f.Add("x-amz-checksum-")
	f.Add("checksum-crc32")

	f.Fuzz(func(t *testing.T, trailer string) {
		_ = inferChecksumAlgorithmFromTrailer(trailer)
	})
}

func FuzzNormalizeChecksumType(f *testing.F) {
	f.Add("CRC32", "")
	f.Add("CRC32C", "")
	f.Add("SHA1", "")
	f.Add("SHA256", "")
	f.Add("CRC64NVME", "")
	f.Add("sha256", "COMPOSITE")
	f.Add("", "FULL_OBJECT")
	f.Add("crc32", "COMPOSITE")
	f.Add("  SHA1  ", "  ")
	f.Add("unknown", "")

	f.Fuzz(func(t *testing.T, algorithm, checksumType string) {
		_ = normalizeChecksumType(algorithm, checksumType)
	})
}
