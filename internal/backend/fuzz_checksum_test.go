package backend

import "testing"

func FuzzChecksumForAlgorithm(f *testing.F) {
	f.Add("CRC32", []byte("hello world"))
	f.Add("CRC32C", []byte("hello world"))
	f.Add("CRC64NVME", []byte("test"))
	f.Add("SHA1", []byte("data"))
	f.Add("SHA256", []byte("content"))
	f.Add("unknown", []byte("x"))
	f.Add("", []byte{})
	f.Add("crc32", []byte{0, 1, 2, 3, 255})
	f.Add("  SHA256  ", []byte("trimmed"))

	f.Fuzz(func(t *testing.T, algorithm string, data []byte) {
		_, _ = checksumForAlgorithm(algorithm, data)
	})
}

func FuzzProvidedChecksumForPut(f *testing.F) {
	f.Add("CRC32", "abc123", "", "", "", "")
	f.Add("CRC32C", "", "def456", "", "", "")
	f.Add("CRC64NVME", "", "", "ghi789", "", "")
	f.Add("SHA1", "", "", "", "sha1val", "")
	f.Add("SHA256", "", "", "", "", "sha256val")
	f.Add("unknown", "", "", "", "", "")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, algorithm, crc32val, crc32c, crc64, sha1val, sha256val string) {
		opts := PutObjectOptions{
			ChecksumCRC32:     crc32val,
			ChecksumCRC32C:    crc32c,
			ChecksumCRC64NVME: crc64,
			ChecksumSHA1:      sha1val,
			ChecksumSHA256:    sha256val,
		}
		_ = providedChecksumForPut(algorithm, opts)
	})
}
