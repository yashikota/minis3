package handler

import (
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzComputeCompositeChecksum(f *testing.F) {
	f.Add("SHA256", "dGVzdA==", "dGVzdDI=")
	f.Add("SHA1", "dGVzdA==", "")
	f.Add("CRC32", "AAAA", "BBBB")
	f.Add("SHA256", "", "")
	f.Add("unknown", "dGVzdA==", "dGVzdDI=")
	f.Add("SHA256", "not-base64!", "also-not!")

	f.Fuzz(func(t *testing.T, algorithm, checksum1, checksum2 string) {
		var parts []string
		if checksum1 != "" {
			parts = append(parts, checksum1)
		}
		if checksum2 != "" {
			parts = append(parts, checksum2)
		}
		_, _ = computeCompositeChecksum(algorithm, parts)
	})
}

func FuzzComputeFullObjectChecksum(f *testing.F) {
	f.Add("CRC32", []byte("hello world"))
	f.Add("CRC32C", []byte("hello world"))
	f.Add("CRC64NVME", []byte("test data"))
	f.Add("SHA1", []byte("content"))
	f.Add("SHA256", []byte("content"))
	f.Add("unknown", []byte("data"))
	f.Add("CRC32", []byte{})
	f.Add("SHA256", []byte{0, 1, 2, 3, 255})

	f.Fuzz(func(t *testing.T, algorithm string, data []byte) {
		_, _ = computeFullObjectChecksum(algorithm, data)
	})
}

func FuzzChecksumFromCompletePart(f *testing.F) {
	f.Add("CRC32", "abc123")
	f.Add("CRC32C", "def456")
	f.Add("CRC64NVME", "ghi789")
	f.Add("SHA1", "sha1val")
	f.Add("SHA256", "sha256val")
	f.Add("unknown", "value")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, algorithm, checksumValue string) {
		part := backend.CompletePart{
			PartNumber:        1,
			ETag:              "\"etag\"",
			ChecksumCRC32:     checksumValue,
			ChecksumCRC32C:    checksumValue,
			ChecksumCRC64NVME: checksumValue,
			ChecksumSHA1:      checksumValue,
			ChecksumSHA256:    checksumValue,
		}
		_ = checksumFromCompletePart(algorithm, part)
	})
}
