package handler

import (
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzTrimLeadingSlash(f *testing.F) {
	f.Add("/path/to/key")
	f.Add("path/to/key")
	f.Add("/")
	f.Add("")
	f.Add("///multi")

	f.Fuzz(func(t *testing.T, s string) {
		_ = trimLeadingSlash(s)
	})
}

func FuzzUnhex(f *testing.F) {
	f.Add(byte('0'))
	f.Add(byte('9'))
	f.Add(byte('a'))
	f.Add(byte('f'))
	f.Add(byte('A'))
	f.Add(byte('F'))
	f.Add(byte('g'))
	f.Add(byte('z'))
	f.Add(byte(0))
	f.Add(byte(255))

	f.Fuzz(func(t *testing.T, c byte) {
		_ = unhex(c)
	})
}

func FuzzIndexByte(f *testing.F) {
	f.Add("hello/world", byte('/'))
	f.Add("nodelimiter", byte('/'))
	f.Add("", byte('x'))
	f.Add("a?b=c", byte('?'))

	f.Fuzz(func(t *testing.T, s string, c byte) {
		_ = indexByte(s, c)
	})
}

func FuzzChecksumFromPartInfoFuzz(f *testing.F) {
	f.Add("CRC32", "abc123", "def456", "", "", "")
	f.Add("CRC32C", "", "crc32c-val", "", "", "")
	f.Add("CRC64NVME", "", "", "crc64-val", "", "")
	f.Add("SHA1", "", "", "", "sha1val", "")
	f.Add("SHA256", "", "", "", "", "sha256val")
	f.Add("unknown", "", "", "", "", "")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, algorithm, crc32, crc32c, crc64, sha1, sha256 string) {
		p := &backend.PartInfo{
			ChecksumCRC32:     crc32,
			ChecksumCRC32C:    crc32c,
			ChecksumCRC64NVME: crc64,
			ChecksumSHA1:      sha1,
			ChecksumSHA256:    sha256,
		}
		_ = checksumFromPartInfo(algorithm, p)
	})
}

func FuzzSetUploadFinalChecksum(f *testing.F) {
	f.Add("CRC32", "abc123")
	f.Add("CRC32C", "def456")
	f.Add("CRC64NVME", "ghi789")
	f.Add("SHA1", "sha1val")
	f.Add("SHA256", "sha256val")
	f.Add("", "")
	f.Add("unknown", "value")

	f.Fuzz(func(t *testing.T, algorithm, value string) {
		upload := &backend.MultipartUpload{}
		setUploadFinalChecksum(upload, algorithm, value)
	})
}
