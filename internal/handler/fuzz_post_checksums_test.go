package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"hash/crc32"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzValidatePostObjectChecksums(f *testing.F) {
	body := []byte("hello world")
	sum := crc32.ChecksumIEEE(body)
	validCRC32 := base64.StdEncoding.EncodeToString([]byte{
		byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
	})
	sha256sum := sha256.Sum256(body)
	validSHA256 := base64.StdEncoding.EncodeToString(sha256sum[:])

	f.Add("x-amz-checksum-crc32", validCRC32, body)
	f.Add("x-amz-checksum-sha256", validSHA256, body)
	f.Add("x-amz-checksum-crc32", "invalid", body)
	f.Add("", "", []byte{})
	f.Add("x-amz-checksum-sha1", "badvalue", []byte("test"))

	f.Fuzz(func(t *testing.T, checksumKey, checksumValue string, body []byte) {
		if len(body) > 64*1024 {
			return
		}
		formFields := map[string]string{}
		if checksumKey != "" {
			formFields[checksumKey] = checksumValue
		}
		opts := &backend.PutObjectOptions{}
		_ = validatePostObjectChecksums(formFields, body, opts)
	})
}
