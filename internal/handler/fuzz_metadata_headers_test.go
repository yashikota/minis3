package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzSetMetadataHeaders(f *testing.F) {
	f.Add("key1", "value1", "key2", "value2")
	f.Add("utf8-key", "héllo wörld", "", "")
	f.Add("simple", "ascii-only", "another", "val")
	f.Add("", "", "", "")
	f.Add("CamelCase", "MixedCase", "lower", "lower")

	f.Fuzz(func(t *testing.T, k1, v1, k2, v2 string) {
		metadata := map[string]string{}
		if k1 != "" {
			metadata[k1] = v1
		}
		if k2 != "" {
			metadata[k2] = v2
		}
		if len(metadata) == 0 {
			return
		}
		recorder := httptest.NewRecorder()
		setMetadataHeaders(recorder, metadata)
	})
}

func FuzzSetObjectLockHeaders(f *testing.F) {
	f.Add("GOVERNANCE", "2025-01-01T00:00:00Z", "ON")
	f.Add("COMPLIANCE", "2030-12-31T23:59:59Z", "OFF")
	f.Add("", "", "")
	f.Add("GOVERNANCE", "", "ON")

	f.Fuzz(func(t *testing.T, retentionMode, retainUntilDate, legalHold string) {
		obj := &backend.Object{
			RetentionMode:   retentionMode,
			LegalHoldStatus: legalHold,
		}
		if retainUntilDate != "" {
			// just set as string - the function reads RetainUntilDate as *time.Time
			// so we skip setting it here for invalid dates
		}
		recorder := httptest.NewRecorder()
		setObjectLockHeaders(recorder, obj)
	})
}

func FuzzSetStorageAndEncryptionHeaders(f *testing.F) {
	f.Add("STANDARD", "AES256", "", "", "")
	f.Add("GLACIER", "aws:kms", "arn:aws:kms:us-east-1:123456:key/id", "AES256", "md5hash")
	f.Add("REDUCED_REDUNDANCY", "", "", "", "")
	f.Add("", "", "", "", "")
	f.Add("INTELLIGENT_TIERING", "aws:kms:dsse", "key-id", "", "")

	f.Fuzz(func(t *testing.T, storageClass, sse, sseKMSKeyID, sseCustomerAlgo, sseCustomerKeyMD5 string) {
		obj := &backend.Object{
			StorageClass:         storageClass,
			ServerSideEncryption: sse,
			SSEKMSKeyId:          sseKMSKeyID,
			SSECustomerAlgorithm: sseCustomerAlgo,
			SSECustomerKeyMD5:    sseCustomerKeyMD5,
		}
		recorder := httptest.NewRecorder()
		setStorageAndEncryptionHeaders(recorder, obj)
	})
}

func FuzzSetChecksumResponseHeaders(f *testing.F) {
	f.Add("CRC32", "FULL_OBJECT", "abc123", "", "", "", "")
	f.Add("SHA256", "COMPOSITE", "", "", "", "", "sha256val")
	f.Add("CRC32C", "", "", "crc32c-val", "", "", "")
	f.Add("", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, algorithm, checksumType, crc32, crc32c, crc64, sha1, sha256 string) {
		obj := &backend.Object{
			ChecksumAlgorithm: algorithm,
			ChecksumType:      checksumType,
			ChecksumCRC32:     crc32,
			ChecksumCRC32C:    crc32c,
			ChecksumCRC64NVME: crc64,
			ChecksumSHA1:      sha1,
			ChecksumSHA256:    sha256,
		}
		recorder := httptest.NewRecorder()
		setChecksumResponseHeaders(recorder, obj)
	})
}
