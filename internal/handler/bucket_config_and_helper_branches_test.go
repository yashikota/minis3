package handler

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash/crc32"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func checksumUint32Base64(v uint32) string {
	return base64.StdEncoding.EncodeToString([]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}

func TestValidateMFAHeaderAllBranches(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantErr string
	}{
		{name: "empty header", header: "", wantErr: "required"},
		{name: "missing token part", header: "serial-only", wantErr: "format"},
		{name: "empty serial", header: " 123456", wantErr: "cannot be empty"},
		{
			name:    "arn without mfa",
			header:  "arn:aws:iam::123456789012:user/name 123456",
			wantErr: "must contain ':mfa/'",
		},
		{name: "token length invalid", header: "20899872 12345", wantErr: "exactly 6 digits"},
		{name: "token non-digit", header: "20899872 12a456", wantErr: "only digits"},
		{name: "valid arn", header: "arn:aws:iam::123456789012:mfa/user 123456", wantErr: ""},
		{name: "valid hardware serial", header: "20899872 301749", wantErr: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMFAHeader(tc.header)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateMFAHeader(%q) failed: %v", tc.header, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf(
					"validateMFAHeader(%q) error = %v, want substring %q",
					tc.header,
					err,
					tc.wantErr,
				)
			}
		})
	}
}

func TestValidatePostObjectChecksumsAllAlgorithms(t *testing.T) {
	body := []byte("checksum-branches")
	crc32Value := checksumUint32Base64(crc32.ChecksumIEEE(body))
	crc32cValue := checksumUint32Base64(crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	sha1Sum := sha1.Sum(body)
	sha1Value := base64.StdEncoding.EncodeToString(sha1Sum[:])
	sha256Sum := sha256.Sum256(body)
	sha256Value := base64.StdEncoding.EncodeToString(sha256Sum[:])

	tests := []struct {
		name      string
		fieldName string
		value     string
		wantAlgo  string
	}{
		{
			name:      "crc32 success",
			fieldName: "x-amz-checksum-crc32",
			value:     crc32Value,
			wantAlgo:  "CRC32",
		},
		{
			name:      "crc32c success",
			fieldName: "x-amz-checksum-crc32c",
			value:     crc32cValue,
			wantAlgo:  "CRC32C",
		},
		{
			name:      "sha1 success",
			fieldName: "x-amz-checksum-sha1",
			value:     sha1Value,
			wantAlgo:  "SHA1",
		},
		{
			name:      "sha256 success",
			fieldName: "x-amz-checksum-sha256",
			value:     sha256Value,
			wantAlgo:  "SHA256",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := &backend.PutObjectOptions{}
			ok := validatePostObjectChecksums(map[string]string{tc.fieldName: tc.value}, body, opts)
			if !ok {
				t.Fatalf("validatePostObjectChecksums returned false for %s", tc.fieldName)
			}
			if opts.ChecksumAlgorithm != tc.wantAlgo {
				t.Fatalf("checksum algorithm = %q, want %q", opts.ChecksumAlgorithm, tc.wantAlgo)
			}
		})
	}

	t.Run("crc32 mismatch", func(t *testing.T) {
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-crc32": "wrong"},
			body,
			&backend.PutObjectOptions{},
		)
		if ok {
			t.Fatal("expected crc32 mismatch to fail validation")
		}
	})
	t.Run("crc32c mismatch", func(t *testing.T) {
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-crc32c": "wrong"},
			body,
			&backend.PutObjectOptions{},
		)
		if ok {
			t.Fatal("expected crc32c mismatch to fail validation")
		}
	})
	t.Run("sha1 mismatch", func(t *testing.T) {
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-sha1": "wrong"},
			body,
			&backend.PutObjectOptions{},
		)
		if ok {
			t.Fatal("expected sha1 mismatch to fail validation")
		}
	})
	t.Run("sha256 mismatch", func(t *testing.T) {
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-sha256": "wrong"},
			body,
			&backend.PutObjectOptions{},
		)
		if ok {
			t.Fatal("expected sha256 mismatch to fail validation")
		}
	})
}

func TestBucketConfigAndTaggingBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "cfg-branch")

	t.Run("location and tagging error branches", func(t *testing.T) {
		wLocationMissing := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?location", "", nil),
		)
		requireStatus(t, wLocationMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wLocationMissing, "NoSuchBucket")

		wTaggingNoSet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?tagging", "", nil),
		)
		requireStatus(t, wTaggingNoSet, http.StatusNotFound)
		requireS3ErrorCode(t, wTaggingNoSet, "NoSuchTagSet")

		wTaggingInvalid := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/cfg-branch?tagging",
				"<Tagging><TagSet><Tag><Key></Key><Value>v</Value></Tag></TagSet></Tagging>",
				nil,
			),
		)
		requireStatus(t, wTaggingInvalid, http.StatusBadRequest)
		requireS3ErrorCode(t, wTaggingInvalid, "InvalidTag")

		wTaggingMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?tagging", "<bad", nil),
		)
		requireStatus(t, wTaggingMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wTaggingMalformed, "MalformedXML")

		wTaggingMissingBucket := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-such-cfg?tagging",
				"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>",
				nil,
			),
		)
		requireStatus(t, wTaggingMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wTaggingMissingBucket, "NoSuchBucket")

		wTaggingGetMissingBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?tagging", "", nil),
		)
		requireStatus(t, wTaggingGetMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wTaggingGetMissingBucket, "NoSuchBucket")
	})

	t.Run("lifecycle branches", func(t *testing.T) {
		wGetNoConfig := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?lifecycle", "", nil),
		)
		requireStatus(t, wGetNoConfig, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoConfig, "NoSuchLifecycleConfiguration")

		wGetNoBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?lifecycle", "", nil),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		wPutMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?lifecycle", "<bad", nil),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedXML")

		payload := "<LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>"
		wPutMissingBucket := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/no-such-cfg?lifecycle", payload, nil),
		)
		requireStatus(t, wPutMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissingBucket, "NoSuchBucket")

		wPutOK := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?lifecycle", payload, nil),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?lifecycle", "", nil),
		)
		requireStatus(t, wGetOK, http.StatusOK)

		wDeleteOK := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-branch?lifecycle", "", nil),
		)
		requireStatus(t, wDeleteOK, http.StatusNoContent)
	})

	t.Run("encryption branches", func(t *testing.T) {
		wGetNoConfig := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?encryption", "", nil),
		)
		requireStatus(t, wGetNoConfig, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoConfig, "ServerSideEncryptionConfigurationNotFoundError")

		wGetNoBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?encryption", "", nil),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		wPutMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?encryption", "<bad", nil),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedXML")

		payload := "<ServerSideEncryptionConfiguration>" +
			"<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>" +
			"</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
		wPutMissingBucket := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/no-such-cfg?encryption", payload, nil),
		)
		requireStatus(t, wPutMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissingBucket, "NoSuchBucket")

		wPutOK := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?encryption", payload, nil),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?encryption", "", nil),
		)
		requireStatus(t, wGetOK, http.StatusOK)

		wDeleteOK := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-branch?encryption", "", nil),
		)
		requireStatus(t, wDeleteOK, http.StatusNoContent)
	})

	t.Run("cors branches", func(t *testing.T) {
		wGetNoConfig := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?cors", "", nil),
		)
		requireStatus(t, wGetNoConfig, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoConfig, "NoSuchCORSConfiguration")

		wGetNoBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?cors", "", nil),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		wPutMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?cors", "<bad", nil),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedXML")

		payload := "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>" +
			"<AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>"
		wPutMissingBucket := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/no-such-cfg?cors", payload, nil),
		)
		requireStatus(t, wPutMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissingBucket, "NoSuchBucket")

		wPutOK := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?cors", payload, nil),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?cors", "", nil),
		)
		requireStatus(t, wGetOK, http.StatusOK)

		wDeleteOK := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-branch?cors", "", nil),
		)
		requireStatus(t, wDeleteOK, http.StatusNoContent)
	})

	t.Run("website branches", func(t *testing.T) {
		wGetNoConfig := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?website", "", nil),
		)
		requireStatus(t, wGetNoConfig, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoConfig, "NoSuchWebsiteConfiguration")

		wGetNoBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/no-such-cfg?website", "", nil),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		wPutMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?website", "<bad", nil),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedXML")

		payload := "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>"
		wPutMissingBucket := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/no-such-cfg?website", payload, nil),
		)
		requireStatus(t, wPutMissingBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissingBucket, "NoSuchBucket")

		wPutOK := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/cfg-branch?website", payload, nil),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/cfg-branch?website", "", nil),
		)
		requireStatus(t, wGetOK, http.StatusOK)

		wDeleteOK := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/cfg-branch?website", "", nil),
		)
		requireStatus(t, wDeleteOK, http.StatusNoContent)
	})
}
