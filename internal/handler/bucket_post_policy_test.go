package handler

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func encodePolicy(t *testing.T, policy map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestValidatePostPolicy(t *testing.T) {
	expiration := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")
	expired := time.Now().UTC().Add(-10 * time.Minute).Format("2006-01-02T15:04:05Z")

	tests := []struct {
		name        string
		policy      map[string]any
		formFields  map[string]string
		key         string
		contentType string
		size        int64
		wantStatus  int
		wantOK      bool
	}{
		{
			name: "valid case-insensitive fields",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bUcKeT": "bucket-a"},
					[]any{"StArTs-WiTh", "$KeY", "foo"},
					[]any{"StArTs-WiTh", "$CoNtEnT-TyPe", "text/plain"},
					[]any{"content-length-range", 0, 1024},
				},
			},
			formFields:  map[string]string{},
			key:         "foo.txt",
			contentType: "text/plain",
			size:        3,
			wantOK:      true,
		},
		{
			name: "invalid expiration format",
			policy: map[string]any{
				"expiration": time.Now().UTC().String(),
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
				},
			},
			wantStatus: 400,
		},
		{
			name: "missing conditions list",
			policy: map[string]any{
				"expiration": expiration,
			},
			wantStatus: 400,
		},
		{
			name: "missing expiration field",
			policy: map[string]any{
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
				},
			},
			wantStatus: 400,
		},
		{
			name: "missing bucket condition",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					[]any{"starts-with", "$key", "foo"},
				},
			},
			key:        "foo.txt",
			wantStatus: 403,
		},
		{
			name: "missing required field by policy",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"starts-with", "$x-amz-meta-foo", "bar"},
				},
			},
			formFields: map[string]string{},
			key:        "foo.txt",
			wantStatus: 403,
		},
		{
			name: "content-length-range malformed",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"content-length-range", 0},
				},
			},
			key:        "foo.txt",
			wantStatus: 400,
		},
		{
			name: "content-length-range out of bounds",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"content-length-range", 10, 20},
				},
			},
			key:        "foo.txt",
			size:       3,
			wantStatus: 400,
		},
		{
			name: "expired policy",
			policy: map[string]any{
				"expiration": expired,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
				},
			},
			wantStatus: 403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := encodePolicy(t, tt.policy)
			status, ok := validatePostPolicy(
				policy,
				"bucket-a",
				tt.key,
				tt.contentType,
				tt.formFields,
				tt.size,
			)
			if ok != tt.wantOK {
				t.Fatalf("ok mismatch: got %v, want %v", ok, tt.wantOK)
			}
			if status != tt.wantStatus {
				t.Fatalf("status mismatch: got %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

func TestValidatePostObjectChecksums(t *testing.T) {
	body := []byte("bar")

	t.Run("valid sha256 checksum", func(t *testing.T) {
		sum := sha256.Sum256(body)
		expected := base64.StdEncoding.EncodeToString(sum[:])
		opts := backend.PutObjectOptions{}
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-sha256": expected},
			body,
			&opts,
		)
		if !ok {
			t.Fatal("expected checksum validation to pass")
		}
		if opts.ChecksumAlgorithm != "SHA256" {
			t.Fatalf("unexpected checksum algorithm: %q", opts.ChecksumAlgorithm)
		}
		if opts.ChecksumSHA256 != expected {
			t.Fatalf("unexpected checksum value: %q", opts.ChecksumSHA256)
		}
	})

	t.Run("invalid sha256 checksum", func(t *testing.T) {
		opts := backend.PutObjectOptions{}
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-sha256": "invalid"},
			body,
			&opts,
		)
		if ok {
			t.Fatal("expected checksum validation to fail")
		}
	})

	t.Run("valid crc32 checksum", func(t *testing.T) {
		sum := crc32.ChecksumIEEE(body)
		expected := base64.StdEncoding.EncodeToString([]byte{
			byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum),
		})

		opts := backend.PutObjectOptions{}
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-crc32": expected},
			body,
			&opts,
		)
		if !ok {
			t.Fatal("expected checksum validation to pass")
		}
		if opts.ChecksumAlgorithm != "CRC32" {
			t.Fatalf("unexpected checksum algorithm: %q", opts.ChecksumAlgorithm)
		}
		if opts.ChecksumCRC32 != expected {
			t.Fatalf("unexpected checksum value: %q", opts.ChecksumCRC32)
		}
	})

	t.Run("invalid crc32 checksum", func(t *testing.T) {
		opts := backend.PutObjectOptions{}
		ok := validatePostObjectChecksums(
			map[string]string{"x-amz-checksum-crc32": "invalid"},
			body,
			&opts,
		)
		if ok {
			t.Fatal("expected checksum validation to fail")
		}
	})

	t.Run("multiple checksum fields use the last recognized algorithm", func(t *testing.T) {
		sha1Sum := sha1.Sum(body)
		sha1Expected := base64.StdEncoding.EncodeToString(sha1Sum[:])
		sha256Sum := sha256.Sum256(body)
		sha256Expected := base64.StdEncoding.EncodeToString(sha256Sum[:])

		opts := backend.PutObjectOptions{}
		ok := validatePostObjectChecksums(
			map[string]string{
				"x-amz-checksum-sha1":   sha1Expected,
				"x-amz-checksum-sha256": sha256Expected,
			},
			body,
			&opts,
		)
		if !ok {
			t.Fatal("expected checksum validation to pass")
		}
		if opts.ChecksumSHA1 != sha1Expected {
			t.Fatalf("unexpected sha1 value: %q", opts.ChecksumSHA1)
		}
		if opts.ChecksumSHA256 != sha256Expected {
			t.Fatalf("unexpected sha256 value: %q", opts.ChecksumSHA256)
		}
		if opts.ChecksumAlgorithm != "SHA256" {
			t.Fatalf("unexpected checksum algorithm: %q", opts.ChecksumAlgorithm)
		}
	})
}

func TestValidatePostPolicyAdditionalScenarios(t *testing.T) {
	expiration := time.Now().UTC().Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")

	tests := []struct {
		name        string
		policy      map[string]any
		formFields  map[string]string
		key         string
		contentType string
		size        int64
		wantStatus  int
		wantOK      bool
	}{
		{
			name: "top-level expiration is case-sensitive",
			policy: map[string]any{
				"EXPIRATION": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
				},
			},
			wantStatus: 400,
		},
		{
			name: "top-level conditions is case-sensitive",
			policy: map[string]any{
				"expiration": expiration,
				"CONDITIONS": []any{
					map[string]any{"bucket": "bucket-a"},
				},
			},
			wantStatus: 400,
		},
		{
			name: "unsupported operator",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"contains", "$key", "foo"},
				},
			},
			key:        "foo.txt",
			wantStatus: 400,
		},
		{
			name: "wrong bucket value fails authorization",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-b"},
				},
			},
			wantStatus: 403,
		},
		{
			name: "eq condition matched against form field",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"eq", "$success_action_redirect", "http://example.test"},
				},
			},
			formFields: map[string]string{"success_action_redirect": "http://example.test"},
			wantOK:     true,
		},
		{
			name: "eq condition mismatch fails authorization",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"eq", "$success_action_redirect", "http://example.test"},
				},
			},
			formFields: map[string]string{"success_action_redirect": "http://other.test"},
			wantStatus: 403,
		},
		{
			name: "content-length-range negative minimum is invalid",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"content-length-range", -1, 10},
				},
			},
			size:       1,
			wantStatus: 400,
		},
		{
			name: "content-length-range maximum smaller than minimum is invalid",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{"bucket": "bucket-a"},
					[]any{"content-length-range", 10, 5},
				},
			},
			size:       7,
			wantStatus: 400,
		},
		{
			name: "empty condition object is invalid",
			policy: map[string]any{
				"expiration": expiration,
				"conditions": []any{
					map[string]any{},
				},
			},
			wantStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := encodePolicy(t, tt.policy)
			status, ok := validatePostPolicy(
				policy,
				"bucket-a",
				tt.key,
				tt.contentType,
				tt.formFields,
				tt.size,
			)
			if ok != tt.wantOK {
				t.Fatalf("ok mismatch: got %v, want %v", ok, tt.wantOK)
			}
			if status != tt.wantStatus {
				t.Fatalf("status mismatch: got %d, want %d", status, tt.wantStatus)
			}
		})
	}
}

func TestValidatePostPolicyRejectsInvalidBase64(t *testing.T) {
	status, ok := validatePostPolicy(
		"%%invalid%%",
		"bucket-a",
		"foo.txt",
		"text/plain",
		map[string]string{},
		3,
	)
	if ok {
		t.Fatal("expected invalid base64 policy to fail")
	}
	if status != 400 {
		t.Fatalf("unexpected status: got %d, want 400", status)
	}
}

func TestParsePostTaggingXML(t *testing.T) {
	t.Run("valid xml", func(t *testing.T) {
		tags, errCode, errMsg := parsePostTaggingXML(
			"<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>2</Value></Tag></TagSet></Tagging>",
		)
		if errCode != "" || errMsg != "" {
			t.Fatalf("unexpected error: code=%q msg=%q", errCode, errMsg)
		}
		if len(tags) != 2 {
			t.Fatalf("unexpected tag count: %d", len(tags))
		}
		if tags["a"] != "1" || tags["b"] != "2" {
			t.Fatalf("unexpected tags: %#v", tags)
		}
	})

	t.Run("malformed xml", func(t *testing.T) {
		_, errCode, _ := parsePostTaggingXML("<Tagging><TagSet>")
		if errCode != "MalformedXML" {
			t.Fatalf("unexpected error code: %q", errCode)
		}
	})

	t.Run("tag key length overflow", func(t *testing.T) {
		longKey := strings.Repeat("k", 129)
		payload := "<Tagging><TagSet><Tag><Key>" + longKey + "</Key><Value>v</Value></Tag></TagSet></Tagging>"
		_, errCode, _ := parsePostTaggingXML(payload)
		if errCode != "InvalidTag" {
			t.Fatalf("unexpected error code: %q", errCode)
		}
	})
}

func TestExtractPostFormMetadata(t *testing.T) {
	metadata := extractPostFormMetadata(map[string]string{
		"x-amz-meta-foo": "bar",
		"x-amz-meta-baz": "qux",
		"key":            "object",
	})
	if len(metadata) != 2 {
		t.Fatalf("unexpected metadata size: %d", len(metadata))
	}
	if metadata["foo"] != "bar" || metadata["baz"] != "qux" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}

	none := extractPostFormMetadata(map[string]string{"key": "object"})
	if none != nil {
		t.Fatalf("expected nil metadata, got %#v", none)
	}
}

func TestVerifyPostPolicySignature(t *testing.T) {
	policy := base64.StdEncoding.EncodeToString(
		[]byte(`{"expiration":"2099-01-01T00:00:00Z","conditions":[]}`),
	)
	mac := hmac.New(sha1.New, []byte("minis3-secret-key"))
	_, _ = mac.Write([]byte(policy))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !verifyPostPolicySignature("minis3-access-key", signature, policy) {
		t.Fatal("expected signature verification to pass")
	}
	if verifyPostPolicySignature("minis3-access-key", signature+"x", policy) {
		t.Fatal("expected signature verification to fail with invalid signature")
	}
	if verifyPostPolicySignature("unknown-access-key", signature, policy) {
		t.Fatal("expected signature verification to fail with unknown access key")
	}
}

func TestResolvePostPolicyFieldValue(t *testing.T) {
	form := map[string]string{
		"success_action_redirect": "http://example.test/ok",
		"x-amz-meta-project":      "alpha",
	}

	if got := resolvePostPolicyFieldValue("bucket", "bucket-a", "k", "text/plain", form); got != "bucket-a" {
		t.Fatalf("unexpected bucket value: %q", got)
	}
	if got := resolvePostPolicyFieldValue("$key", "bucket-a", "k", "text/plain", form); got != "k" {
		t.Fatalf("unexpected key value: %q", got)
	}
	if got := resolvePostPolicyFieldValue("$Content-Type", "bucket-a", "k", "text/plain", form); got != "text/plain" {
		t.Fatalf("unexpected content-type value: %q", got)
	}
	if got := resolvePostPolicyFieldValue("$x-amz-meta-project", "bucket-a", "k", "text/plain", form); got != "alpha" {
		t.Fatalf("unexpected form field value: %q", got)
	}
}

func TestParseMultipartFormFields(t *testing.T) {
	body := &strings.Builder{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("AWSAccessKeyId", "minis3-access-key"); err != nil {
		t.Fatalf("WriteField failed: %v", err)
	}
	if err := writer.WriteField("Key", "foo.txt"); err != nil {
		t.Fatalf("WriteField failed: %v", err)
	}
	if err := writer.WriteField("X-Amz-Meta-Project", "alpha"); err != nil {
		t.Fatalf("WriteField failed: %v", err)
	}
	// non-file form field sent as file-part should still be captured
	policyPart, err := writer.CreateFormFile("PoLiCy", "policy.txt")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := policyPart.Write([]byte("encoded-policy")); err != nil {
		t.Fatalf("policyPart.Write failed: %v", err)
	}
	filePart, err := writer.CreateFormFile("file", "upload.txt")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := filePart.Write([]byte("payload")); err != nil {
		t.Fatalf("filePart.Write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/bucket", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if err := req.ParseMultipartForm(8 << 20); err != nil {
		t.Fatalf("ParseMultipartForm failed: %v", err)
	}

	fields := parseMultipartFormFields(req)
	if fields["awsaccesskeyid"] != "minis3-access-key" {
		t.Fatalf("unexpected awsaccesskeyid: %q", fields["awsaccesskeyid"])
	}
	if fields["key"] != "foo.txt" {
		t.Fatalf("unexpected key: %q", fields["key"])
	}
	if fields["x-amz-meta-project"] != "alpha" {
		t.Fatalf("unexpected metadata project: %q", fields["x-amz-meta-project"])
	}
	if fields["policy"] != "encoded-policy" {
		t.Fatalf("unexpected policy: %q", fields["policy"])
	}
	if _, exists := fields["file"]; exists {
		t.Fatalf("file part must not be treated as metadata field: %#v", fields)
	}
}
