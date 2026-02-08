package handler

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func TestExtractMetadata(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "http://example.test/bucket/key", nil)
	r.Header.Set("X-Amz-Meta-User", "Alice")
	r.Header.Set("x-amz-meta-note", "caf%C3%A9")
	r.Header.Set("x-amz-meta-plus", "a+b")
	r.Header.Set("Content-Type", "text/plain")

	metadata := extractMetadata(r)
	if metadata["user"] != "Alice" {
		t.Fatalf("unexpected user metadata: %+v", metadata)
	}
	if metadata["note"] != "café" {
		t.Fatalf("expected decoded metadata value, got %+v", metadata)
	}
	if metadata["plus"] != "a+b" {
		t.Fatalf("plus should not be converted to space, got %+v", metadata)
	}

	r2 := httptest.NewRequest(http.MethodPut, "http://example.test/bucket/key", nil)
	if got := extractMetadata(r2); got != nil {
		t.Fatalf("expected nil metadata for request without x-amz-meta headers, got %+v", got)
	}
}

func TestSetMetadataHeadersAndEncoding(t *testing.T) {
	w := httptest.NewRecorder()
	setMetadataHeaders(w, map[string]string{
		"plain": "value",
		"latin": "café",
	})

	plainValues := getHeaderValuesCaseInsensitive(w.Header(), "x-amz-meta-plain")
	if len(plainValues) != 1 || plainValues[0] != "value" {
		t.Fatalf("unexpected plain metadata header: %+v", plainValues)
	}

	latinValues := getHeaderValuesCaseInsensitive(w.Header(), "x-amz-meta-latin")
	if len(latinValues) != 1 {
		t.Fatalf("unexpected latin metadata header values: %+v", latinValues)
	}
	if !bytes.Equal([]byte(latinValues[0]), []byte{'c', 'a', 'f', 0xE9}) {
		t.Fatalf("latin metadata was not encoded as latin-1 bytes: %v", []byte(latinValues[0]))
	}

	if got := encodeHeaderMetadataValue("ascii"); got != "ascii" {
		t.Fatalf("encodeHeaderMetadataValue(ascii) = %q", got)
	}
	// Character outside Latin-1 should keep original UTF-8
	if got := encodeHeaderMetadataValue("price €"); got != "price €" {
		t.Fatalf("encodeHeaderMetadataValue(non-latin1) = %q", got)
	}
}

func getHeaderValuesCaseInsensitive(h http.Header, key string) []string {
	for k, values := range h {
		if strings.EqualFold(k, key) {
			return values
		}
	}
	return nil
}

func TestParseTaggingAndValidation(t *testing.T) {
	if got := parseTaggingHeader(""); got != nil {
		t.Fatalf("expected nil for empty tagging header, got %+v", got)
	}
	if got := parseTaggingHeader("%%%broken"); got != nil {
		t.Fatalf("expected nil for invalid tagging header, got %+v", got)
	}

	tags := parseTaggingHeader("team=platform&env=dev")
	if tags["team"] != "platform" || tags["env"] != "dev" {
		t.Fatalf("unexpected parsed tags: %+v", tags)
	}

	if code, msg := validateTags(tags); code != "" || msg != "" {
		t.Fatalf("unexpected validateTags error: %s %s", code, msg)
	}

	tooMany := make(map[string]string)
	for i := 0; i < maxTagsPerObject+1; i++ {
		tooMany[string(rune('a'+i))] = "v"
	}
	if code, _ := validateTags(tooMany); code != "InvalidTag" {
		t.Fatalf("expected InvalidTag for too many tags, got %q", code)
	}

	longKey := map[string]string{string(make([]byte, maxTagKeyLength+1)): "v"}
	if code, _ := validateTags(longKey); code != "InvalidTag" {
		t.Fatalf("expected InvalidTag for long key, got %q", code)
	}

	longValue := map[string]string{"k": string(make([]byte, maxTagValLength+1))}
	if code, _ := validateTags(longValue); code != "InvalidTag" {
		t.Fatalf("expected InvalidTag for long value, got %q", code)
	}

	validTagSet := []backend.Tag{{Key: "k1", Value: "v1"}}
	if code, msg := validateTagSet(validTagSet); code != "" || msg != "" {
		t.Fatalf("unexpected validateTagSet error: %s %s", code, msg)
	}
	if code, _ := validateTagSet(make([]backend.Tag, maxTagsPerObject+1)); code != "InvalidTag" {
		t.Fatalf("expected InvalidTag for too many tags in set, got %q", code)
	}
}

func TestObjectResponseHeaderSetters(t *testing.T) {
	obj := &backend.Object{
		RetentionMode:        backend.RetentionModeGovernance,
		RetainUntilDate:      ptrTime(time.Date(2026, 2, 7, 12, 0, 0, 0, time.UTC)),
		LegalHoldStatus:      backend.LegalHoldStatusOn,
		StorageClass:         "STANDARD_IA",
		ServerSideEncryption: "AES256",
		SSEKMSKeyId:          "kms-key",
		SSECustomerAlgorithm: "AES256",
		SSECustomerKeyMD5:    "abc",
		ChecksumAlgorithm:    "SHA256",
		ChecksumCRC32:        "crc32",
		ChecksumCRC32C:       "crc32c",
		ChecksumSHA1:         "sha1",
		ChecksumSHA256:       "sha256",
	}

	w := httptest.NewRecorder()
	setObjectLockHeaders(w, obj)
	setStorageAndEncryptionHeaders(w, obj)
	setChecksumResponseHeaders(w, obj)

	if got := w.Header().Get("x-amz-object-lock-mode"); got != backend.RetentionModeGovernance {
		t.Fatalf("unexpected lock mode header: %q", got)
	}
	if got := w.Header().Get("x-amz-object-lock-retain-until-date"); got == "" {
		t.Fatal("retain-until header should be set")
	}
	if got := w.Header().Get("x-amz-object-lock-legal-hold"); got != backend.LegalHoldStatusOn {
		t.Fatalf("unexpected legal hold header: %q", got)
	}
	if got := w.Header().Get("x-amz-storage-class"); got != "STANDARD_IA" {
		t.Fatalf("unexpected storage class header: %q", got)
	}
	if got := w.Header().Get("x-amz-server-side-encryption"); got != "AES256" {
		t.Fatalf("unexpected SSE header: %q", got)
	}
	if got := w.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"); got != "kms-key" {
		t.Fatalf("unexpected SSE KMS header: %q", got)
	}
	if got := w.Header().Get("x-amz-server-side-encryption-customer-algorithm"); got != "AES256" {
		t.Fatalf("unexpected SSE-C algorithm header: %q", got)
	}
	if got := w.Header().Get("x-amz-server-side-encryption-customer-key-md5"); got != "abc" {
		t.Fatalf("unexpected SSE-C key md5 header: %q", got)
	}
	if got := w.Header().Get("x-amz-checksum-algorithm"); got != "SHA256" {
		t.Fatalf("unexpected checksum algorithm header: %q", got)
	}
	if got := w.Header().Get("x-amz-checksum-crc32"); got != "crc32" {
		t.Fatalf("unexpected checksum crc32 header: %q", got)
	}
	if got := w.Header().Get("x-amz-checksum-crc32c"); got != "crc32c" {
		t.Fatalf("unexpected checksum crc32c header: %q", got)
	}
	if got := w.Header().Get("x-amz-checksum-sha1"); got != "sha1" {
		t.Fatalf("unexpected checksum sha1 header: %q", got)
	}
	if got := w.Header().Get("x-amz-checksum-sha256"); got != "sha256" {
		t.Fatalf("unexpected checksum sha256 header: %q", got)
	}

	w2 := httptest.NewRecorder()
	setStorageAndEncryptionHeaders(w2, &backend.Object{StorageClass: "STANDARD"})
	if got := w2.Header().Get("x-amz-storage-class"); got != "" {
		t.Fatalf("STANDARD should not be emitted as storage class header, got %q", got)
	}
}

func TestValidateSSEHeaders(t *testing.T) {
	req := func() *http.Request {
		return httptest.NewRequest(http.MethodPut, "http://example.test/bucket/key", nil)
	}

	t.Run("invalid algorithm", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption", "invalid")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("sse-c and sse-s3 are mutually exclusive", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption", "AES256")
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set(
			"x-amz-server-side-encryption-customer-key",
			base64.StdEncoding.EncodeToString([]byte("secret")),
		)
		r.Header.Set("x-amz-server-side-encryption-customer-key-md5", "dummy")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("kms key without kms algorithm", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption", "AES256")
		r.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", "kms")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("incomplete sse-c headers", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("invalid sse-c key base64", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set("x-amz-server-side-encryption-customer-key", "@@not-base64@@")
		r.Header.Set("x-amz-server-side-encryption-customer-key-md5", "dummy")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("sse-c key md5 mismatch", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set(
			"x-amz-server-side-encryption-customer-key",
			base64.StdEncoding.EncodeToString([]byte("secret")),
		)
		r.Header.Set(
			"x-amz-server-side-encryption-customer-key-md5",
			base64.StdEncoding.EncodeToString([]byte("mismatch")),
		)
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})

	t.Run("valid sse-c", func(t *testing.T) {
		r := req()
		key := []byte("secret")
		keyB64 := base64.StdEncoding.EncodeToString(key)
		sum := md5.Sum(key)
		md5B64 := base64.StdEncoding.EncodeToString(sum[:])
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set("x-amz-server-side-encryption-customer-key", keyB64)
		r.Header.Set("x-amz-server-side-encryption-customer-key-md5", md5B64)
		if code, msg := validateSSEHeaders(r); code != "" || msg != "" {
			t.Fatalf("expected valid headers, got code=%q msg=%q", code, msg)
		}
	})

	t.Run("valid kms", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption", "aws:kms")
		r.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", "kms")
		if code, msg := validateSSEHeaders(r); code != "" || msg != "" {
			t.Fatalf("expected valid headers, got code=%q msg=%q", code, msg)
		}
	})

	t.Run("kms algorithm without key id", func(t *testing.T) {
		r := req()
		r.Header.Set("x-amz-server-side-encryption", "aws:kms")
		if code, _ := validateSSEHeaders(r); code != "InvalidArgument" {
			t.Fatalf("expected InvalidArgument, got %q", code)
		}
	})
}

func TestValidateSSECAccess(t *testing.T) {
	obj := &backend.Object{SSECustomerAlgorithm: "AES256", SSECustomerKeyMD5: "expected-md5"}

	t.Run("not sse-c object", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		if denied := validateSSECAccess(w, r, &backend.Object{}); denied {
			t.Fatal("unexpected deny for non-SSE-C object")
		}
	})

	t.Run("missing algorithm header", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		if denied := validateSSECAccess(w, r, obj); !denied {
			t.Fatal("expected access denial")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 status, got %d", w.Code)
		}
	})

	t.Run("md5 mismatch", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set("x-amz-server-side-encryption-customer-key-md5", "wrong")
		if denied := validateSSECAccess(w, r, obj); !denied {
			t.Fatal("expected access denial")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 status, got %d", w.Code)
		}
	})

	t.Run("matching sse-c headers", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
		r.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		r.Header.Set("x-amz-server-side-encryption-customer-key-md5", "expected-md5")
		if denied := validateSSECAccess(w, r, obj); denied {
			t.Fatal("did not expect access denial")
		}
	})
}

func TestInferChecksumAlgorithmFromTrailer(t *testing.T) {
	tests := []struct {
		trailer string
		want    string
	}{
		{trailer: "x-amz-checksum-crc32c", want: "CRC32C"},
		{trailer: "x-amz-checksum-crc32", want: "CRC32"},
		{trailer: "x-amz-checksum-sha1", want: "SHA1"},
		{trailer: "x-amz-checksum-sha256", want: "SHA256"},
		{trailer: "x-custom-trailer", want: ""},
	}
	for _, tt := range tests {
		if got := inferChecksumAlgorithmFromTrailer(tt.trailer); got != tt.want {
			t.Fatalf(
				"inferChecksumAlgorithmFromTrailer(%q) = %q, want %q",
				tt.trailer,
				got,
				tt.want,
			)
		}
	}
}

func TestGetPartData(t *testing.T) {
	obj := &backend.Object{Data: []byte("hello"), Size: 5}
	if data, size, _, ok := getPartData(obj, 1); !ok || string(data) != "hello" || size != 5 {
		t.Fatalf(
			"unexpected non-multipart part 1 result: data=%q size=%d ok=%v",
			string(data),
			size,
			ok,
		)
	}
	if _, _, _, ok := getPartData(obj, 2); ok {
		t.Fatal("expected part 2 to be missing for non-multipart object")
	}

	multipartObj := &backend.Object{
		Data: []byte("abcdef"),
		Parts: []backend.ObjectPart{
			{PartNumber: 1, Size: 2},
			{PartNumber: 2, Size: 4},
		},
	}
	if data, size, _, ok := getPartData(multipartObj, 2); !ok || string(data) != "cdef" || size != 4 {
		t.Fatalf("unexpected multipart part result: data=%q size=%d ok=%v", string(data), size, ok)
	}

	clampedObj := &backend.Object{
		Data: []byte("abc"),
		Parts: []backend.ObjectPart{
			{PartNumber: 1, Size: 2},
			{PartNumber: 2, Size: 5},
		},
	}
	if data, size, _, ok := getPartData(clampedObj, 2); !ok || string(data) != "c" || size != 5 {
		t.Fatalf(
			"unexpected clamped multipart part result: data=%q size=%d ok=%v",
			string(data),
			size,
			ok,
		)
	}
}

func TestParseRangeHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		size      int64
		wantStart int64
		wantEnd   int64
		wantErr   bool
	}{
		{name: "invalid prefix", header: "items=0-1", size: 10, wantErr: true},
		{name: "suffix range", header: "bytes=-3", size: 10, wantStart: 7, wantEnd: 9},
		{
			name:      "suffix larger than object",
			header:    "bytes=-20",
			size:      10,
			wantStart: 0,
			wantEnd:   9,
		},
		{name: "open ended", header: "bytes=3-", size: 10, wantStart: 3, wantEnd: 9},
		{name: "closed range", header: "bytes=2-5", size: 10, wantStart: 2, wantEnd: 5},
		{name: "end clamped", header: "bytes=7-100", size: 10, wantStart: 7, wantEnd: 9},
		{name: "start greater than end", header: "bytes=6-2", size: 10, wantErr: true},
		{name: "start out of range", header: "bytes=10-12", size: 10, wantErr: true},
		{name: "invalid number", header: "bytes=a-1", size: 10, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parseRangeHeader(tt.header, tt.size)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseRangeHeader error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if start != tt.wantStart || end != tt.wantEnd {
				t.Fatalf(
					"parseRangeHeader(%q) = (%d, %d), want (%d, %d)",
					tt.header,
					start,
					end,
					tt.wantStart,
					tt.wantEnd,
				)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
