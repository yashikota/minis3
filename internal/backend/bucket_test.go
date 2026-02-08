package backend

import (
	"errors"
	"testing"
)

func TestValidateBucketName(t *testing.T) {
	tests := []struct {
		name    string
		bucket  string
		wantErr bool
	}{
		// Valid names
		{"valid simple", "my-bucket", false},
		{"valid with numbers", "bucket123", false},
		{"valid with periods", "my.bucket.name", false},
		{"valid min length", "abc", false},
		{
			"valid 63 chars",
			"a123456789012345678901234567890123456789012345678901234567890bc",
			false,
		},

		// Invalid: length
		{"too short 2 chars", "ab", true},
		{
			"too long 64 chars",
			"a1234567890123456789012345678901234567890123456789012345678901234",
			true,
		},

		// Invalid: uppercase
		{"uppercase letters", "MyBucket", true},
		{"mixed case", "my-Bucket-123", true},

		// Invalid: invalid characters
		{"underscore", "my_bucket", true},
		{"space", "my bucket", true},
		{"special chars", "my@bucket", true},

		// Invalid: start/end
		{"starts with hyphen", "-mybucket", true},
		{"ends with hyphen", "mybucket-", true},
		{"starts with period", ".mybucket", true},
		{"ends with period", "mybucket.", true},

		// Invalid: consecutive periods
		{"consecutive periods", "my..bucket", true},

		// Invalid: IP address format
		{"ip address", "192.168.1.1", true},
		{"ip like", "10.0.0.1", true},

		// Invalid: period adjacent to hyphen
		{"period before hyphen", "my.-bucket", true},
		{"hyphen before period", "my-.bucket", true},

		// Invalid: prohibited prefixes
		{"xn-- prefix", "xn--mybucket", true},
		{"sthree- prefix", "sthree-mybucket", true},
		{"sthree-accesspoint- prefix", "sthree-accesspoint-mybucket", true},
		{"amzn-s3-demo- prefix", "amzn-s3-demo-bucket", true},

		// Invalid: prohibited suffixes
		{"-s3alias suffix", "mybucket-s3alias", true},
		{"--ol-s3 suffix", "mybucket--ol-s3", true},
		{".mrap suffix", "mybucket.mrap", true},
		{"--x-s3 suffix", "mybucket--x-s3", true},
		{"--table-s3 suffix", "mybucket--table-s3", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBucketName(tt.bucket)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ValidateBucketName(%q) error = %v, wantErr %v",
					tt.bucket,
					err,
					tt.wantErr,
				)
			}
		})
	}
}

func TestGetBucketLocation(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	t.Run("existing bucket", func(t *testing.T) {
		location, err := b.GetBucketLocation("test-bucket")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Default location is empty (us-east-1)
		if location != "" {
			t.Errorf("expected empty location, got %q", location)
		}
	})

	t.Run("non-existent bucket", func(t *testing.T) {
		_, err := b.GetBucketLocation("non-existent")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Errorf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("set location constraint", func(t *testing.T) {
		if err := b.SetBucketLocation("test-bucket", "us-west-2"); err != nil {
			t.Fatalf("SetBucketLocation failed: %v", err)
		}
		location, err := b.GetBucketLocation("test-bucket")
		if err != nil {
			t.Fatalf("GetBucketLocation failed: %v", err)
		}
		if location != "us-west-2" {
			t.Fatalf("expected us-west-2, got %q", location)
		}
	})

	t.Run("set location non-existent bucket", func(t *testing.T) {
		err := b.SetBucketLocation("non-existent", "ap-northeast-1")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Errorf("expected ErrBucketNotFound, got %v", err)
		}
	})
}

func TestBucketTagging(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	t.Run("no tags initially", func(t *testing.T) {
		_, err := b.GetBucketTagging("test-bucket")
		if !errors.Is(err, ErrNoSuchTagSet) {
			t.Errorf("expected ErrNoSuchTagSet, got %v", err)
		}
	})

	t.Run("put and get tags", func(t *testing.T) {
		tags := map[string]string{"Project": "Test", "Environment": "Dev"}
		err := b.PutBucketTagging("test-bucket", tags)
		if err != nil {
			t.Fatalf("PutBucketTagging failed: %v", err)
		}

		result, err := b.GetBucketTagging("test-bucket")
		if err != nil {
			t.Fatalf("GetBucketTagging failed: %v", err)
		}

		if result["Project"] != "Test" || result["Environment"] != "Dev" {
			t.Errorf("tags mismatch: %v", result)
		}
	})

	t.Run("delete tags", func(t *testing.T) {
		err := b.DeleteBucketTagging("test-bucket")
		if err != nil {
			t.Fatalf("DeleteBucketTagging failed: %v", err)
		}

		_, err = b.GetBucketTagging("test-bucket")
		if !errors.Is(err, ErrNoSuchTagSet) {
			t.Errorf("expected ErrNoSuchTagSet after delete, got %v", err)
		}
	})

	t.Run("non-existent bucket", func(t *testing.T) {
		_, err := b.GetBucketTagging("non-existent")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Errorf("expected ErrBucketNotFound, got %v", err)
		}
	})
}

func TestBucketPolicy(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	validPolicy := `{"Version":"2012-10-17","Statement":[]}`
	invalidPolicy := `{invalid json}`

	t.Run("no policy initially", func(t *testing.T) {
		_, err := b.GetBucketPolicy("test-bucket")
		if !errors.Is(err, ErrNoSuchBucketPolicy) {
			t.Errorf("expected ErrNoSuchBucketPolicy, got %v", err)
		}
	})

	t.Run("put valid policy", func(t *testing.T) {
		err := b.PutBucketPolicy("test-bucket", validPolicy)
		if err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		result, err := b.GetBucketPolicy("test-bucket")
		if err != nil {
			t.Fatalf("GetBucketPolicy failed: %v", err)
		}

		if result != validPolicy {
			t.Errorf("policy mismatch: got %q, want %q", result, validPolicy)
		}
	})

	t.Run("put invalid policy", func(t *testing.T) {
		err := b.PutBucketPolicy("test-bucket", invalidPolicy)
		if !errors.Is(err, ErrMalformedPolicy) {
			t.Errorf("expected ErrMalformedPolicy, got %v", err)
		}
	})

	t.Run("delete policy", func(t *testing.T) {
		// First set a valid policy
		_ = b.PutBucketPolicy("test-bucket", validPolicy)

		err := b.DeleteBucketPolicy("test-bucket")
		if err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}

		_, err = b.GetBucketPolicy("test-bucket")
		if !errors.Is(err, ErrNoSuchBucketPolicy) {
			t.Errorf("expected ErrNoSuchBucketPolicy after delete, got %v", err)
		}
	})

	t.Run("non-existent bucket", func(t *testing.T) {
		_, err := b.GetBucketPolicy("non-existent")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Errorf("expected ErrBucketNotFound, got %v", err)
		}
	})
}

func TestIsValidJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid object", `{"key": "value"}`, true},
		{"valid array", `["a", "b"]`, true},
		{"valid nested", `{"nested": {"key": "value"}}`, true},
		{"valid with escapes", `{"key": "value with \"quotes\""}`, true},
		{"empty string", ``, false},
		{"not json", `hello`, false},
		{"unbalanced braces", `{"key": "value"`, false},
		{"unbalanced brackets", `["a", "b"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidJSON(tt.input)
			if got != tt.want {
				t.Errorf("isValidJSON(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetBucketUsage(t *testing.T) {
	b := New()

	t.Run("non-existent bucket", func(t *testing.T) {
		_, _, err := b.GetBucketUsage("no-such-bucket")
		if !errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("expected ErrBucketNotFound, got %v", err)
		}
	})

	t.Run("unversioned bucket reflects current objects and bytes", func(t *testing.T) {
		if err := b.CreateBucket("usage-unversioned"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if _, err := b.PutObject("usage-unversioned", "a", []byte("abc"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject a failed: %v", err)
		}
		if _, err := b.PutObject("usage-unversioned", "b", []byte("hello"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject b failed: %v", err)
		}

		count, bytesUsed, err := b.GetBucketUsage("usage-unversioned")
		if err != nil {
			t.Fatalf("GetBucketUsage failed: %v", err)
		}
		if count != 2 || bytesUsed != 8 {
			t.Fatalf("unexpected usage before delete: count=%d bytes=%d", count, bytesUsed)
		}

		if _, err := b.DeleteObject("usage-unversioned", "a", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		count, bytesUsed, err = b.GetBucketUsage("usage-unversioned")
		if err != nil {
			t.Fatalf("GetBucketUsage failed: %v", err)
		}
		if count != 1 || bytesUsed != 5 {
			t.Fatalf("unexpected usage after delete: count=%d bytes=%d", count, bytesUsed)
		}
	})

	t.Run("latest delete marker still counts latest non-delete version", func(t *testing.T) {
		if err := b.CreateBucket("usage-versioned"); err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
		if err := b.SetBucketVersioning("usage-versioned", VersioningEnabled, MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}

		if _, err := b.PutObject("usage-versioned", "k", []byte("abc"), PutObjectOptions{}); err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		if _, err := b.DeleteObject("usage-versioned", "k", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}

		count, bytesUsed, err := b.GetBucketUsage("usage-versioned")
		if err != nil {
			t.Fatalf("GetBucketUsage failed: %v", err)
		}
		if count != 1 || bytesUsed != 3 {
			t.Fatalf(
				"unexpected usage with delete marker latest: count=%d bytes=%d",
				count,
				bytesUsed,
			)
		}
	})
}
