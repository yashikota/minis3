package backend

import "testing"

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
