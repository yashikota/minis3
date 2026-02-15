package backend

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func mustCreateBucketCov(t *testing.T, b *Backend, name string) {
	t.Helper()
	if err := b.CreateBucket(name); err != nil {
		t.Fatalf("CreateBucket(%q) failed: %v", name, err)
	}
}

func TestBackendBucketControlsAndLoggingCoverage(t *testing.T) {
	b := New()
	mustCreateBucketCov(t, b, "src-controls")
	mustCreateBucketCov(t, b, "dst-controls")
	mustCreateBucketCov(t, b, "third-controls")

	if err := ValidateBucketName("tenant:"); !errors.Is(err, ErrInvalidBucketName) {
		t.Fatalf("ValidateBucketName trailing colon = %v, want ErrInvalidBucketName", err)
	}
	if err := ValidateBucketName("tenant:abc-bucket"); err != nil {
		t.Fatalf("ValidateBucketName tenant-prefixed valid name failed: %v", err)
	}
	if !isSupportedBucketPolicy(
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`,
	) {
		t.Fatal("isSupportedBucketPolicy should support map-style Statement")
	}

	// Cover SetBucketOwner path when ACL already exists.
	b.SetBucketOwner("src-controls", "minis3-access-key")
	b.SetBucketOwner("src-controls", "root-access-key")
	srcBucket, ok := b.GetBucket("src-controls")
	if !ok || srcBucket == nil || srcBucket.ACL == nil || srcBucket.ACL.Owner == nil ||
		srcBucket.ACL.Owner.DisplayName != "root" {
		t.Fatalf("SetBucketOwner should refresh ACL owner, got %+v", srcBucket)
	}

	if _, err := b.IsBucketACLEnabled("missing-controls"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("IsBucketACLEnabled missing = %v, want ErrBucketNotFound", err)
	}
	if enabled, err := b.IsBucketACLEnabled("src-controls"); err != nil || !enabled {
		t.Fatalf("IsBucketACLEnabled default = (%v,%v), want (true,nil)", enabled, err)
	}

	if _, err := b.GetBucketOwnershipControls("missing-controls"); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("GetBucketOwnershipControls missing = %v, want ErrBucketNotFound", err)
	}
	if _, err := b.GetBucketOwnershipControls("src-controls"); !errors.Is(
		err,
		ErrOwnershipControlsNotFound,
	) {
		t.Fatalf(
			"GetBucketOwnershipControls unset = %v, want ErrOwnershipControlsNotFound",
			err,
		)
	}
	if err := b.PutBucketOwnershipControls("missing-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerPreferred}},
	}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("PutBucketOwnershipControls missing = %v, want ErrBucketNotFound", err)
	}
	if err := b.PutBucketOwnershipControls("src-controls", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketOwnershipControls nil = %v, want ErrInvalidRequest", err)
	}
	if err := b.PutBucketOwnershipControls("src-controls", &OwnershipControls{}); !errors.Is(
		err,
		ErrInvalidRequest,
	) {
		t.Fatalf("PutBucketOwnershipControls empty rules = %v, want ErrInvalidRequest", err)
	}
	if err := b.PutBucketOwnershipControls("src-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: "invalid"}},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketOwnershipControls invalid mode = %v, want ErrInvalidRequest", err)
	}

	// Incompatible ACL (group grant) is rejected for BucketOwnerEnforced.
	if err := b.PutBucketACL("src-controls", CannedACLToPolicy(string(ACLPublicRead))); err != nil {
		t.Fatalf("PutBucketACL public-read failed: %v", err)
	}
	if err := b.PutBucketOwnershipControls("src-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerEnforced}},
	}); !errors.Is(err, ErrInvalidBucketAclWithObjectOwnership) {
		t.Fatalf(
			"PutBucketOwnershipControls incompatible ACL = %v, want ErrInvalidBucketAclWithObjectOwnership",
			err,
		)
	}
	if err := b.PutBucketACL("src-controls", NewDefaultACLForOwner(OwnerForAccessKey("root-access-key"))); err != nil {
		t.Fatalf("PutBucketACL owner-only failed: %v", err)
	}
	if err := b.PutBucketOwnershipControls("src-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerEnforced}},
	}); err != nil {
		t.Fatalf("PutBucketOwnershipControls enforced failed: %v", err)
	}
	if enabled, err := b.IsBucketACLEnabled("src-controls"); err != nil || enabled {
		t.Fatalf("IsBucketACLEnabled enforced = (%v,%v), want (false,nil)", enabled, err)
	}
	controls, err := b.GetBucketOwnershipControls("src-controls")
	if err != nil || controls == nil || len(controls.Rules) != 1 ||
		controls.Rules[0].ObjectOwnership != ObjectOwnershipBucketOwnerEnforced {
		t.Fatalf("GetBucketOwnershipControls enforced got controls=%+v err=%v", controls, err)
	}

	if err := b.DeleteBucketOwnershipControls("missing-controls"); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("DeleteBucketOwnershipControls missing = %v, want ErrBucketNotFound", err)
	}
	if err := b.DeleteBucketOwnershipControls("src-controls"); err != nil {
		t.Fatalf("DeleteBucketOwnershipControls failed: %v", err)
	}
	if _, err := b.GetBucketOwnershipControls("src-controls"); !errors.Is(
		err,
		ErrOwnershipControlsNotFound,
	) {
		t.Fatalf("GetBucketOwnershipControls after delete = %v, want ErrOwnershipControlsNotFound", err)
	}

	if !bucketACLCompatibleWithOwnerEnforced(&Bucket{
		OwnerAccessKey: "minis3-access-key",
		ACL: &AccessControlPolicy{
			AccessControlList: AccessControlList{Grants: []Grant{
				{Grantee: nil, Permission: PermissionRead},
				{
					Grantee: &Grantee{
						Type: "CanonicalUser",
						ID:   OwnerForAccessKey("minis3-access-key").ID,
					},
					Permission: PermissionFullControl,
				},
			}},
		},
	}) {
		t.Fatal("bucketACLCompatibleWithOwnerEnforced should allow nil grantee + owner grantee")
	}
	if !bucketACLCompatibleWithOwnerEnforced(&Bucket{
		OwnerAccessKey: "",
		ACL: &AccessControlPolicy{
			AccessControlList: AccessControlList{Grants: []Grant{{
				Grantee: &Grantee{Type: "CanonicalUser", ID: DefaultOwner().ID},
			}}},
		},
	}) {
		t.Fatal("bucketACLCompatibleWithOwnerEnforced should allow default-owner canonical grant")
	}

	if _, err := b.GetBucketLogging("missing-controls"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("GetBucketLogging missing = %v, want ErrBucketNotFound", err)
	}
	logDefault, err := b.GetBucketLogging("src-controls")
	if err != nil || logDefault == nil || logDefault.LoggingEnabled != nil {
		t.Fatalf("GetBucketLogging default = (%+v,%v), want empty config", logDefault, err)
	}

	if err := b.PutBucketLogging("missing-controls", &BucketLoggingStatus{}); !errors.Is(
		err,
		ErrBucketNotFound,
	) {
		t.Fatalf("PutBucketLogging missing bucket = %v, want ErrBucketNotFound", err)
	}
	if err := b.PutBucketLogging("src-controls", nil); err != nil {
		t.Fatalf("PutBucketLogging disable(nil) failed: %v", err)
	}
	srcBucket, _ = b.GetBucket("src-controls")
	if srcBucket.LoggingConfiguration != nil || srcBucket.LoggingConfigModifiedAt.IsZero() ||
		srcBucket.LoggingObjectKey != "" {
		t.Fatalf("PutBucketLogging disable(nil) should clear state, got %+v", srcBucket)
	}
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "missing-target", TargetPrefix: "logs/"},
	}); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("PutBucketLogging missing target = %v, want ErrObjectNotFound", err)
	}
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "src-controls", TargetPrefix: "logs/"},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketLogging same target bucket = %v, want ErrInvalidRequest", err)
	}

	dstBucket, _ := b.GetBucket("dst-controls")
	dstBucket.LoggingConfiguration = &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "third-controls", TargetPrefix: "logs/"},
	}
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs/"},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketLogging target with logging enabled = %v, want ErrInvalidRequest", err)
	}
	dstBucket.LoggingConfiguration = nil

	dstBucket.EncryptionConfiguration = &ServerSideEncryptionConfiguration{
		Rules: []ServerSideEncryptionRule{{
			ApplyServerSideEncryptionByDefault: &ServerSideEncryptionByDefault{
				SSEAlgorithm: SSEAlgorithmAES256,
			},
		}},
	}
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs/"},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketLogging encrypted target = %v, want ErrInvalidRequest", err)
	}
	dstBucket.EncryptionConfiguration = nil

	if err := b.PutBucketRequestPayment(
		"dst-controls",
		&RequestPaymentConfiguration{Payer: RequestPayerRequester},
	); err != nil {
		t.Fatalf("PutBucketRequestPayment requester setup failed: %v", err)
	}
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs/"},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketLogging requester-pays target = %v, want ErrInvalidRequest", err)
	}
	if err := b.PutBucketRequestPayment(
		"dst-controls",
		&RequestPaymentConfiguration{Payer: RequestPayerBucketOwner},
	); err != nil {
		t.Fatalf("PutBucketRequestPayment reset failed: %v", err)
	}

	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs/"},
	}); err != nil {
		t.Fatalf("PutBucketLogging success failed: %v", err)
	}
	// Manually sparse config to cover GetBucketLogging normalization.
	srcBucket, _ = b.GetBucket("src-controls")
	srcBucket.LoggingConfiguration = &BucketLoggingStatus{LoggingEnabled: &LoggingEnabled{
		TargetBucket: "dst-controls",
		TargetPrefix: "logs/",
	}}
	afterPut, err := b.GetBucketLogging("src-controls")
	if err != nil || afterPut == nil || afterPut.LoggingEnabled == nil {
		t.Fatalf("GetBucketLogging after put = (%+v,%v), want enabled config", afterPut, err)
	}
	if afterPut.LoggingEnabled.TargetObjectKeyFormat == nil ||
		afterPut.LoggingEnabled.TargetObjectKeyFormat.SimplePrefix == nil {
		t.Fatalf("TargetObjectKeyFormat should default to SimplePrefix, got %+v", afterPut)
	}
	if afterPut.LoggingEnabled.LoggingType != BucketLoggingTypeStandard {
		t.Fatalf("LoggingType default = %q, want %q", afterPut.LoggingEnabled.LoggingType, BucketLoggingTypeStandard)
	}
	if afterPut.LoggingEnabled.ObjectRollTime != DefaultObjectRollTime {
		t.Fatalf("ObjectRollTime default = %d, want %d", afterPut.LoggingEnabled.ObjectRollTime, DefaultObjectRollTime)
	}

	srcBucket, _ = b.GetBucket("src-controls")
	firstModified := srcBucket.LoggingConfigModifiedAt
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs/"},
	}); err != nil {
		t.Fatalf("PutBucketLogging identical config failed: %v", err)
	}
	srcBucket, _ = b.GetBucket("src-controls")
	if !srcBucket.LoggingConfigModifiedAt.Equal(firstModified) {
		t.Fatalf("LoggingConfigModifiedAt should remain unchanged for identical config")
	}

	time.Sleep(2 * time.Millisecond)
	if err := b.PutBucketLogging("src-controls", &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{TargetBucket: "dst-controls", TargetPrefix: "logs2/"},
	}); err != nil {
		t.Fatalf("PutBucketLogging changed config failed: %v", err)
	}
	srcBucket, _ = b.GetBucket("src-controls")
	if !srcBucket.LoggingConfigModifiedAt.After(firstModified) {
		t.Fatalf(
			"LoggingConfigModifiedAt should advance for changed config: old=%v new=%v",
			firstModified,
			srcBucket.LoggingConfigModifiedAt,
		)
	}

	if err := b.DeleteBucketLogging("missing-controls"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("DeleteBucketLogging missing = %v, want ErrBucketNotFound", err)
	}
	if err := b.DeleteBucketLogging("src-controls"); err != nil {
		t.Fatalf("DeleteBucketLogging failed: %v", err)
	}
	srcBucket, _ = b.GetBucket("src-controls")
	if srcBucket.LoggingConfiguration != nil || srcBucket.LoggingObjectKey != "" {
		t.Fatalf("DeleteBucketLogging should clear config, got %+v", srcBucket.LoggingConfiguration)
	}

	if _, err := b.GetBucketRequestPayment("missing-controls"); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("GetBucketRequestPayment missing = %v, want ErrBucketNotFound", err)
	}
	if err := b.PutBucketRequestPayment("missing-controls", &RequestPaymentConfiguration{
		Payer: RequestPayerBucketOwner,
	}); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("PutBucketRequestPayment missing = %v, want ErrBucketNotFound", err)
	}
	if err := b.PutBucketRequestPayment("src-controls", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketRequestPayment nil = %v, want ErrInvalidRequest", err)
	}
	if err := b.PutBucketRequestPayment("src-controls", &RequestPaymentConfiguration{
		Payer: "Invalid",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("PutBucketRequestPayment invalid payer = %v, want ErrInvalidRequest", err)
	}

	srcBucket, _ = b.GetBucket("src-controls")
	srcBucket.RequestPaymentPayer = ""
	cfg, err := b.GetBucketRequestPayment("src-controls")
	if err != nil || cfg == nil || cfg.Payer != RequestPayerBucketOwner {
		t.Fatalf("GetBucketRequestPayment default = (%+v,%v), want BucketOwner", cfg, err)
	}
	if err := b.PutBucketRequestPayment("src-controls", &RequestPaymentConfiguration{
		Payer: RequestPayerRequester,
	}); err != nil {
		t.Fatalf("PutBucketRequestPayment requester failed: %v", err)
	}
	cfg, err = b.GetBucketRequestPayment("src-controls")
	if err != nil || cfg == nil || cfg.Payer != RequestPayerRequester {
		t.Fatalf("GetBucketRequestPayment requester = (%+v,%v), want Requester", cfg, err)
	}
}

func TestBackendBucketLoggingEqualityHelpersCoverage(t *testing.T) {
	if !bucketLoggingConfigEqual(nil, nil) {
		t.Fatal("bucketLoggingConfigEqual(nil,nil) should be true")
	}
	if bucketLoggingConfigEqual(nil, &BucketLoggingStatus{LoggingEnabled: &LoggingEnabled{}}) {
		t.Fatal("bucketLoggingConfigEqual(nil,non-nil) should be false")
	}
	if bucketLoggingConfigEqual(&BucketLoggingStatus{LoggingEnabled: &LoggingEnabled{}}, nil) {
		t.Fatal("bucketLoggingConfigEqual(non-nil,nil) should be false")
	}
	if !bucketLoggingConfigEqual(
		&BucketLoggingStatus{LoggingEnabled: &LoggingEnabled{
			TargetBucket: "target", TargetPrefix: "logs/", LoggingType: BucketLoggingTypeStandard, ObjectRollTime: DefaultObjectRollTime,
		}},
		&BucketLoggingStatus{LoggingEnabled: &LoggingEnabled{
			TargetBucket: "target", TargetPrefix: "logs/", LoggingType: "", ObjectRollTime: 0,
		}},
	) {
		t.Fatal("bucketLoggingConfigEqual should normalize defaults on b side")
	}

	base := &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{
			TargetBucket:     "target",
			TargetPrefix:     "logs/",
			LoggingType:      "",
			ObjectRollTime:   0,
			RecordsBatchSize: 10,
			Filter: &LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{
				Name:  "prefix",
				Value: "a/",
			}}}},
			TargetObjectKeyFormat: nil,
		},
	}
	sameNormalized := &BucketLoggingStatus{
		LoggingEnabled: &LoggingEnabled{
			TargetBucket:     "target",
			TargetPrefix:     "logs/",
			LoggingType:      BucketLoggingTypeStandard,
			ObjectRollTime:   DefaultObjectRollTime,
			RecordsBatchSize: 10,
			Filter: &LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{
				Name:  "prefix",
				Value: "a/",
			}}}},
			TargetObjectKeyFormat: &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
		},
	}
	if !bucketLoggingConfigEqual(base, sameNormalized) {
		t.Fatal("bucketLoggingConfigEqual should treat normalized defaults as equal")
	}
	diffBucket := *sameNormalized
	diffBucket.LoggingEnabled = &LoggingEnabled{TargetBucket: "other", TargetPrefix: "logs/"}
	if bucketLoggingConfigEqual(base, &diffBucket) {
		t.Fatal("bucketLoggingConfigEqual should detect target bucket mismatch")
	}
	diffType := *sameNormalized
	diffType.LoggingEnabled = &LoggingEnabled{
		TargetBucket:          "target",
		TargetPrefix:          "logs/",
		LoggingType:           BucketLoggingTypeJournal,
		ObjectRollTime:        DefaultObjectRollTime,
		RecordsBatchSize:      10,
		Filter:                sameNormalized.LoggingEnabled.Filter,
		TargetObjectKeyFormat: &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	}
	if bucketLoggingConfigEqual(base, &diffType) {
		t.Fatal("bucketLoggingConfigEqual should detect logging type mismatch")
	}
	diffRoll := *sameNormalized
	diffRoll.LoggingEnabled = &LoggingEnabled{
		TargetBucket:          "target",
		TargetPrefix:          "logs/",
		LoggingType:           BucketLoggingTypeStandard,
		ObjectRollTime:        DefaultObjectRollTime + 1,
		RecordsBatchSize:      10,
		Filter:                sameNormalized.LoggingEnabled.Filter,
		TargetObjectKeyFormat: &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	}
	if bucketLoggingConfigEqual(base, &diffRoll) {
		t.Fatal("bucketLoggingConfigEqual should detect roll time mismatch")
	}
	diffBatch := *sameNormalized
	diffBatch.LoggingEnabled = &LoggingEnabled{
		TargetBucket:          "target",
		TargetPrefix:          "logs/",
		LoggingType:           BucketLoggingTypeStandard,
		ObjectRollTime:        DefaultObjectRollTime,
		RecordsBatchSize:      11,
		Filter:                sameNormalized.LoggingEnabled.Filter,
		TargetObjectKeyFormat: &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	}
	if bucketLoggingConfigEqual(base, &diffBatch) {
		t.Fatal("bucketLoggingConfigEqual should detect batch size mismatch")
	}
	diffFilter := *sameNormalized
	diffFilter.LoggingEnabled = &LoggingEnabled{
		TargetBucket:     "target",
		TargetPrefix:     "logs/",
		LoggingType:      BucketLoggingTypeStandard,
		ObjectRollTime:   DefaultObjectRollTime,
		RecordsBatchSize: 10,
		Filter: &LoggingFilter{
			Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "suffix", Value: ".txt"}}},
		},
		TargetObjectKeyFormat: &TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	}
	if bucketLoggingConfigEqual(base, &diffFilter) {
		t.Fatal("bucketLoggingConfigEqual should detect filter mismatch")
	}
	diffFormat := *sameNormalized
	diffFormat.LoggingEnabled = &LoggingEnabled{
		TargetBucket:     "target",
		TargetPrefix:     "logs/",
		LoggingType:      BucketLoggingTypeStandard,
		ObjectRollTime:   DefaultObjectRollTime,
		RecordsBatchSize: 10,
		Filter:           sameNormalized.LoggingEnabled.Filter,
		TargetObjectKeyFormat: &TargetObjectKeyFormat{
			PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "DeliveryTime"},
		},
	}
	if bucketLoggingConfigEqual(base, &diffFormat) {
		t.Fatal("bucketLoggingConfigEqual should detect target object key format mismatch")
	}

	if !bucketLoggingFilterEqual(nil, nil) {
		t.Fatal("bucketLoggingFilterEqual(nil,nil) should be true")
	}
	if !bucketLoggingFilterEqual(
		nil,
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{}}},
	) {
		t.Fatal("bucketLoggingFilterEqual(nil,empty) should be true")
	}
	if !bucketLoggingFilterEqual(
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{}}},
		nil,
	) {
		t.Fatal("bucketLoggingFilterEqual(empty,nil) should be true")
	}
	if bucketLoggingFilterEqual(
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "a/"}}}},
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{}}},
	) {
		t.Fatal("bucketLoggingFilterEqual should detect len mismatch")
	}
	if bucketLoggingFilterEqual(
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "a/"}}}},
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "suffix", Value: "a/"}}}},
	) {
		t.Fatal("bucketLoggingFilterEqual should detect rule name mismatch")
	}
	if bucketLoggingFilterEqual(
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "a/"}}}},
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "b/"}}}},
	) {
		t.Fatal("bucketLoggingFilterEqual should detect rule value mismatch")
	}
	if !bucketLoggingFilterEqual(
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "a/"}}}},
		&LoggingFilter{Key: &LoggingKeyFilter{FilterRules: []FilterRule{{Name: "prefix", Value: "a/"}}}},
	) {
		t.Fatal("bucketLoggingFilterEqual should accept equal rules")
	}

	if !bucketLogKeyFormatEqual(nil, nil) {
		t.Fatal("bucketLogKeyFormatEqual(nil,nil) should be true")
	}
	if bucketLogKeyFormatEqual(
		&TargetObjectKeyFormat{PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "DeliveryTime"}},
		&TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	) {
		t.Fatal("bucketLogKeyFormatEqual should detect simple/partitioned mismatch")
	}
	if bucketLogKeyFormatEqual(
		&TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
		&TargetObjectKeyFormat{
			SimplePrefix:      &SimplePrefix{},
			PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "EventTime"},
		},
	) {
		t.Fatal("bucketLogKeyFormatEqual should detect partitioned presence mismatch")
	}
	if !bucketLogKeyFormatEqual(
		&TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
		&TargetObjectKeyFormat{SimplePrefix: &SimplePrefix{}},
	) {
		t.Fatal("bucketLogKeyFormatEqual simple/simple should be true")
	}
	if bucketLogKeyFormatEqual(
		&TargetObjectKeyFormat{PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "DeliveryTime"}},
		&TargetObjectKeyFormat{PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "EventTime"}},
	) {
		t.Fatal("bucketLogKeyFormatEqual should detect partition date source mismatch")
	}
	if !bucketLogKeyFormatEqual(
		&TargetObjectKeyFormat{PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "DeliveryTime"}},
		&TargetObjectKeyFormat{PartitionedPrefix: &PartitionedPrefix{PartitionDateSource: "DeliveryTime"}},
	) {
		t.Fatal("bucketLogKeyFormatEqual partitioned equal should be true")
	}
}

func TestBackendObjectACLAndDeletePreconditionHelpersCoverage(t *testing.T) {
	b := New()
	mustCreateBucketCov(t, b, "objacl-controls")

	if err := b.PutBucketOwnershipControls("objacl-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerEnforced}},
	}); err != nil {
		t.Fatalf("PutBucketOwnershipControls enforced setup failed: %v", err)
	}
	if err := b.PutBucketACL("objacl-controls", NewDefaultACL()); !errors.Is(
		err,
		ErrAccessControlListNotSupported,
	) {
		t.Fatalf("PutBucketACL enforced = %v, want ErrAccessControlListNotSupported", err)
	}

	if err := b.PutBucketOwnershipControls("objacl-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerPreferred}},
	}); err != nil {
		t.Fatalf("PutBucketOwnershipControls preferred setup failed: %v", err)
	}
	if _, err := b.PutObject("objacl-controls", "k", []byte("data"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	bkt, _ := b.GetBucket("objacl-controls")
	bkt.OwnerAccessKey = "root-access-key"
	bkt.Objects["k"].Versions[0].ACL = nil
	bkt.Objects["k"].Versions[0].Owner = nil
	gotACL, err := b.GetObjectACL("objacl-controls", "k", "")
	if err != nil || gotACL == nil || gotACL.Owner == nil || gotACL.Owner.DisplayName != "root" {
		t.Fatalf("GetObjectACL owner fallback = (%+v,%v), want root owner", gotACL, err)
	}

	bkt.Objects["k"].Versions[0].ACL = nil
	bkt.Objects["k"].Versions[0].Owner = OwnerForAccessKey("minis3-access-key")
	gotACL, err = b.GetObjectACL("objacl-controls", "k", "")
	if err != nil || gotACL == nil || gotACL.Owner == nil || gotACL.Owner.DisplayName != "minis3" {
		t.Fatalf("GetObjectACL object-owner fallback = (%+v,%v), want minis3 owner", gotACL, err)
	}

	if err := b.PutBucketOwnershipControls("objacl-controls", &OwnershipControls{
		Rules: []OwnershipControlsRule{{ObjectOwnership: ObjectOwnershipBucketOwnerEnforced}},
	}); err != nil {
		t.Fatalf("PutBucketOwnershipControls enforced setup failed: %v", err)
	}
	gotACL, err = b.GetObjectACL("objacl-controls", "k", "")
	if err != nil || gotACL == nil || gotACL.Owner == nil || gotACL.Owner.DisplayName != "root" {
		t.Fatalf("GetObjectACL enforced owner fallback = (%+v,%v), want root owner", gotACL, err)
	}
	if err := b.PutObjectACL("objacl-controls", "k", "", NewDefaultACL()); !errors.Is(
		err,
		ErrAccessControlListNotSupported,
	) {
		t.Fatalf("PutObjectACL enforced = %v, want ErrAccessControlListNotSupported", err)
	}

	if !strings.Contains(checksumCRC64NVMEBase64([]byte("abc")), "=") {
		t.Fatalf("checksumCRC64NVMEBase64 should return base64 output")
	}
	if got := providedChecksumForPut("CRC64NVME", PutObjectOptions{ChecksumCRC64NVME: "crc64"}); got != "crc64" {
		t.Fatalf("providedChecksumForPut(CRC64NVME) = %q, want crc64", got)
	}
	if got := providedChecksumForPut("SHA256", PutObjectOptions{ChecksumSHA256: "sha256"}); got != "sha256" {
		t.Fatalf("providedChecksumForPut(SHA256) = %q, want sha256", got)
	}
	if got := providedChecksumForPut("unknown", PutObjectOptions{ChecksumSHA256: "sha256"}); got != "" {
		t.Fatalf("providedChecksumForPut(unknown) = %q, want empty", got)
	}

	etag := "\"abc\""
	if !matchesDeleteETag("*", etag) {
		t.Fatal("matchesDeleteETag(*) should be true")
	}
	if !matchesDeleteETag("abc", etag) {
		t.Fatal("matchesDeleteETag(unquoted candidate) should match quoted ETag")
	}
	if !matchesDeleteETag("\"x\", abc, \"y\"", etag) {
		t.Fatal("matchesDeleteETag(list candidate) should match when one candidate matches")
	}
	if !matchesDeleteETag(", ,\"abc\"", etag) {
		t.Fatal("matchesDeleteETag should skip empty candidates and still match")
	}
	if !matchesDeleteETag("abc", "abc") {
		t.Fatal("matchesDeleteETag should match raw candidate and raw ETag")
	}
	if matchesDeleteETag(" \"x\" , \"y\" ", etag) {
		t.Fatal("matchesDeleteETag should be false when no candidate matches")
	}

	now := time.Now().UTC().Truncate(time.Second)
	if _, err := parseDeletePreconditionTime(now.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("parseDeletePreconditionTime RFC3339Nano failed: %v", err)
	}
	if _, err := parseDeletePreconditionTime(now.Format(time.RFC3339)); err != nil {
		t.Fatalf("parseDeletePreconditionTime RFC3339 failed: %v", err)
	}
	if _, err := parseDeletePreconditionTime(now.Format(http.TimeFormat)); err != nil {
		t.Fatalf("parseDeletePreconditionTime http.TimeFormat failed: %v", err)
	}
	if _, err := parseDeletePreconditionTime("invalid"); err == nil {
		t.Fatal("parseDeletePreconditionTime invalid should fail")
	}
}

func TestBackendRestoreAndLifecycleHelperCoverage(t *testing.T) {
	t.Setenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS", "")
	t.Setenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS", "")
	if d := restoreDayDuration(); d != 24*time.Hour {
		t.Fatalf("restoreDayDuration default = %v, want 24h", d)
	}
	t.Setenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS", "5")
	t.Setenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS", "")
	if d := restoreDayDuration(); d != 5*time.Second {
		t.Fatalf("restoreDayDuration restore-only = %v, want 5s", d)
	}
	t.Setenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS", "")
	t.Setenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS", "7")
	if d := restoreDayDuration(); d != 14*time.Second {
		t.Fatalf("restoreDayDuration lifecycle-only = %v, want 14s", d)
	}
	t.Setenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS", "5")
	t.Setenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS", "7")
	if d := restoreDayDuration(); d != 12*time.Second {
		t.Fatalf("restoreDayDuration both = %v, want 12s", d)
	}
	t.Setenv("MINIS3_RESTORE_DEBUG_INTERVAL_SECONDS", "bad")
	t.Setenv("MINIS3_LC_DEBUG_INTERVAL_SECONDS", "0")
	if d := restoreDayDuration(); d != 24*time.Hour {
		t.Fatalf("restoreDayDuration invalid env = %v, want 24h", d)
	}

	t.Setenv("MINIS3_CLOUD_READ_THROUGH_RESTORE_DAYS", "")
	if got := cloudReadThroughRestoreDays(); got != 1 {
		t.Fatalf("cloudReadThroughRestoreDays default = %d, want 1", got)
	}
	t.Setenv("MINIS3_CLOUD_READ_THROUGH_RESTORE_DAYS", "3")
	if got := cloudReadThroughRestoreDays(); got != 3 {
		t.Fatalf("cloudReadThroughRestoreDays set = %d, want 3", got)
	}
	t.Setenv("MINIS3_CLOUD_READ_THROUGH_RESTORE_DAYS", "bad")
	if got := cloudReadThroughRestoreDays(); got != 1 {
		t.Fatalf("cloudReadThroughRestoreDays invalid = %d, want 1", got)
	}
	if got := CloudReadThroughRestoreDays(); got != 1 {
		t.Fatalf("CloudReadThroughRestoreDays wrapper = %d, want 1", got)
	}

	t.Setenv("MINIS3_CLOUD_ALLOW_READ_THROUGH", "")
	if !cloudAllowReadThrough() {
		t.Fatal("cloudAllowReadThrough default should be true")
	}
	t.Setenv("MINIS3_CLOUD_ALLOW_READ_THROUGH", "false")
	if cloudAllowReadThrough() {
		t.Fatal("cloudAllowReadThrough(false) should be false")
	}
	t.Setenv("MINIS3_CLOUD_ALLOW_READ_THROUGH", "bad")
	if !cloudAllowReadThrough() {
		t.Fatal("cloudAllowReadThrough(invalid) should fallback to true")
	}
	if !CloudAllowReadThrough() {
		t.Fatal("CloudAllowReadThrough wrapper should return true with invalid env fallback")
	}

	t.Setenv("MINIS3_CLOUD_TARGET_STORAGE_CLASS", "")
	if got := cloudTargetStorageClass(); got != "STANDARD" {
		t.Fatalf("cloudTargetStorageClass default = %q, want STANDARD", got)
	}
	t.Setenv("MINIS3_CLOUD_TARGET_STORAGE_CLASS", "STANDARD_IA")
	if got := cloudTargetStorageClass(); got != "STANDARD_IA" {
		t.Fatalf("cloudTargetStorageClass set = %q, want STANDARD_IA", got)
	}

	t.Setenv("MINIS3_CLOUD_RETAIN_HEAD_OBJECT", "")
	if !cloudRetainHeadObject() {
		t.Fatal("cloudRetainHeadObject default should be true")
	}
	t.Setenv("MINIS3_CLOUD_RETAIN_HEAD_OBJECT", "false")
	if cloudRetainHeadObject() {
		t.Fatal("cloudRetainHeadObject(false) should be false")
	}
	t.Setenv("MINIS3_CLOUD_RETAIN_HEAD_OBJECT", "bad")
	if !cloudRetainHeadObject() {
		t.Fatal("cloudRetainHeadObject(invalid) should fallback to true")
	}

	now := time.Now().UTC()
	if dueAt, ok := lifecycleTransitionDueAt(
		LifecycleTransition{Days: 1, StorageClass: "GLACIER"},
		now.Add(-48*time.Hour),
		24*time.Hour,
	); !ok || dueAt.IsZero() {
		t.Fatalf("lifecycleTransitionDueAt(Days) = (%v,%v), want non-zero,true", dueAt, ok)
	}
	if _, ok := lifecycleTransitionDueAt(
		LifecycleTransition{Date: "", StorageClass: "GLACIER"},
		now,
		24*time.Hour,
	); ok {
		t.Fatal("lifecycleTransitionDueAt empty date should be false")
	}
	if _, ok := lifecycleTransitionDueAt(
		LifecycleTransition{Date: "not-a-date", StorageClass: "GLACIER"},
		now,
		24*time.Hour,
	); ok {
		t.Fatal("lifecycleTransitionDueAt invalid date should be false")
	}
	date := now.Add(-time.Hour).Format(time.RFC3339)
	if _, ok := lifecycleTransitionDueAt(
		LifecycleTransition{Date: date, StorageClass: "GLACIER"},
		now,
		24*time.Hour,
	); !ok {
		t.Fatal("lifecycleTransitionDueAt valid date should be true")
	}

	class, dueAt, ok := dueLifecycleTransitionStorageClass(
		[]LifecycleTransition{
			{StorageClass: "", Days: 1},
			{StorageClass: "GLACIER", Days: 10},
			{StorageClass: "DEEP_ARCHIVE", Days: 1},
		},
		now.Add(-5*24*time.Hour),
		now,
		24*time.Hour,
	)
	if !ok || class != "DEEP_ARCHIVE" || dueAt.IsZero() {
		t.Fatalf("dueLifecycleTransitionStorageClass = (%q,%v,%v), want DEEP_ARCHIVE,non-zero,true", class, dueAt, ok)
	}

	ncClass, _, ncOK := dueNoncurrentTransitionStorageClass(
		[]NoncurrentVersionTransition{
			{NoncurrentDays: 0, StorageClass: "GLACIER"},
			{NoncurrentDays: 1, StorageClass: ""},
			{NoncurrentDays: 1, NewerNoncurrentVersions: 2, StorageClass: "GLACIER"},
			{NoncurrentDays: 2, StorageClass: "DEEP_ARCHIVE"},
		},
		now.Add(-72*time.Hour),
		now,
		24*time.Hour,
		3,
	)
	if !ncOK || ncClass != "DEEP_ARCHIVE" {
		t.Fatalf("dueNoncurrentTransitionStorageClass = (%q,%v), want DEEP_ARCHIVE,true", ncClass, ncOK)
	}

	lcBackend := New()
	mustCreateBucketCov(t, lcBackend, "lc-src")
	lcBucket, _ := lcBackend.GetBucket("lc-src")
	lcBucket.LifecycleConfiguration = &LifecycleConfiguration{Rules: []LifecycleRule{
		{
			Status: LifecycleStatusEnabled,
			Filter: &LifecycleFilter{Prefix: "x/"},
			Transition: []LifecycleTransition{{
				Days:         1,
				StorageClass: "GLACIER",
			}},
		},
		{
			Status: LifecycleStatusEnabled,
			Transition: []LifecycleTransition{{
				Date:         "invalid-date",
				StorageClass: "DEEP_ARCHIVE",
			}},
		},
		{
			Status: LifecycleStatusEnabled,
			Transition: []LifecycleTransition{{
				Days:         1,
				StorageClass: "DEEP_ARCHIVE",
			}},
		},
	}}
	curr := &Object{
		Key:          "obj",
		LastModified: now.Add(-72 * time.Hour),
		StorageClass: "STANDARD",
		Data:         []byte("x"),
		Size:         1,
	}
	lcBackend.applyCurrentTransitionRules(
		lcBucket,
		"obj",
		[]*Object{curr},
		lcBucket.LifecycleConfiguration.Rules,
		now,
		24*time.Hour,
	)
	if curr.StorageClass == "STANDARD" {
		t.Fatal("applyCurrentTransitionRules should apply due transition for matching rule")
	}
	lcBackend.applyNoncurrentTransitionRules(
		lcBucket,
		"obj",
		[]*Object{},
		lcBucket.LifecycleConfiguration.Rules,
		now,
		24*time.Hour,
	)
	lcBackend.applyNoncurrentTransitionRules(
		lcBucket,
		"obj",
		[]*Object{
			{IsLatest: true},
			{IsLatest: false, LastModified: now.Add(-72 * time.Hour), StorageClass: "STANDARD"},
		},
		[]LifecycleRule{{
			Status: LifecycleStatusEnabled,
			Filter: &LifecycleFilter{Prefix: "x/"},
			NoncurrentVersionTransition: []NoncurrentVersionTransition{{
				NoncurrentDays: 1,
				StorageClass:   "GLACIER",
			}},
		}},
		now,
		24*time.Hour,
	)
	lcBackend.applyNoncurrentTransitionRules(
		lcBucket,
		"obj",
		[]*Object{
			{IsLatest: true},
			{IsLatest: false, LastModified: now.Add(-72 * time.Hour), StorageClass: "STANDARD"},
		},
		lcBucket.LifecycleConfiguration.Rules,
		now,
		24*time.Hour,
	)
	lcBackend.applyLifecycleStorageClassTransition(lcBucket, "obj", nil, "GLACIER", now)

	lcObj := &Object{
		IsLatest:            true,
		StorageClass:        cloudStorageClass(),
		LastModified:        now,
		CloudTransitionedAt: func() *time.Time { t := now.Add(-72 * time.Hour); return &t }(),
	}
	lcBucket.LifecycleConfiguration = &LifecycleConfiguration{Rules: []LifecycleRule{{
		Status: LifecycleStatusEnabled,
		Expiration: &LifecycleExpiration{
			Days: 1,
		},
	}}}
	if !lcBackend.shouldExpireCurrentVersion(
		lcBucket,
		"obj",
		&ObjectVersions{Versions: []*Object{lcObj}},
		now,
		24*time.Hour,
	) {
		t.Fatal("shouldExpireCurrentVersion should use CloudTransitionedAt for cloud storage class")
	}

	obj := &Object{StorageClass: "GLACIER", Data: []byte("x"), Size: 1}
	if changed := (&Backend{}).restoreExpiredArchivedObjectIfNeeded(obj, now); changed {
		t.Fatal("restoreExpiredArchivedObjectIfNeeded without expiry should be false")
	}
	expiryFuture := now.Add(time.Hour)
	obj.RestoreExpiryDate = &expiryFuture
	if changed := (&Backend{}).restoreExpiredArchivedObjectIfNeeded(obj, now); changed {
		t.Fatal("restoreExpiredArchivedObjectIfNeeded future expiry should be false")
	}
	expiryPast := now.Add(-time.Hour)
	obj.RestoreExpiryDate = &expiryPast
	obj.RestoreOngoing = true
	if changed := (&Backend{}).restoreExpiredArchivedObjectIfNeeded(obj, now); !changed ||
		obj.RestoreExpiryDate != nil || obj.Size != 0 || len(obj.Data) != 0 || obj.RestoreOngoing {
		t.Fatalf("restoreExpiredArchivedObjectIfNeeded expired should clear restore state, got %+v", obj)
	}

	b := New()
	mustCreateBucketCov(t, b, "src-restore")
	archived := &Object{
		Key:          "obj",
		VersionId:    NullVersionId,
		StorageClass: "GLACIER",
		LastModified: now,
	}
	bkt, _ := b.GetBucket("src-restore")
	bkt.Objects["obj"] = &ObjectVersions{Versions: []*Object{archived, nil}}
	bkt.Objects["nil-versions"] = nil
	past := now.Add(-time.Hour)
	archived.RestoreExpiryDate = &past
	b.expireRestoredArchivedObjects(nil, now)
	b.expireRestoredArchivedObjects(bkt, now)
	if archived.RestoreExpiryDate != nil {
		t.Fatal("expireRestoredArchivedObjects should clear expired restore date")
	}

	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", nil)
	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", &Object{
		StorageClass: "STANDARD",
	})
	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", &Object{
		StorageClass: "GLACIER",
		Data:         []byte("already"),
		Size:         7,
	})

	targetMissing := &Object{StorageClass: "GLACIER"}
	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", targetMissing)
	if len(targetMissing.Data) != 0 {
		t.Fatal("hydrateArchivedObjectDataLocked should skip when target cloud bucket is missing")
	}

	cloudBucketName := cloudTargetBucketName("GLACIER")
	mustCreateBucketCov(t, b, cloudBucketName)
	dstObj := &Object{
		Key:          cloudObjectKey("src-restore", "obj", NullVersionId),
		VersionId:    NullVersionId,
		StorageClass: "STANDARD",
		Data:         []byte("hydrated-data"),
	}
	cloudBkt, _ := b.GetBucket(cloudBucketName)
	cloudBkt.Objects[dstObj.Key] = &ObjectVersions{Versions: []*Object{nil}}
	target := &Object{StorageClass: "GLACIER"}
	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", target)
	if len(target.Data) != 0 {
		t.Fatal("hydrateArchivedObjectDataLocked should skip when cloud head object is nil")
	}
	cloudBkt.Objects[dstObj.Key] = &ObjectVersions{Versions: []*Object{dstObj}}
	hydrateArchivedObjectDataLocked(b, "src-restore", "obj", target)
	if string(target.Data) != "hydrated-data" || target.Size != int64(len("hydrated-data")) {
		t.Fatalf("hydrateArchivedObjectDataLocked copied wrong data: %+v", target)
	}

	mustCreateBucketCov(t, b, "restore-bucket")
	if _, err := b.PutObject("restore-bucket", "rest-key", []byte("archive"), PutObjectOptions{
		StorageClass: "GLACIER",
	}); err != nil {
		t.Fatalf("PutObject restore setup failed: %v", err)
	}
	if _, err := b.RestoreObject("restore-bucket", "rest-key", "", 1); err != nil {
		t.Fatalf("RestoreObject initial failed: %v", err)
	}
	res, err := b.RestoreObject("restore-bucket", "rest-key", "", 0)
	if err != nil || res == nil || res.StatusCode != 200 {
		t.Fatalf("RestoreObject already-restored days=0 = (%+v,%v), want status 200", res, err)
	}
	restored, err := b.GetObject("restore-bucket", "rest-key")
	if err != nil || restored == nil || restored.StorageClass != "STANDARD" {
		t.Fatalf("RestoreObject days=0 should convert to STANDARD, obj=%+v err=%v", restored, err)
	}
}

func TestBackendMultipartChecksumBranchesCoverage(t *testing.T) {
	makeUploadAndComplete := func(
		t *testing.T,
		algorithm string,
		provided bool,
		enforcedOwner bool,
	) {
		t.Helper()
		b := New()
		mustCreateBucketCov(t, b, "mp-src")
		bkt, _ := b.GetBucket("mp-src")
		if enforcedOwner {
			bkt.OwnerAccessKey = "unknown-owner"
			bkt.ObjectOwnership = ObjectOwnershipBucketOwnerEnforced
		}
		opts := CreateMultipartUploadOptions{ChecksumAlgorithm: algorithm}
		payload := []byte("hello-multipart-" + algorithm)
		if provided {
			sum, ok := ComputeChecksumBase64(algorithm, payload)
			if !ok {
				t.Fatalf("ComputeChecksumBase64(%s) unsupported", algorithm)
			}
			switch algorithm {
			case "CRC32":
				opts.ChecksumCRC32 = sum
			case "CRC32C":
				opts.ChecksumCRC32C = sum
			case "CRC64NVME":
				opts.ChecksumCRC64NVME = sum
			case "SHA1":
				opts.ChecksumSHA1 = sum
			case "SHA256":
				opts.ChecksumSHA256 = sum
			}
		}
		upload, err := b.CreateMultipartUpload("mp-src", "obj", opts)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}
		part, err := b.UploadPart("mp-src", "obj", upload.UploadId, 1, payload)
		if err != nil {
			t.Fatalf("UploadPart failed: %v", err)
		}
		switch algorithm {
		case "CRC32":
			if part.ChecksumCRC32 == "" {
				t.Fatal("UploadPart should populate CRC32 checksum")
			}
		case "CRC32C":
			if part.ChecksumCRC32C == "" {
				t.Fatal("UploadPart should populate CRC32C checksum")
			}
		case "CRC64NVME":
			if part.ChecksumCRC64NVME == "" {
				t.Fatal("UploadPart should populate CRC64NVME checksum")
			}
		case "SHA1":
			if part.ChecksumSHA1 == "" {
				t.Fatal("UploadPart should populate SHA1 checksum")
			}
		case "SHA256":
			if part.ChecksumSHA256 == "" {
				t.Fatal("UploadPart should populate SHA256 checksum")
			}
		}
		obj, err := b.CompleteMultipartUpload("mp-src", "obj", upload.UploadId, []CompletePart{{
			PartNumber: 1,
			ETag:       part.ETag,
		}})
		if err != nil {
			t.Fatalf("CompleteMultipartUpload failed: %v", err)
		}
		switch algorithm {
		case "CRC32":
			if obj.ChecksumCRC32 == "" {
				t.Fatal("CompleteMultipartUpload should populate CRC32 checksum")
			}
		case "CRC32C":
			if obj.ChecksumCRC32C == "" {
				t.Fatal("CompleteMultipartUpload should populate CRC32C checksum")
			}
		case "CRC64NVME":
			if obj.ChecksumCRC64NVME == "" {
				t.Fatal("CompleteMultipartUpload should populate CRC64NVME checksum")
			}
		case "SHA1":
			if obj.ChecksumSHA1 == "" {
				t.Fatal("CompleteMultipartUpload should populate SHA1 checksum")
			}
		case "SHA256":
			if obj.ChecksumSHA256 == "" {
				t.Fatal("CompleteMultipartUpload should populate SHA256 checksum")
			}
		}
	}

	for _, algo := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"} {
		t.Run("computed_"+algo, func(t *testing.T) {
			makeUploadAndComplete(t, algo, false, false)
		})
		t.Run("provided_"+algo, func(t *testing.T) {
			makeUploadAndComplete(t, algo, true, false)
		})
	}

	// Cover owner-enforced branches in Create/CompleteMultipartUpload.
	makeUploadAndComplete(t, "CRC32", false, true)
}

func TestBackendPutCopyDeletePolicyAndRetentionRemainingBranches(t *testing.T) {
	b := New()
	mustCreateBucketCov(t, b, "put-rem")
	putBucket, _ := b.GetBucket("put-rem")
	putBucket.OwnerAccessKey = "unknown-owner"
	putBucket.ObjectOwnership = ObjectOwnershipBucketOwnerEnforced

	if _, err := b.PutObject(
		"put-rem",
		"k",
		[]byte("data"),
		PutObjectOptions{
			ChecksumAlgorithm: "CRC64NVME",
		},
	); err != nil {
		t.Fatalf("PutObject CRC64NVME failed: %v", err)
	}
	if _, err := b.PutObject(
		"put-rem",
		"bad-digest",
		[]byte("data"),
		PutObjectOptions{
			ChecksumAlgorithm: "CRC32",
			ChecksumCRC32:     "AAAAAA==",
		},
	); !errors.Is(err, ErrBadDigest) {
		t.Fatalf("PutObject bad digest = %v, want ErrBadDigest", err)
	}

	mustCreateBucketCov(t, b, "copy-src-rem")
	mustCreateBucketCov(t, b, "copy-dst-rem")
	srcObj, err := b.PutObject("copy-src-rem", "obj", []byte("copy-data"), PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject copy source failed: %v", err)
	}
	if _, _, err := b.CopyObject(
		"copy-src-rem",
		"obj",
		"",
		"copy-dst-rem",
		"crc32",
		CopyObjectOptions{ChecksumAlgorithm: "CRC32"},
	); err != nil {
		t.Fatalf("CopyObject CRC32 failed: %v", err)
	}
	dstBucket, _ := b.GetBucket("copy-dst-rem")
	dstBucket.ObjectOwnership = ObjectOwnershipBucketOwnerEnforced
	dstBucket.OwnerAccessKey = "unknown-owner"
	copied, _, err := b.CopyObject(
		"copy-src-rem",
		"obj",
		"",
		"copy-dst-rem",
		"crc64",
		CopyObjectOptions{ChecksumAlgorithm: "CRC64NVME"},
	)
	if err != nil {
		t.Fatalf("CopyObject CRC64NVME failed: %v", err)
	}
	if copied.Owner == nil || copied.ACL == nil || copied.ChecksumCRC64NVME == "" {
		t.Fatalf("CopyObject owner-enforced/CRC64 result unexpected: %+v", copied)
	}

	if _, err := b.PutObject("copy-dst-rem", "delete-precond", []byte("12345"), PutObjectOptions{}); err != nil {
		t.Fatalf("PutObject delete-precond failed: %v", err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	targetBucket, _ := b.GetBucket("copy-dst-rem")
	targetObj := targetBucket.Objects["delete-precond"].Versions[0]
	targetObj.LastModified = past
	wrongSize := int64(9)
	results, err := b.DeleteObjects("copy-dst-rem", []ObjectIdentifier{
		{Key: "delete-precond", ETag: "\"mismatch\""},
		{Key: "delete-precond", LastModifiedTime: "bad-time"},
		{Key: "delete-precond", LastModifiedTime: time.Now().UTC().Format(http.TimeFormat)},
		{Key: "delete-precond", Size: &wrongSize},
	}, false)
	if err != nil {
		t.Fatalf("DeleteObjects precondition cases failed: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("DeleteObjects result length = %d, want 4", len(results))
	}
	for i, r := range results {
		if !errors.Is(r.Error, ErrPreconditionFailed) {
			t.Fatalf("DeleteObjects result %d error = %v, want ErrPreconditionFailed", i, r.Error)
		}
	}
	if targetObj.IsDeleteMarker {
		t.Fatal("source object should remain when all DeleteObjects entries failed preconditions")
	}

	policy := `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},` +
		`{"Effect":"Allow","Principal":{"AWS":"other"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	if HasAllowStatementForRequest(
		policy,
		PolicyEvalContext{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", AccessKey: "ak"},
	) {
		t.Fatal("HasAllowStatementForRequest should be false for deny and principal mismatch")
	}
	if evaluateCondition(
		"StringEquals",
		"s3:ExistingObjectTag/team",
		"value",
		PolicyEvalContext{Action: "s3:PutObject"},
	) {
		t.Fatal("evaluateCondition should be false for unsupported condition key")
	}

	obj := &Object{LastModified: time.Now().UTC()}
	applyDefaultRetention(&Bucket{
		ObjectLockEnabled: true,
		ObjectLockConfiguration: &ObjectLockConfiguration{
			Rule: &ObjectLockRule{
				DefaultRetention: &DefaultRetention{Mode: "", Days: 1},
			},
		},
	}, obj)
	if obj.RetainUntilDate != nil || obj.RetentionMode != "" {
		t.Fatalf("applyDefaultRetention with empty mode should not set retention fields: %+v", obj)
	}

	if srcObj == nil || srcObj.ETag == "" {
		t.Fatalf("source object sanity failed: %+v", srcObj)
	}
}
