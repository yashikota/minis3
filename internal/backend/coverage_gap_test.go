package backend

import (
	"errors"
	"testing"
	"time"
)

func TestOwnerResolverBranches(t *testing.T) {
	known := OwnerForAccessKey("minis3-access-key")
	if known == nil || known.DisplayName != "minis3" {
		t.Fatalf("unexpected known owner: %+v", known)
	}

	empty := OwnerForAccessKey("")
	def := DefaultOwner()
	if empty == nil || empty.ID != def.ID || empty.DisplayName != def.DisplayName {
		t.Fatalf("unexpected default owner for empty access key: %+v", empty)
	}

	unknown := OwnerForAccessKey("unknown-access-key")
	if unknown == nil || unknown.ID != "unknown-access-key" ||
		unknown.DisplayName != "unknown-access-key" {
		t.Fatalf("unexpected fallback owner for unknown access key: %+v", unknown)
	}

	knownCanonical := OwnerForCanonicalID(def.ID)
	if knownCanonical == nil || knownCanonical.ID != def.ID {
		t.Fatalf("expected known canonical id to resolve, got %+v", knownCanonical)
	}
	if got := OwnerForCanonicalID("missing-canonical"); got != nil {
		t.Fatalf("expected missing canonical id to return nil, got %+v", got)
	}

	knownEmail := OwnerForEmail("minis3@example.com")
	if knownEmail == nil || knownEmail.DisplayName != "minis3" {
		t.Fatalf("expected known email owner, got %+v", knownEmail)
	}
	if got := OwnerForEmail("missing@example.com"); got != nil {
		t.Fatalf("expected missing email to return nil, got %+v", got)
	}
}

func TestACLAndLifecycleNormalizationBranches(t *testing.T) {
	acl := NewDefaultACLForOwner(nil)
	if acl.Owner == nil || acl.Owner.ID != DefaultOwner().ID {
		t.Fatalf("unexpected default owner ACL: %+v", acl)
	}

	if got := normalizeACL(nil); got == nil || got.Owner == nil {
		t.Fatalf("normalizeACL(nil) returned unexpected value: %+v", got)
	}

	in := &AccessControlPolicy{
		AccessControlList: AccessControlList{Grants: []Grant{
			{Grantee: nil, Permission: PermissionRead},
			{Grantee: &Grantee{URI: AllUsersURI}, Permission: PermissionRead},
			{Grantee: &Grantee{ID: DefaultOwner().ID}, Permission: PermissionRead},
		}},
	}
	normalized := normalizeACL(in)
	if normalized.Owner == nil {
		t.Fatalf("expected owner normalization, got %+v", normalized)
	}
	if normalized.AccessControlList.Grants[0].Grantee == nil ||
		normalized.AccessControlList.Grants[0].Grantee.Type != "Group" {
		t.Fatalf(
			"expected group grant to be sorted first, got %+v",
			normalized.AccessControlList.Grants,
		)
	}
	canonicalSeen := false
	for _, grant := range normalized.AccessControlList.Grants {
		if grant.Grantee != nil && grant.Grantee.Type == "CanonicalUser" {
			canonicalSeen = true
			break
		}
	}
	if !canonicalSeen {
		t.Fatalf(
			"expected canonical-user grant normalization, got %+v",
			normalized.AccessControlList.Grants,
		)
	}

	if got := aclGrantSortKey(Grant{}); got != 2 {
		t.Fatalf("aclGrantSortKey(nil grantee) = %d, want 2", got)
	}

	canonical := newCanonicalGrant(nil, PermissionRead)
	if canonical.Grantee == nil || canonical.Grantee.ID != DefaultOwner().ID {
		t.Fatalf("expected default owner canonical grant, got %+v", canonical)
	}

	privateACL := CannedACLToPolicyForOwner(string(ACLPrivate), nil, nil)
	if privateACL == nil || privateACL.Owner == nil ||
		len(privateACL.AccessControlList.Grants) != 1 {
		t.Fatalf("unexpected private ACL normalization result: %+v", privateACL)
	}

	if got := normalizeLifecycleConfiguration(nil); got != nil {
		t.Fatalf("normalizeLifecycleConfiguration(nil) = %+v, want nil", got)
	}
}

func TestObjectCurrentVisibleVersionBranches(t *testing.T) {
	var nilVersions *ObjectVersions
	if got := nilVersions.getCurrentVisibleVersion(); got != nil {
		t.Fatalf("expected nil for nil receiver, got %+v", got)
	}

	empty := &ObjectVersions{}
	if got := empty.getCurrentVisibleVersion(); got != nil {
		t.Fatalf("expected nil for empty versions, got %+v", got)
	}

	deleteMarkerFirst := &ObjectVersions{
		Versions: []*Object{{IsDeleteMarker: true}, {IsDeleteMarker: false}},
	}
	if got := deleteMarkerFirst.getCurrentVisibleVersion(); got != nil {
		t.Fatalf("expected nil when current version is delete marker, got %+v", got)
	}

	current := &Object{Key: "visible", IsDeleteMarker: false}
	visible := &ObjectVersions{Versions: []*Object{current, {IsDeleteMarker: true}}}
	if got := visible.getCurrentVisibleVersion(); got != current {
		t.Fatalf("expected first non-delete current object, got %+v", got)
	}
}

func TestPolicyPrincipalHelperBranches(t *testing.T) {
	ctx := PolicyEvalContext{AccessKey: "ak"}

	if !matchesPrincipal(nil, ctx) {
		t.Fatal("expected nil principal to match")
	}
	if matchesPrincipal(123, ctx) {
		t.Fatal("expected unsupported principal type to not match")
	}
	if !matchesPrincipal("*", ctx) {
		t.Fatal("expected wildcard principal to match")
	}
	if !matchesPrincipal(map[string]any{"AWS": "ak"}, ctx) {
		t.Fatal("expected matching access key principal to match")
	}
	if matchesPrincipal(map[string]any{"AWS": "other"}, ctx) {
		t.Fatal("expected non-matching access key principal to not match")
	}

	if values, ok := extractAWSPrincipals("*"); !ok || len(values) != 1 || values[0] != "*" {
		t.Fatalf("unexpected extracted principals for string: values=%v ok=%v", values, ok)
	}
	if values, ok := extractAWSPrincipals([]any{"a", "b"}); !ok || len(values) != 2 {
		t.Fatalf("unexpected extracted principals for []any: values=%v ok=%v", values, ok)
	}
	if values, ok := extractAWSPrincipals([]any{"a", 1}); ok || values != nil {
		t.Fatalf("expected []any with non-string to fail: values=%v ok=%v", values, ok)
	}
	if values, ok := extractAWSPrincipals(map[string]any{"AWS": []any{"a", "b"}}); !ok ||
		len(values) != 2 {
		t.Fatalf("unexpected extracted principals for AWS map: values=%v ok=%v", values, ok)
	}
	if values, ok := extractAWSPrincipals(map[string]any{"CanonicalUser": "x"}); ok ||
		values != nil {
		t.Fatalf("expected map without AWS key to fail: values=%v ok=%v", values, ok)
	}

	if !isPublicPrincipal(map[string]any{"AWS": "*"}) {
		t.Fatal("expected public principal to be detected")
	}
	if isPublicPrincipal(map[string]any{"AWS": []any{"ak"}}) {
		t.Fatal("expected non-public principal to not be detected as public")
	}
	if isPublicPrincipal(123) {
		t.Fatal("expected invalid principal type to not be public")
	}

	if IsPolicyPublic("") {
		t.Fatal("empty policy should not be public")
	}
	if IsPolicyPublic("{") {
		t.Fatal("invalid policy JSON should not be public")
	}
	if !IsPolicyPublic(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
	) {
		t.Fatal("expected unconditional public allow policy to be public")
	}
	if IsPolicyPublic(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:Referer":"x"}}}]}`,
	) {
		t.Fatal("policy with condition should not be treated as public")
	}
	if IsPolicyPublic(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
	) {
		t.Fatal("deny statement should not make policy public")
	}
	if IsPolicyPublic(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"ak"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`,
	) {
		t.Fatal("non-public principal should not make policy public")
	}

	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"other"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},{"Effect":"Allow","Principal":{"AWS":"other"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	if effect := EvaluateBucketPolicyAccess(policy, PolicyEvalContext{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k", AccessKey: "ak"}); effect != PolicyEffectDefault {
		t.Fatalf("expected principal mismatch to result in default effect, got %v", effect)
	}
}

func TestLifecycleHelperBranches(t *testing.T) {
	now := time.Now().UTC()

	if lifecycleRuleMatchesObject(LifecycleRule{}, "k", nil) {
		t.Fatal("nil object should not match lifecycle rule")
	}
	if lifecycleRuleMatchesObject(LifecycleRule{Prefix: "x/"}, "k", &Object{}) {
		t.Fatal("prefix mismatch should not match")
	}
	if !lifecycleRuleMatchesObject(LifecycleRule{}, "k", &Object{Size: 10}) {
		t.Fatal("rule without filter should match object")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{Filter: &LifecycleFilter{Prefix: "x/"}},
		"k",
		&Object{Size: 10},
	) {
		t.Fatal("filter prefix mismatch should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{Filter: &LifecycleFilter{ObjectSizeGreaterThan: 10}},
		"k",
		&Object{Size: 10},
	) {
		t.Fatal("object size <= greater-than should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{Filter: &LifecycleFilter{ObjectSizeLessThan: 10}},
		"k",
		&Object{Size: 10},
	) {
		t.Fatal("object size >= less-than should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{Filter: &LifecycleFilter{Tag: &Tag{Key: "a", Value: "1"}}},
		"k",
		&Object{Tags: map[string]string{"a": "2"}},
	) {
		t.Fatal("tag mismatch should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{Filter: &LifecycleFilter{And: &LifecycleFilterAnd{Prefix: "x/"}}},
		"k",
		&Object{},
	) {
		t.Fatal("AND prefix mismatch should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{
			Filter: &LifecycleFilter{And: &LifecycleFilterAnd{ObjectSizeGreaterThan: 10}},
		},
		"k",
		&Object{Size: 10},
	) {
		t.Fatal("AND object size mismatch should not match")
	}
	if lifecycleRuleMatchesObject(
		LifecycleRule{
			Filter: &LifecycleFilter{And: &LifecycleFilterAnd{Tags: []Tag{{Key: "a", Value: "1"}}}},
		},
		"k",
		&Object{Tags: map[string]string{"a": "2"}},
	) {
		t.Fatal("AND tag mismatch should not match")
	}
	if !lifecycleRuleMatchesObject(
		LifecycleRule{
			Filter: &LifecycleFilter{
				And: &LifecycleFilterAnd{Prefix: "k", Tags: []Tag{{Key: "a", Value: "1"}}},
			},
		},
		"k/ok",
		&Object{Size: 11, Tags: map[string]string{"a": "1"}},
	) {
		t.Fatal("expected AND filter match")
	}

	if !lifecycleObjectSizeMatch(11, 10, 20) {
		t.Fatal("size in range should match")
	}
	if lifecycleObjectSizeMatch(10, 10, 20) {
		t.Fatal("size <= greater-than should fail")
	}
	if lifecycleObjectSizeMatch(20, 10, 20) {
		t.Fatal("size >= less-than should fail")
	}

	if objectHasTag(nil, Tag{Key: "k", Value: "v"}) {
		t.Fatal("nil object should not have tags")
	}
	if objectHasTag(&Object{}, Tag{Key: "", Value: "v"}) {
		t.Fatal("empty tag key should not match")
	}
	if objectHasTag(&Object{Tags: map[string]string{"k": "v"}}, Tag{Key: "k", Value: "x"}) {
		t.Fatal("tag value mismatch should fail")
	}
	if !objectHasTag(&Object{Tags: map[string]string{"k": "v"}}, Tag{Key: "k", Value: "v"}) {
		t.Fatal("tag value match should pass")
	}

	if lifecycleExpirationDue(nil, now, now, time.Second) {
		t.Fatal("nil expiration should not be due")
	}
	if !lifecycleExpirationDue(
		&LifecycleExpiration{Days: 1},
		now.Add(-2*time.Second),
		now,
		time.Second,
	) {
		t.Fatal("expiration by days should be due")
	}
	if lifecycleExpirationDue(
		&LifecycleExpiration{Days: 2},
		now.Add(-1*time.Second),
		now,
		time.Second,
	) {
		t.Fatal("expiration by days should not be due yet")
	}
	dateRFC3339 := now.Add(-time.Second).Format(time.RFC3339)
	if !lifecycleExpirationDue(&LifecycleExpiration{Date: dateRFC3339}, now, now, time.Second) {
		t.Fatal("RFC3339 expiration date should be due")
	}
	dateYYYYMMDD := now.Add(-24 * time.Hour).Format("2006-01-02")
	if !lifecycleExpirationDue(&LifecycleExpiration{Date: dateYYYYMMDD}, now, now, 24*time.Hour) {
		t.Fatal("YYYY-MM-DD expiration date should be due")
	}
	if lifecycleExpirationDue(&LifecycleExpiration{Date: "not-a-date"}, now, now, time.Second) {
		t.Fatal("invalid expiration date should not be due")
	}
	if lifecycleExpirationDue(&LifecycleExpiration{}, now, now, time.Second) {
		t.Fatal("empty expiration rule should not be due")
	}

	if lifecycleNoncurrentExpirationDue(nil, now, now, time.Second) {
		t.Fatal("nil noncurrent expiration should not be due")
	}
	if lifecycleNoncurrentExpirationDue(
		&NoncurrentVersionExpiration{NoncurrentDays: 0},
		now,
		now,
		time.Second,
	) {
		t.Fatal("noncurrent days <= 0 should not be due")
	}
	if !lifecycleNoncurrentExpirationDue(
		&NoncurrentVersionExpiration{NoncurrentDays: 1},
		now.Add(-2*time.Second),
		now,
		time.Second,
	) {
		t.Fatal("expected noncurrent expiration due")
	}

	deleteMarker := &Object{IsDeleteMarker: true, LastModified: now.Add(-2 * time.Second)}
	if shouldDeleteExpiredObjectDeleteMarker("k", nil, nil, now, time.Second) {
		t.Fatal("empty versions should not delete")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{{IsDeleteMarker: false}},
		nil,
		now,
		time.Second,
	) {
		t.Fatal("non-delete latest should not delete")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker, {IsDeleteMarker: false}},
		nil,
		now,
		time.Second,
	) {
		t.Fatal("presence of non-delete version should keep delete marker")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker},
		[]LifecycleRule{
			{
				Status:     LifecycleStatusDisabled,
				Expiration: &LifecycleExpiration{ExpiredObjectDeleteMarker: true},
			},
		},
		now,
		time.Second,
	) {
		t.Fatal("disabled rule should not apply")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker},
		[]LifecycleRule{
			{
				Status:     LifecycleStatusEnabled,
				Prefix:     "x/",
				Expiration: &LifecycleExpiration{ExpiredObjectDeleteMarker: true},
			},
		},
		now,
		time.Second,
	) {
		t.Fatal("prefix mismatch should not apply")
	}
	if !shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker},
		[]LifecycleRule{
			{
				Status:     LifecycleStatusEnabled,
				Expiration: &LifecycleExpiration{ExpiredObjectDeleteMarker: true},
			},
		},
		now,
		time.Second,
	) {
		t.Fatal("ExpiredObjectDeleteMarker=true should delete")
	}
	if !shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker},
		[]LifecycleRule{
			{Status: LifecycleStatusEnabled, Expiration: &LifecycleExpiration{Days: 1}},
		},
		now,
		time.Second,
	) {
		t.Fatal("Days expiration should delete when due")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{{IsDeleteMarker: true, LastModified: now}},
		[]LifecycleRule{
			{Status: LifecycleStatusEnabled, Expiration: &LifecycleExpiration{Days: 1}},
		},
		now,
		time.Second,
	) {
		t.Fatal("Days expiration should not delete before due")
	}
	if shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{{IsDeleteMarker: true, LastModified: now}},
		[]LifecycleRule{
			{Status: LifecycleStatusEnabled, Expiration: &LifecycleExpiration{Date: "not-a-date"}},
		},
		now,
		time.Second,
	) {
		t.Fatal("invalid expiration date should not delete")
	}
	if !shouldDeleteExpiredObjectDeleteMarker(
		"k",
		[]*Object{deleteMarker},
		[]LifecycleRule{
			{
				Status:     LifecycleStatusEnabled,
				Expiration: &LifecycleExpiration{Date: now.Add(-time.Second).Format(time.RFC3339)},
			},
		},
		now,
		time.Second,
	) {
		t.Fatal("valid expiration date should delete when due")
	}

	if lifecycleRuleMatchesUpload(LifecycleRule{}, nil) {
		t.Fatal("nil upload should not match")
	}
	if lifecycleRuleMatchesUpload(LifecycleRule{Prefix: "x/"}, &MultipartUpload{Key: "k"}) {
		t.Fatal("upload prefix mismatch should fail")
	}
	if !lifecycleRuleMatchesUpload(LifecycleRule{}, &MultipartUpload{Key: "k"}) {
		t.Fatal("rule without filter should match upload")
	}
	if lifecycleRuleMatchesUpload(
		LifecycleRule{Filter: &LifecycleFilter{Prefix: "x/"}},
		&MultipartUpload{Key: "k"},
	) {
		t.Fatal("filter prefix mismatch should fail")
	}
	if lifecycleRuleMatchesUpload(
		LifecycleRule{Filter: &LifecycleFilter{Tag: &Tag{Key: "a", Value: "1"}}},
		&MultipartUpload{Key: "k", Tags: map[string]string{"a": "2"}},
	) {
		t.Fatal("filter tag mismatch should fail")
	}
	if lifecycleRuleMatchesUpload(
		LifecycleRule{Filter: &LifecycleFilter{And: &LifecycleFilterAnd{Prefix: "x/"}}},
		&MultipartUpload{Key: "k"},
	) {
		t.Fatal("AND prefix mismatch should fail")
	}
	if lifecycleRuleMatchesUpload(
		LifecycleRule{
			Filter: &LifecycleFilter{And: &LifecycleFilterAnd{Tags: []Tag{{Key: "a", Value: "1"}}}},
		},
		&MultipartUpload{Key: "k", Tags: map[string]string{"a": "2"}},
	) {
		t.Fatal("AND tag mismatch should fail")
	}
	if !lifecycleRuleMatchesUpload(
		LifecycleRule{
			Filter: &LifecycleFilter{
				And: &LifecycleFilterAnd{Prefix: "k", Tags: []Tag{{Key: "a", Value: "1"}}},
			},
		},
		&MultipartUpload{Key: "k/ok", Tags: map[string]string{"a": "1"}},
	) {
		t.Fatal("expected AND upload filter match")
	}

	if uploadHasTag(nil, Tag{Key: "k", Value: "v"}) {
		t.Fatal("nil upload should not have tags")
	}
	if uploadHasTag(&MultipartUpload{}, Tag{Key: "k", Value: "v"}) {
		t.Fatal("upload without tags should not match")
	}
	if uploadHasTag(&MultipartUpload{Tags: map[string]string{"k": "v"}}, Tag{Key: "", Value: "v"}) {
		t.Fatal("empty tag key should fail")
	}
	if uploadHasTag(
		&MultipartUpload{Tags: map[string]string{"k": "v"}},
		Tag{Key: "k", Value: "x"},
	) {
		t.Fatal("tag value mismatch should fail")
	}
	if !uploadHasTag(
		&MultipartUpload{Tags: map[string]string{"k": "v"}},
		Tag{Key: "k", Value: "v"},
	) {
		t.Fatal("tag value match should pass")
	}

	if _, err := parseLifecycleDate(now.Format(time.RFC3339)); err != nil {
		t.Fatalf("RFC3339 lifecycle date should parse: %v", err)
	}
	if _, err := parseLifecycleDate(now.Format("2006-01-02")); err != nil {
		t.Fatalf("YYYY-MM-DD lifecycle date should parse: %v", err)
	}
	if _, err := parseLifecycleDate("invalid-date"); err == nil {
		t.Fatal("invalid lifecycle date should fail")
	}
}

func TestApplyLifecycleAndMultipartLifecycleBranches(t *testing.T) {
	b := New()
	base := time.Now().UTC()
	now := base.Add(72 * time.Hour)

	b.buckets["skip-no-lifecycle"] = &Bucket{
		Name:    "skip-no-lifecycle",
		Objects: map[string]*ObjectVersions{},
	}

	lifecycleBucket := &Bucket{
		Name:             "lifecycle-bucket",
		VersioningStatus: VersioningEnabled,
		Objects: map[string]*ObjectVersions{
			"nil-versions":   nil,
			"empty-versions": {Versions: nil},
			"expire/key": {Versions: []*Object{{
				Key:          "expire/key",
				IsLatest:     true,
				LastModified: base,
			}}},
			"keep/key": {Versions: []*Object{{
				Key:          "keep/key",
				IsLatest:     true,
				LastModified: now,
			}}},
			"prune/key": {Versions: []*Object{{
				Key:          "prune/key",
				IsLatest:     false,
				LastModified: base,
			}}},
		},
		LifecycleConfiguration: &LifecycleConfiguration{
			Rules: []LifecycleRule{
				{
					Status:     LifecycleStatusEnabled,
					Prefix:     "expire/",
					Expiration: &LifecycleExpiration{Days: 1},
				},
				{
					Status: LifecycleStatusEnabled,
					Prefix: "prune/",
					NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
						NoncurrentDays: 1,
					},
				},
			},
		},
	}
	b.buckets["lifecycle-bucket"] = lifecycleBucket

	b.uploads["nil-upload"] = nil
	b.uploads["missing-bucket-upload"] = &MultipartUpload{
		UploadId:  "missing-bucket-upload",
		Bucket:    "missing-bucket",
		Key:       "x",
		Initiated: base.Format(time.RFC3339),
		Parts:     map[int]*PartInfo{},
		Tags:      map[string]string{},
		Metadata:  map[string]string{},
		Owner:     DefaultOwner(),
		Initiator: DefaultOwner(),
	}
	b.buckets["upload-no-config"] = &Bucket{
		Name:    "upload-no-config",
		Objects: map[string]*ObjectVersions{},
	}
	b.uploads["no-config-upload"] = &MultipartUpload{
		UploadId:  "no-config-upload",
		Bucket:    "upload-no-config",
		Key:       "x",
		Initiated: base.Format(time.RFC3339),
		Parts:     map[int]*PartInfo{},
		Owner:     DefaultOwner(),
		Initiator: DefaultOwner(),
	}

	b.buckets["upload-bad-time"] = &Bucket{
		Name:    "upload-bad-time",
		Objects: map[string]*ObjectVersions{},
		LifecycleConfiguration: &LifecycleConfiguration{
			Rules: []LifecycleRule{
				{
					Status: LifecycleStatusEnabled,
					AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
						DaysAfterInitiation: 1,
					},
				},
			},
		},
	}
	b.uploads["bad-time-upload"] = &MultipartUpload{
		UploadId:  "bad-time-upload",
		Bucket:    "upload-bad-time",
		Key:       "x",
		Initiated: "not-rfc3339",
		Parts:     map[int]*PartInfo{},
		Owner:     DefaultOwner(),
		Initiator: DefaultOwner(),
	}

	b.buckets["upload-rules"] = &Bucket{
		Name:    "upload-rules",
		Objects: map[string]*ObjectVersions{},
		LifecycleConfiguration: &LifecycleConfiguration{Rules: []LifecycleRule{
			{
				Status: LifecycleStatusDisabled,
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 1,
				},
			},
			{
				Status: LifecycleStatusEnabled,
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 0,
				},
			},
			{
				Status: LifecycleStatusEnabled,
				Prefix: "miss/",
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 1,
				},
			},
			{
				Status: LifecycleStatusEnabled,
				Prefix: "ok/",
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 1,
				},
			},
		}},
	}
	b.uploads["rule-skip-upload"] = &MultipartUpload{
		UploadId:  "rule-skip-upload",
		Bucket:    "upload-rules",
		Key:       "other/key",
		Initiated: base.Format(time.RFC3339),
		Parts:     map[int]*PartInfo{},
		Owner:     DefaultOwner(),
		Initiator: DefaultOwner(),
	}
	b.uploads["rule-expire-upload"] = &MultipartUpload{
		UploadId:  "rule-expire-upload",
		Bucket:    "upload-rules",
		Key:       "ok/key",
		Initiated: base.Format(time.RFC3339),
		Parts:     map[int]*PartInfo{},
		Owner:     DefaultOwner(),
		Initiator: DefaultOwner(),
	}

	b.ApplyLifecycle(now, 0)

	if _, exists := lifecycleBucket.Objects["nil-versions"]; exists {
		t.Fatal("expected nil version entry to be removed")
	}
	if _, exists := lifecycleBucket.Objects["empty-versions"]; exists {
		t.Fatal("expected empty version entry to be removed")
	}
	if _, exists := lifecycleBucket.Objects["prune/key"]; exists {
		t.Fatal("expected pruned noncurrent key to be removed")
	}
	if versions, exists := lifecycleBucket.Objects["expire/key"]; !exists ||
		len(versions.Versions) < 1 ||
		!versions.Versions[0].IsDeleteMarker {
		t.Fatalf("expected expire/key latest to become delete marker, got %+v", versions)
	}
	if versions, exists := lifecycleBucket.Objects["keep/key"]; !exists ||
		len(versions.Versions) == 0 ||
		versions.Versions[0].IsDeleteMarker {
		t.Fatalf("expected keep/key to remain visible, got %+v", versions)
	}

	if _, exists := b.uploads["rule-expire-upload"]; exists {
		t.Fatal("expected matching multipart upload to be expired")
	}
	if _, exists := b.uploads["rule-skip-upload"]; !exists {
		t.Fatal("expected prefix-mismatched multipart upload to remain")
	}
	if _, exists := b.uploads["bad-time-upload"]; !exists {
		t.Fatal("expected bad-time multipart upload to remain")
	}
	if _, exists := b.uploads["missing-bucket-upload"]; !exists {
		t.Fatal("expected missing-bucket multipart upload to remain")
	}
	if _, exists := b.uploads["no-config-upload"]; !exists {
		t.Fatal("expected no-config multipart upload to remain")
	}
}

func TestDirectLifecycleEdgeBranches(t *testing.T) {
	b := New()
	now := time.Now().UTC()
	bucket := &Bucket{LifecycleConfiguration: &LifecycleConfiguration{Rules: []LifecycleRule{}}}

	if b.shouldExpireCurrentVersion(bucket, "k", nil, now, time.Second) {
		t.Fatal("nil versions should not expire")
	}
	if got := applyNoncurrentExpirationRules("k", nil, nil, now, time.Second); got != nil {
		t.Fatalf("expected nil versions to stay nil, got %+v", got)
	}
}

func TestCompleteMultipartUploadNormalizedPartsGuardBranch(t *testing.T) {
	b := New()
	if err := b.CreateBucket("multipart-normalize-guard"); err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	upload, err := b.CreateMultipartUpload(
		"multipart-normalize-guard",
		"obj",
		CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload failed: %v", err)
	}

	if _, err := b.UploadPart("multipart-normalize-guard", "obj", upload.UploadId, 1, []byte("x")); err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	_, err = b.CompleteMultipartUpload(
		"multipart-normalize-guard",
		"obj",
		upload.UploadId,
		[]CompletePart{{PartNumber: 0, ETag: "ignored"}},
	)
	if err != nil && !errors.Is(err, ErrInvalidPartOrder) && !errors.Is(err, ErrInvalidPart) {
		t.Fatalf("unexpected error for invalid part number completion: %v", err)
	}
}
