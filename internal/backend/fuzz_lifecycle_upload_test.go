package backend

import "testing"

func FuzzLifecycleRuleMatchesUpload(f *testing.F) {
	f.Add("prefix/", "prefix/key.txt", "env", "prod", "env", "prod")
	f.Add("", "any-key", "", "", "", "")
	f.Add("logs/", "data/file.csv", "", "", "", "")
	f.Add("prefix/", "prefix/deep/key", "tag1", "val1", "tag1", "val1")

	f.Fuzz(
		func(t *testing.T, prefix, key, filterTagKey, filterTagVal, uploadTagKey, uploadTagVal string) {
			rule := LifecycleRule{
				Status: LifecycleStatusEnabled,
				Filter: &LifecycleFilter{
					Prefix: prefix,
				},
				AbortIncompleteMultipartUpload: &AbortIncompleteMultipartUpload{
					DaysAfterInitiation: 7,
				},
			}
			if filterTagKey != "" {
				rule.Filter.Tag = &Tag{Key: filterTagKey, Value: filterTagVal}
			}
			upload := &MultipartUpload{
				Key:  key,
				Tags: map[string]string{},
			}
			if uploadTagKey != "" {
				upload.Tags[uploadTagKey] = uploadTagVal
			}
			_ = lifecycleRuleMatchesUpload(rule, upload)
		},
	)
}

func FuzzEvaluateBucketPolicy(f *testing.F) {
	f.Add(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`,
		"AKID",
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
	)
	f.Add(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		"AKID",
		"s3:PutObject",
		"arn:aws:s3:::bucket/key",
	)
	f.Add(``, "AKID", "s3:GetObject", "arn:aws:s3:::bucket/key")
	f.Add(`invalid json`, "", "", "")
	f.Add(
		`{"Version":"2012-10-17","Statement":[]}`,
		"AKID",
		"s3:GetObject",
		"arn:aws:s3:::bucket/key",
	)

	f.Fuzz(func(t *testing.T, policyJSON, accessKey, action, resource string) {
		ctx := PolicyEvalContext{
			AccessKey: accessKey,
			Action:    action,
			Resource:  resource,
		}
		_ = EvaluateBucketPolicy(policyJSON, ctx)
	})
}
