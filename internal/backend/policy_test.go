package backend

import (
	"encoding/json"
	"testing"
)

func mustPolicyJSON(t *testing.T, policy map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	return string(raw)
}

func TestEvaluateBucketPolicy(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		ctx      PolicyEvalContext
		wantDeny bool
	}{
		{
			name:   "empty policy does not deny",
			policy: "",
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: false,
		},
		{
			name:   "malformed policy does not deny",
			policy: "{not-json",
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: false,
		},
		{
			name: "deny without conditions is unconditional",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: true,
		},
		{
			name: "allow effect is ignored",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Allow",
						"Action": "s3:PutObject",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: false,
		},
		{
			name: "action mismatch does not deny",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:GetObject",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: false,
		},
		{
			name: "action wildcard matches",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "*",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
			},
			wantDeny: true,
		},
		{
			name: "string equals condition match denies",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"StringEquals": map[string]string{
								"s3:x-amz-server-side-encryption": "AES256",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
				Headers: map[string]string{
					"x-amz-server-side-encryption": "AES256",
				},
			},
			wantDeny: true,
		},
		{
			name: "string equals condition mismatch does not deny",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"StringEquals": map[string]string{
								"s3:x-amz-server-side-encryption": "AES256",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
				Headers: map[string]string{
					"x-amz-server-side-encryption": "aws:kms",
				},
			},
			wantDeny: false,
		},
		{
			name: "string not equals condition match denies",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"StringNotEquals": map[string]string{
								"s3:x-amz-server-side-encryption": "AES256",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
				Headers: map[string]string{
					"x-amz-server-side-encryption": "aws:kms",
				},
			},
			wantDeny: true,
		},
		{
			name: "null true on missing header denies",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"Null": map[string]string{
								"s3:x-amz-server-side-encryption": "true",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:  "s3:PutObject",
				Headers: map[string]string{},
			},
			wantDeny: true,
		},
		{
			name: "generic s3 header mapping works",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"StringEquals": map[string]string{
								"s3:x-amz-meta-project": "test",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
				Headers: map[string]string{
					"x-amz-meta-project": "test",
				},
			},
			wantDeny: true,
		},
		{
			name: "unknown operator does not match",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect": "Deny",
						"Action": "s3:PutObject",
						"Condition": map[string]any{
							"NumericEquals": map[string]string{
								"s3:x-amz-meta-project": "test*",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action: "s3:PutObject",
				Headers: map[string]string{
					"x-amz-meta-project": "test-app",
				},
			},
			wantDeny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateBucketPolicy(tt.policy, tt.ctx)
			if got != tt.wantDeny {
				t.Fatalf("EvaluateBucketPolicy() = %v, want %v", got, tt.wantDeny)
			}
		})
	}
}

func TestEvaluateBucketPolicyAccess(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		ctx        PolicyEvalContext
		wantEffect PolicyEffect
	}{
		{
			name: "deny takes precedence over allow",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::bucket/*",
					},
					map[string]any{
						"Effect":   "Deny",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::bucket/*",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::bucket/path/to/object",
			},
			wantEffect: PolicyEffectDeny,
		},
		{
			name: "allow on wildcard resource",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::bucket/*",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::bucket/path/to/object",
			},
			wantEffect: PolicyEffectAllow,
		},
		{
			name: "existing object tag condition match",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::bucket/*",
						"Condition": map[string]any{
							"StringEquals": map[string]string{
								"s3:ExistingObjectTag/Project": "alpha",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:             "s3:GetObject",
				Resource:           "arn:aws:s3:::bucket/object",
				ExistingObjectTags: map[string]string{"Project": "alpha"},
			},
			wantEffect: PolicyEffectAllow,
		},
		{
			name: "request object tag condition match",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:PutObject",
						"Resource": "arn:aws:s3:::bucket/*",
						"Condition": map[string]any{
							"StringEquals": map[string]string{
								"s3:RequestObjectTag/Environment": "dev",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:            "s3:PutObject",
				Resource:          "arn:aws:s3:::bucket/object",
				RequestObjectTags: map[string]string{"Environment": "dev"},
			},
			wantEffect: PolicyEffectAllow,
		},
		{
			name: "string like matches wildcard",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:GetObject",
						"Resource": "arn:aws:s3:::bucket/*",
						"Condition": map[string]any{
							"StringLike": map[string]string{
								"aws:Referer": "https://*.example.com/*",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::bucket/object",
				Headers:  map[string]string{"referer": "https://app.example.com/path"},
			},
			wantEffect: PolicyEffectAllow,
		},
		{
			name: "ifexists passes when key missing",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:PutObject",
						"Resource": "arn:aws:s3:::bucket/*",
						"Condition": map[string]any{
							"StringEqualsIfExists": map[string]string{
								"s3:x-amz-meta-project": "alpha",
							},
						},
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:   "s3:PutObject",
				Resource: "arn:aws:s3:::bucket/object",
				Headers:  map[string]string{},
			},
			wantEffect: PolicyEffectAllow,
		},
		{
			name: "no statement match returns default",
			policy: mustPolicyJSON(t, map[string]any{
				"Version": "2012-10-17",
				"Statement": []any{
					map[string]any{
						"Effect":   "Allow",
						"Action":   "s3:DeleteObject",
						"Resource": "arn:aws:s3:::bucket/*",
					},
				},
			}),
			ctx: PolicyEvalContext{
				Action:   "s3:GetObject",
				Resource: "arn:aws:s3:::bucket/object",
			},
			wantEffect: PolicyEffectDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateBucketPolicyAccess(tt.policy, tt.ctx)
			if got != tt.wantEffect {
				t.Fatalf("EvaluateBucketPolicyAccess() = %v, want %v", got, tt.wantEffect)
			}
		})
	}
}
