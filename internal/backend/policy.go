package backend

import (
	"encoding/json"
	"path"
	"strings"
)

// BucketPolicy represents a parsed S3 bucket policy.
type BucketPolicy struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single statement in a bucket policy.
type PolicyStatement struct {
	Effect    string                       `json:"Effect"`
	Action    PolicyStringOrSlice          `json:"Action"`
	Resource  PolicyStringOrSlice          `json:"Resource"`
	Principal any                          `json:"Principal,omitempty"`
	Condition map[string]map[string]string `json:"Condition,omitempty"`
}

// PolicyStringOrSlice handles JSON fields that can be either a string or an array of strings.
type PolicyStringOrSlice []string

func (p *PolicyStringOrSlice) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*p = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*p = multi
		return nil
	}
	return json.Unmarshal(data, (*[]string)(p))
}

// PolicyEffect represents the result of policy evaluation.
type PolicyEffect int

const (
	PolicyEffectDefault PolicyEffect = iota
	PolicyEffectAllow
	PolicyEffectDeny
)

// PolicyEvalContext contains the context values for policy evaluation.
type PolicyEvalContext struct {
	Action             string
	Resource           string // e.g., "arn:aws:s3:::bucket/key"
	Headers            map[string]string
	ExistingObjectTags map[string]string
	RequestObjectTags  map[string]string
	AccessKey          string
	IsAnonymous        bool
}

// EvaluateBucketPolicy evaluates a bucket policy against the given context.
// Returns true if the request should be denied (for backward compatibility with SSE checks).
func EvaluateBucketPolicy(policyJSON string, ctx PolicyEvalContext) bool {
	effect := EvaluateBucketPolicyAccess(policyJSON, ctx)
	return effect == PolicyEffectDeny
}

// EvaluateBucketPolicyAccess evaluates a bucket policy and returns the effect.
// Deny takes priority over Allow. If no statement matches, returns Default.
func EvaluateBucketPolicyAccess(policyJSON string, ctx PolicyEvalContext) PolicyEffect {
	if policyJSON == "" {
		return PolicyEffectDefault
	}

	var policy BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return PolicyEffectDefault
	}

	hasAllow := false

	// First pass: check for explicit Deny (Deny takes priority)
	for _, stmt := range policy.Statement {
		if stmt.Effect != "Deny" {
			continue
		}
		if !matchesPrincipal(stmt.Principal, ctx) {
			continue
		}
		if !matchesAction(stmt.Action, ctx.Action) {
			continue
		}
		if !matchesResource(stmt.Resource, ctx.Resource) {
			continue
		}
		if evaluateConditions(stmt.Condition, ctx) {
			return PolicyEffectDeny
		}
	}

	// Second pass: check for explicit Allow
	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !matchesPrincipal(stmt.Principal, ctx) {
			continue
		}
		if !matchesAction(stmt.Action, ctx.Action) {
			continue
		}
		if !matchesResource(stmt.Resource, ctx.Resource) {
			continue
		}
		if evaluateConditions(stmt.Condition, ctx) {
			hasAllow = true
		}
	}

	if hasAllow {
		return PolicyEffectAllow
	}
	return PolicyEffectDefault
}

// HasAllowStatementForRequest reports whether the policy has an Allow statement
// that matches principal/action/resource for the request context, regardless of conditions.
func HasAllowStatementForRequest(policyJSON string, ctx PolicyEvalContext) bool {
	if policyJSON == "" {
		return false
	}

	var policy BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false
	}

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !matchesPrincipal(stmt.Principal, ctx) {
			continue
		}
		if !matchesAction(stmt.Action, ctx.Action) {
			continue
		}
		if !matchesResource(stmt.Resource, ctx.Resource) {
			continue
		}
		return true
	}
	return false
}

func matchesPrincipal(principal any, ctx PolicyEvalContext) bool {
	// Backward-compat: statements without Principal are treated as matching.
	if principal == nil {
		return true
	}

	values, ok := extractAWSPrincipals(principal)
	if !ok {
		return false
	}
	for _, value := range values {
		switch value {
		case "*":
			return true
		default:
			if ctx.AccessKey != "" && value == ctx.AccessKey {
				return true
			}
		}
	}
	return false
}

func extractAWSPrincipals(principal any) ([]string, bool) {
	switch p := principal.(type) {
	case string:
		return []string{p}, true
	case []any:
		values := make([]string, 0, len(p))
		for _, item := range p {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, s)
		}
		return values, true
	case map[string]any:
		rawAWS, ok := p["AWS"]
		if !ok {
			return nil, false
		}
		return extractAWSPrincipals(rawAWS)
	default:
		return nil, false
	}
}

func isPublicPrincipal(principal any) bool {
	values, ok := extractAWSPrincipals(principal)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

// IsPolicyPublic returns true when policy contains an unconditional public Allow.
func IsPolicyPublic(policyJSON string) bool {
	if policyJSON == "" {
		return false
	}

	var policy BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false
	}

	for _, stmt := range policy.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !isPublicPrincipal(stmt.Principal) {
			continue
		}
		// Conservative behavior: any condition makes it non-public.
		if len(stmt.Condition) > 0 {
			continue
		}
		return true
	}
	return false
}

func matchesAction(actions PolicyStringOrSlice, target string) bool {
	for _, action := range actions {
		if action == "*" || action == "s3:*" || strings.EqualFold(action, target) {
			return true
		}
		// Support prefix wildcards like s3:Get*
		if strings.HasSuffix(action, "*") {
			prefix := strings.TrimSuffix(action, "*")
			if strings.HasPrefix(strings.ToLower(target), strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}

func matchesResource(resources PolicyStringOrSlice, target string) bool {
	if len(resources) == 0 || target == "" {
		return true // No resource constraint or no resource context
	}
	for _, resource := range resources {
		if resource == "*" {
			return true
		}
		if matchResourcePattern(resource, target) {
			return true
		}
	}
	return false
}

func matchResourcePattern(pattern, target string) bool {
	// Exact match
	if pattern == target {
		return true
	}
	// Wildcard matching using path.Match style, but handle arn:aws:s3::: prefix
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		matched, err := path.Match(pattern, target)
		if err == nil && matched {
			return true
		}
		// path.Match doesn't match across path separators for *
		// So we need to handle arn:aws:s3:::bucket/* matching arn:aws:s3:::bucket/any/path/key
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "/*")
			if strings.HasPrefix(target, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func evaluateConditions(conditions map[string]map[string]string, ctx PolicyEvalContext) bool {
	if len(conditions) == 0 {
		return true // No conditions means unconditional match
	}

	// All condition operators must match (AND logic)
	for operator, condMap := range conditions {
		for condKey, condValue := range condMap {
			if !evaluateCondition(operator, condKey, condValue, ctx) {
				return false
			}
		}
	}
	return true
}

func evaluateCondition(operator, condKey, condValue string, ctx PolicyEvalContext) bool {
	if !conditionKeySupportedForAction(condKey, ctx.Action) {
		return false
	}

	// Handle IfExists suffix - if the key doesn't exist, the condition is satisfied
	isIfExists := strings.HasSuffix(operator, "IfExists")
	baseOperator := strings.TrimSuffix(operator, "IfExists")

	actualValue := getConditionKeyValue(condKey, ctx)

	if isIfExists && actualValue == "" {
		return true // Key doesn't exist, condition is vacuously true
	}

	switch baseOperator {
	case "StringEquals":
		return actualValue == condValue
	case "StringNotEquals":
		return actualValue != condValue
	case "StringLike":
		return matchWildcard(condValue, actualValue)
	case "StringNotLike":
		return !matchWildcard(condValue, actualValue)
	case "Null":
		isNull := actualValue == ""
		if condValue == "true" {
			return isNull
		}
		return !isNull
	default:
		return false
	}
}

func conditionKeySupportedForAction(condKey, action string) bool {
	if strings.HasPrefix(condKey, "s3:ExistingObjectTag/") {
		switch strings.ToLower(action) {
		case "s3:putobject", "s3:deleteobject":
			return false
		}
	}
	return true
}

func matchWildcard(pattern, s string) bool {
	// Simple wildcard matching: * matches any sequence, ? matches any single char
	return wildcardMatch(pattern, s)
}

func wildcardMatch(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip consecutive *
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true // trailing * matches everything
			}
			// Try matching rest of pattern at each position
			for i := 0; i <= len(s); i++ {
				if wildcardMatch(pattern, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		default:
			if len(s) == 0 || pattern[0] != s[0] {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		}
	}
	return len(s) == 0
}

func getConditionKeyValue(condKey string, ctx PolicyEvalContext) string {
	// ExistingObjectTag condition: s3:ExistingObjectTag/<key>
	if strings.HasPrefix(condKey, "s3:ExistingObjectTag/") {
		tagKey := condKey[len("s3:ExistingObjectTag/"):]
		if ctx.ExistingObjectTags != nil {
			return ctx.ExistingObjectTags[tagKey]
		}
		return ""
	}

	// RequestObjectTag condition: s3:RequestObjectTag/<key>
	if strings.HasPrefix(condKey, "s3:RequestObjectTag/") {
		tagKey := condKey[len("s3:RequestObjectTag/"):]
		if ctx.RequestObjectTags != nil {
			return ctx.RequestObjectTags[tagKey]
		}
		return ""
	}

	// aws: prefixed conditions (Referer, etc.)
	if strings.HasPrefix(condKey, "aws:") {
		headerName := condKey[len("aws:"):]
		if ctx.Headers != nil {
			return ctx.Headers[strings.ToLower(headerName)]
		}
		return ""
	}

	// s3: prefixed conditions (headers)
	if strings.HasPrefix(condKey, "s3:") {
		headerName := condKey[len("s3:"):]
		if ctx.Headers != nil {
			return ctx.Headers[headerName]
		}
		return ""
	}

	return ""
}
