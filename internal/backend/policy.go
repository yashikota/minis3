package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// BucketPolicy represents a parsed S3 bucket policy.
type BucketPolicy struct {
	Version   string              `json:"Version"`
	ID        string              `json:"Id,omitempty"`
	Statement PolicyStatementList `json:"Statement"`
}

// PolicyStatementList is a list of policy statements that unmarshals from
// either a JSON array or a single statement object. AWS IAM policy grammar
// accepts both forms.
type PolicyStatementList []PolicyStatement

func (l *PolicyStatementList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var single PolicyStatement
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*l = PolicyStatementList{single}
		return nil
	}
	var multi []PolicyStatement
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*l = multi
	return nil
}

var iamPolicyNamePattern = regexp.MustCompile(`^[\w+=,.@-]+$`)

// IsValidIAMPolicyName reports whether name is a valid IAM policy name:
// 1-128 characters of word characters and +=,.@- (per AWS IAM quotas).
func IsValidIAMPolicyName(name string) bool {
	return len(name) >= 1 && len(name) <= 128 && iamPolicyNamePattern.MatchString(name)
}

// ValidateIAMUserPolicyDocument checks IAM user policy grammar: the document
// must be a JSON object with a supported Version and a non-empty Statement
// (object or array), Sids must be unique, identity policies must not carry
// a Principal element, and effects must be Allow or Deny.
func ValidateIAMUserPolicyDocument(document string) error {
	var raw struct {
		Version   string              `json:"Version"`
		Statement PolicyStatementList `json:"Statement"`
	}
	decoder := json.NewDecoder(strings.NewReader(document))
	if err := decoder.Decode(&raw); err != nil {
		return ErrMalformedPolicyDocument
	}
	if raw.Version != "2012-10-17" && raw.Version != "2008-10-17" {
		return ErrMalformedPolicyDocument
	}
	if len(raw.Statement) == 0 {
		return ErrMalformedPolicyDocument
	}
	seenSids := make(map[string]struct{}, len(raw.Statement))
	for _, stmt := range raw.Statement {
		if stmt.Sid != "" {
			if _, dup := seenSids[stmt.Sid]; dup {
				return ErrMalformedPolicyDocument
			}
			seenSids[stmt.Sid] = struct{}{}
		}
		if stmt.Principal != nil || stmt.NotPrincipal != nil {
			return ErrMalformedPolicyDocument
		}
		if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
			return ErrMalformedPolicyDocument
		}
	}
	return nil
}

// PolicyStatement represents a single statement in a bucket policy.
//
// Action/NotAction, Resource/NotResource and Principal/NotPrincipal are
// mutually exclusive pairs. A nil slice (or nil principal) means the element
// is absent. ValidateBucketPolicy guarantees that a stored bucket policy has
// exactly one principal and one action element per statement, and at most
// one resource element (an absent Resource applies to the whole bucket).
type PolicyStatement struct {
	Sid          string                                    `json:"Sid,omitempty"`
	Effect       string                                    `json:"Effect"`
	Action       PolicyStringOrSlice                       `json:"Action,omitempty"`
	NotAction    PolicyStringOrSlice                       `json:"NotAction,omitempty"`
	Resource     PolicyStringOrSlice                       `json:"Resource,omitempty"`
	NotResource  PolicyStringOrSlice                       `json:"NotResource,omitempty"`
	Principal    any                                       `json:"Principal,omitempty"`
	NotPrincipal any                                       `json:"NotPrincipal,omitempty"`
	Condition    map[string]map[string]PolicyStringOrSlice `json:"Condition,omitempty"`
}

// PolicyStringOrSlice handles JSON fields that can be either a string or an array of strings.
type PolicyStringOrSlice []string

func (p *PolicyStringOrSlice) UnmarshalJSON(data []byte) error {
	// IAM accepts a single value or an array, and condition values may be
	// JSON booleans or numbers (e.g. {"Bool": {"aws:SecureTransport": false}}).
	// Numbers keep their literal spelling so that a large account ID written
	// as a number still compares equal to its string form.
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	values, ok := raw.([]any)
	if !ok {
		values = []any{raw}
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case json.Number:
			out = append(out, v.String())
		case bool:
			out = append(out, fmt.Sprint(v))
		default:
			return fmt.Errorf("unsupported policy value %v", v)
		}
	}
	*p = out
	return nil
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
	// Principal identifies the caller. When nil it is derived from
	// AccessKey/IsAnonymous with PrincipalForAccessKey.
	Principal *PolicyPrincipal
	// ConditionKeys holds request context values for global and
	// service-specific condition keys (aws:SourceIp, s3:prefix, ...). Keys
	// are matched case-insensitively, as IAM condition key names are.
	ConditionKeys map[string][]string
	// CurrentTime is the request time for aws:CurrentTime/aws:EpochTime.
	// The zero value means time.Now().
	CurrentTime time.Time
}

// parseBucketPolicy decodes a bucket policy for evaluation.
func parseBucketPolicy(policyJSON string) (*BucketPolicy, bool) {
	if policyJSON == "" {
		return nil, false
	}
	var policy BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, false
	}
	return &policy, true
}

// EvaluateBucketPolicy evaluates a bucket policy against the given context.
// Returns true if the request should be denied (for backward compatibility with SSE checks).
func EvaluateBucketPolicy(policyJSON string, ctx PolicyEvalContext) bool {
	effect := EvaluateBucketPolicyAccess(policyJSON, ctx)
	return effect == PolicyEffectDeny
}

// EvaluateBucketPolicyAccess evaluates a bucket policy and returns the effect.
// An applicable Deny statement wins over any Allow; if no statement applies
// the result is Default (implicit deny, left to the caller's ACL logic).
// Statement order is irrelevant.
func EvaluateBucketPolicyAccess(policyJSON string, ctx PolicyEvalContext) PolicyEffect {
	policy, ok := parseBucketPolicy(policyJSON)
	if !ok {
		return PolicyEffectDefault
	}
	return policy.evaluate(ctx)
}

func (p *BucketPolicy) evaluate(ctx PolicyEvalContext) PolicyEffect {
	ctx.Principal = resolvePrincipal(ctx)
	allowed := false
	for i := range p.Statement {
		stmt := &p.Statement[i]
		if !stmt.applies(ctx) || !evaluateConditions(stmt.Condition, ctx) {
			continue
		}
		switch stmt.Effect {
		case "Deny":
			return PolicyEffectDeny
		case "Allow":
			allowed = true
		}
	}
	if allowed {
		return PolicyEffectAllow
	}
	return PolicyEffectDefault
}

// applies reports whether the statement's principal, action and resource
// elements match the request, ignoring conditions.
func (s *PolicyStatement) applies(ctx PolicyEvalContext) bool {
	return s.matchesPrincipal(ctx) && s.matchesAction(ctx.Action) &&
		s.matchesResource(ctx.Resource)
}

func (s *PolicyStatement) matchesPrincipal(ctx PolicyEvalContext) bool {
	if s.NotPrincipal != nil {
		return !matchesPrincipal(s.NotPrincipal, ctx)
	}
	return matchesPrincipal(s.Principal, ctx)
}

func (s *PolicyStatement) matchesAction(action string) bool {
	if s.NotAction != nil {
		return !matchesAction(s.NotAction, action)
	}
	return matchesAction(s.Action, action)
}

func (s *PolicyStatement) matchesResource(resource string) bool {
	if s.NotResource != nil {
		return !matchesResource(s.NotResource, resource)
	}
	return matchesResource(s.Resource, resource)
}

// HasAllowStatementForRequest reports whether the policy has an Allow statement
// that matches principal/action/resource for the request context, regardless of conditions.
func HasAllowStatementForRequest(policyJSON string, ctx PolicyEvalContext) bool {
	policy, ok := parseBucketPolicy(policyJSON)
	if !ok {
		return false
	}
	ctx.Principal = resolvePrincipal(ctx)
	for i := range policy.Statement {
		stmt := &policy.Statement[i]
		if stmt.Effect == "Allow" && stmt.applies(ctx) {
			return true
		}
	}
	return false
}

func matchesAction(actions PolicyStringOrSlice, target string) bool {
	// IAM action names are case-insensitive and support * and ? wildcards
	// anywhere in the pattern.
	target = strings.ToLower(target)
	for _, action := range actions {
		if action == "*" || wildcardMatch(strings.ToLower(action), target) {
			return true
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
	// IAM ARN wildcards: "*" matches any run of characters including "/",
	// and "?" matches exactly one character. No other character is special.
	return wildcardMatch(pattern, target)
}

// wildcardMatch reports whether s matches an IAM wildcard pattern: "*"
// matches any run of characters (including "/" and none) and "?" exactly one
// character. Matching is per Unicode character, not per byte.
func wildcardMatch(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == s
	}
	p, str := []rune(pattern), []rune(s)
	px, sx := 0, 0
	starIdx, matchIdx := -1, 0

	for sx < len(str) {
		if px < len(p) && p[px] == '?' {
			px++
			sx++
		} else if px < len(p) && p[px] == '*' {
			starIdx = px
			matchIdx = sx
			px++
		} else if px < len(p) && p[px] == str[sx] {
			px++
			sx++
		} else if starIdx >= 0 {
			matchIdx++
			sx = matchIdx
			px = starIdx + 1
		} else {
			return false
		}
	}

	for px < len(p) && p[px] == '*' {
		px++
	}

	return px == len(p)
}
