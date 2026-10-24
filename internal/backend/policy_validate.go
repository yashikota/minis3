package backend

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// MaxBucketPolicySize is the AWS limit on a bucket policy document (20 KB).
const MaxBucketPolicySize = 20 * 1024

// PolicyValidationError describes why PutBucketPolicy rejected a policy.
// It matches ErrMalformedPolicy with errors.Is.
type PolicyValidationError struct {
	Message string
}

func (e *PolicyValidationError) Error() string { return e.Message }

func (e *PolicyValidationError) Unwrap() error { return ErrMalformedPolicy }

func policyError(format string, args ...any) error {
	return &PolicyValidationError{Message: fmt.Sprintf(format, args...)}
}

var (
	policyTopLevelFields = map[string]bool{"Version": true, "Id": true, "Statement": true}
	policyStatementField = map[string]bool{
		"Sid": true, "Effect": true,
		"Principal": true, "NotPrincipal": true,
		"Action": true, "NotAction": true,
		"Resource": true, "NotResource": true,
		"Condition": true,
	}
	policyPrincipalKinds = map[string]bool{
		"AWS": true, "CanonicalUser": true, "Service": true, "Federated": true,
	}
	policyActionPattern       = regexp.MustCompile(`^[A-Za-z0-9-]+:[A-Za-z0-9*?]+$`)
	policyConditionKeyPattern = regexp.MustCompile(`^[A-Za-z0-9-]+:[^\s]+$`)
)

// ValidateBucketPolicy checks a bucket policy document against the IAM policy
// grammar as S3 enforces it for PutBucketPolicy. bucketName, when non-empty,
// is the bucket the policy is attached to; every resource must refer to it.
//
// The checks reject everything the evaluator would otherwise have to ignore
// silently: unknown elements, unknown condition operators, malformed values,
// unknown s3 actions, and statements missing a required element.
func ValidateBucketPolicy(policy, bucketName string) error {
	if len(policy) > MaxBucketPolicySize {
		return policyError("Policies must be less than %d bytes", MaxBucketPolicySize)
	}
	decoder := json.NewDecoder(strings.NewReader(policy))
	decoder.UseNumber()
	var doc any
	if err := decoder.Decode(&doc); err != nil {
		return policyError("This policy contains invalid Json")
	}
	if decoder.More() {
		return policyError("This policy contains invalid Json")
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return policyError("This policy contains invalid Json")
	}
	for field := range top {
		if !policyTopLevelFields[field] {
			return policyError("Unknown field %s", field)
		}
	}
	if v, ok := top["Version"]; ok {
		version, _ := v.(string)
		if version != "2012-10-17" && version != "2008-10-17" {
			return policyError("The policy must contain a valid version string")
		}
	}
	if v, ok := top["Id"]; ok {
		if _, isString := v.(string); !isString {
			return policyError("Id must be a string")
		}
	}
	rawStatements, ok := top["Statement"]
	if !ok {
		return policyError("Missing required field Statement")
	}
	var statements []any
	switch s := rawStatements.(type) {
	case map[string]any:
		statements = []any{s}
	case []any:
		statements = s
	default:
		return policyError("Statement must be an object or an array of objects")
	}
	if len(statements) == 0 {
		return policyError("Missing required field Statement")
	}
	for _, raw := range statements {
		stmt, ok := raw.(map[string]any)
		if !ok {
			return policyError("Statement must be an object or an array of objects")
		}
		if err := validatePolicyStatement(stmt, bucketName); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyStatement(stmt map[string]any, bucketName string) error {
	for field := range stmt {
		if !policyStatementField[field] {
			return policyError("Unknown field %s", field)
		}
	}
	if raw, ok := stmt["Sid"]; ok {
		if _, isString := raw.(string); !isString {
			return policyError("Sid must be a string")
		}
		// Unlike IAM identity policies, S3 accepts repeated Sids in a
		// bucket policy (s3-tests test_put_bucket_logging_policy_wildcard).
	}

	effect, ok := stmt["Effect"]
	if !ok {
		return policyError("Missing required field Effect")
	}
	if effect != "Allow" && effect != "Deny" {
		return policyError("Invalid effect: %v", effect)
	}

	principalKey, err := exactlyOne(stmt, "Principal", "NotPrincipal")
	if err != nil {
		return err
	}
	if principalKey == "NotPrincipal" && effect == "Allow" {
		return policyError("NotPrincipal is not supported with an Allow effect")
	}
	if err := validatePolicyPrincipal(stmt[principalKey]); err != nil {
		return err
	}

	actionKey, err := exactlyOne(stmt, "Action", "NotAction")
	if err != nil {
		return err
	}
	actions, ok := policyStrings(stmt[actionKey])
	if !ok {
		return policyError("Policy has invalid action")
	}
	for _, action := range actions {
		if err := validatePolicyAction(action); err != nil {
			return err
		}
	}

	// AWS requires a Resource element, but Ceph RGW and the s3-tests suite
	// (test_bucket_logging_owner) accept a statement without one, applying
	// it to every resource of the bucket. minis3 follows them:
	// matchesResource treats an absent Resource as "*".
	_, hasResource := stmt["Resource"]
	_, hasNotResource := stmt["NotResource"]
	if hasResource || hasNotResource {
		resourceKey, err := exactlyOne(stmt, "Resource", "NotResource")
		if err != nil {
			return err
		}
		resources, ok := policyStrings(stmt[resourceKey])
		if !ok {
			return policyError("Policy has invalid resource")
		}
		for _, resource := range resources {
			if err := validatePolicyResource(resource, bucketName); err != nil {
				return err
			}
		}
	}

	if raw, ok := stmt["Condition"]; ok {
		return validatePolicyConditionBlock(raw)
	}
	return nil
}

// exactlyOne returns which of the two mutually exclusive elements is present.
func exactlyOne(stmt map[string]any, element, notElement string) (string, error) {
	_, has := stmt[element]
	_, hasNot := stmt[notElement]
	switch {
	case has && hasNot:
		return "", policyError("Statement cannot contain both %s and %s", element, notElement)
	case has:
		return element, nil
	case hasNot:
		return notElement, nil
	default:
		return "", policyError("Missing required field %s", element)
	}
}

// policyStrings returns a non-empty list of non-empty strings from a string
// or array-of-strings element.
func policyStrings(raw any) ([]string, bool) {
	var values []string
	switch v := raw.(type) {
	case string:
		values = []string{v}
	case []any:
		var ok bool
		if values, ok = stringValues(v); !ok {
			return nil, false
		}
	default:
		return nil, false
	}
	if len(values) == 0 {
		return nil, false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return nil, false
		}
	}
	return values, true
}

func validatePolicyPrincipal(raw any) error {
	invalid := policyError("Invalid principal in policy")
	switch p := raw.(type) {
	case string:
		if p != "*" {
			return invalid
		}
		return nil
	case map[string]any:
		if len(p) == 0 {
			return invalid
		}
		for kind, values := range p {
			if !policyPrincipalKinds[kind] {
				return invalid
			}
			if _, ok := policyStrings(values); !ok {
				return invalid
			}
		}
		return nil
	default:
		return invalid
	}
}

func validatePolicyAction(action string) error {
	if action == "*" {
		return nil
	}
	if !policyActionPattern.MatchString(action) {
		return policyError("Policy has invalid action")
	}
	service, name, _ := strings.Cut(action, ":")
	if !strings.EqualFold(service, "s3") {
		return policyError("Policy has invalid action")
	}
	if !strings.ContainsAny(name, "*?") && !IsKnownS3PolicyAction(action) {
		return policyError("Policy has invalid action")
	}
	return nil
}

func validatePolicyResource(resource, bucketName string) error {
	if resource == "*" {
		return nil
	}
	parts := strings.SplitN(resource, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "s3" || parts[5] == "" {
		return policyError("Policy has invalid resource")
	}
	if bucketName == "" {
		return nil
	}
	bucketPattern, _, _ := strings.Cut(parts[5], "/")
	if !wildcardMatch(bucketPattern, displayBucketNameForPolicy(bucketName)) {
		return policyError("Policy has invalid resource")
	}
	return nil
}

// displayBucketNameForPolicy strips a "tenant:" qualifier from a bucket name.
func displayBucketNameForPolicy(bucketName string) string {
	if i := strings.Index(bucketName, ":"); i >= 0 && i+1 < len(bucketName) {
		return bucketName[i+1:]
	}
	return bucketName
}

func validatePolicyConditionBlock(raw any) error {
	block, ok := raw.(map[string]any)
	if !ok {
		return policyError("Condition must be an object")
	}
	for operatorName, rawKeys := range block {
		op, ok := parseConditionOperator(operatorName)
		if !ok {
			return policyError("Invalid Condition type : %s", operatorName)
		}
		keys, ok := rawKeys.(map[string]any)
		if !ok || len(keys) == 0 {
			return policyError("Invalid Condition block for %s", operatorName)
		}
		for key, rawValues := range keys {
			if !policyConditionKeyPattern.MatchString(key) {
				return policyError("Policy has an invalid condition key")
			}
			values, ok := conditionValueStrings(rawValues)
			if !ok {
				return policyError("Invalid Condition value for %s", key)
			}
			for _, value := range values {
				if !validConditionValue(op.kind, value) {
					return policyError("Invalid Condition value for %s: %s", key, value)
				}
			}
		}
	}
	return nil
}

// conditionValueStrings accepts a string, number or boolean, or a non-empty
// array of them, matching what PolicyStringOrSlice decodes.
func conditionValueStrings(raw any) ([]string, bool) {
	items, isArray := raw.([]any)
	if !isArray {
		items = []any{raw}
	}
	if len(items) == 0 {
		return nil, false
	}
	values := make([]string, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case string:
			values = append(values, v)
		case json.Number:
			values = append(values, v.String())
		case bool:
			values = append(values, fmt.Sprint(v))
		default:
			return nil, false
		}
	}
	return values, true
}

func validConditionValue(kind conditionKind, value string) bool {
	switch kind {
	case condNumericEquals, condNumericLessThan, condNumericLessThanEquals,
		condNumericGreaterThan, condNumericGreaterThanEquals:
		_, ok := parsePolicyNumber(value)
		return ok
	case condDateEquals, condDateLessThan, condDateLessThanEquals,
		condDateGreaterThan, condDateGreaterThanEquals:
		_, ok := parsePolicyDate(value)
		return ok
	case condBool, condNull:
		return strings.EqualFold(value, "true") || strings.EqualFold(value, "false")
	case condIPAddress:
		_, ok := parsePolicyCIDR(value)
		return ok
	default:
		return true
	}
}
