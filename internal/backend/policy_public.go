package backend

import "strings"

// restrictingConditionKeys are the condition keys that make a statement
// granting access to "*" non-public when pinned to fixed values (AWS S3
// User Guide, "The meaning of public").
var restrictingConditionKeys = map[string]bool{
	"aws:sourceip":              true,
	"aws:sourcearn":             true,
	"aws:sourcevpc":             true,
	"aws:sourcevpce":            true,
	"aws:sourceowner":           true,
	"aws:sourceaccount":         true,
	"aws:userid":                true,
	"aws:principalorgid":        true,
	"aws:principalaccount":      true,
	"aws:principalarn":          true,
	"s3:dataaccesspointarn":     true,
	"s3:dataaccesspointaccount": true,
}

// IsPolicyPublic reports whether the policy grants access to everyone: it has
// an Allow statement for the "*" principal that no condition pins to fixed
// values of a restricting key (source IP range, source ARN/account/VPC,
// principal account/org/ARN, user ID).
func IsPolicyPublic(policyJSON string) bool {
	policy, ok := parseBucketPolicy(policyJSON)
	if !ok {
		return false
	}
	for i := range policy.Statement {
		stmt := &policy.Statement[i]
		if stmt.Effect != "Allow" || !isPublicPrincipal(stmt.Principal) {
			continue
		}
		if !conditionsRestrictAccess(stmt.Condition) {
			return true
		}
	}
	return false
}

// conditionsRestrictAccess reports whether a condition block confines a
// statement to fixed callers. Conditions are ANDed, so one restricting
// condition is enough.
func conditionsRestrictAccess(conditions map[string]map[string]PolicyStringOrSlice) bool {
	for operatorName, keys := range conditions {
		op, ok := parseConditionOperator(operatorName)
		if !ok || op.negated || op.ifExists || op.set == condSetForAllValues {
			// A negated operator or IfExists can be satisfied by requests
			// from anywhere; ForAllValues is vacuously true when the key is
			// missing.
			continue
		}
		for key, values := range keys {
			if restrictsToFixedValues(op, strings.ToLower(key), values) {
				return true
			}
		}
	}
	return false
}

func restrictsToFixedValues(op conditionOperator, key string, values []string) bool {
	if !restrictingConditionKeys[key] || len(values) == 0 {
		return false
	}
	switch op.kind {
	case condIPAddress:
		if key != "aws:sourceip" {
			return false
		}
		for _, value := range values {
			ipNet, ok := parsePolicyCIDR(value)
			if !ok {
				return false
			}
			ones, bits := ipNet.Mask.Size()
			// Very broad ranges are as good as public.
			if (bits == 32 && ones < 8) || (bits == 128 && ones < 32) {
				return false
			}
		}
		return true
	case condString, condStringIgnoreCase, condStringLike, condArn:
		for _, value := range values {
			if strings.ContainsAny(value, "*?") || strings.Contains(value, "${") {
				return false
			}
		}
		return true
	default:
		return false
	}
}
