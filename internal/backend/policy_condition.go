package backend

import (
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// conditionKind is the value type a condition operator compares.
type conditionKind int

const (
	condString conditionKind = iota
	condStringIgnoreCase
	condStringLike
	condNumericEquals
	condNumericLessThan
	condNumericLessThanEquals
	condNumericGreaterThan
	condNumericGreaterThanEquals
	condDateEquals
	condDateLessThan
	condDateLessThanEquals
	condDateGreaterThan
	condDateGreaterThanEquals
	condBool
	condBinary
	condIPAddress
	condArn
	condNull
)

type conditionOperatorSpec struct {
	kind    conditionKind
	negated bool
}

// conditionOperators lists every IAM condition operator. Each negated
// operator is defined as the negation of its positive counterpart.
var conditionOperators = map[string]conditionOperatorSpec{
	"StringEquals":              {condString, false},
	"StringNotEquals":           {condString, true},
	"StringEqualsIgnoreCase":    {condStringIgnoreCase, false},
	"StringNotEqualsIgnoreCase": {condStringIgnoreCase, true},
	"StringLike":                {condStringLike, false},
	"StringNotLike":             {condStringLike, true},
	"NumericEquals":             {condNumericEquals, false},
	"NumericNotEquals":          {condNumericEquals, true},
	"NumericLessThan":           {condNumericLessThan, false},
	"NumericLessThanEquals":     {condNumericLessThanEquals, false},
	"NumericGreaterThan":        {condNumericGreaterThan, false},
	"NumericGreaterThanEquals":  {condNumericGreaterThanEquals, false},
	"DateEquals":                {condDateEquals, false},
	"DateNotEquals":             {condDateEquals, true},
	"DateLessThan":              {condDateLessThan, false},
	"DateLessThanEquals":        {condDateLessThanEquals, false},
	"DateGreaterThan":           {condDateGreaterThan, false},
	"DateGreaterThanEquals":     {condDateGreaterThanEquals, false},
	"Bool":                      {condBool, false},
	"BinaryEquals":              {condBinary, false},
	"IpAddress":                 {condIPAddress, false},
	"NotIpAddress":              {condIPAddress, true},
	"ArnEquals":                 {condArn, false},
	"ArnLike":                   {condArn, false},
	"ArnNotEquals":              {condArn, true},
	"ArnNotLike":                {condArn, true},
	"Null":                      {condNull, false},
}

// Set operator qualifiers for multivalued condition keys.
const (
	condSetNone = iota
	condSetForAllValues
	condSetForAnyValue
)

// conditionOperator is a parsed condition operator such as
// "ForAnyValue:StringLikeIfExists".
type conditionOperator struct {
	conditionOperatorSpec
	name     string
	ifExists bool
	set      int
}

// parseConditionOperator parses an operator name. Operator names are
// case-sensitive in IAM.
func parseConditionOperator(name string) (conditionOperator, bool) {
	op := conditionOperator{name: name}
	rest := name
	switch {
	case strings.HasPrefix(rest, "ForAllValues:"):
		op.set = condSetForAllValues
		rest = strings.TrimPrefix(rest, "ForAllValues:")
	case strings.HasPrefix(rest, "ForAnyValue:"):
		op.set = condSetForAnyValue
		rest = strings.TrimPrefix(rest, "ForAnyValue:")
	}
	if base, ok := strings.CutSuffix(rest, "IfExists"); ok {
		op.ifExists = true
		rest = base
	}
	spec, ok := conditionOperators[rest]
	if !ok {
		return conditionOperator{}, false
	}
	if spec.kind == condNull && (op.ifExists || op.set != condSetNone) {
		// Null tests for presence itself; it has no IfExists or set form.
		return conditionOperator{}, false
	}
	op.conditionOperatorSpec = spec
	return op, true
}

func evaluateConditions(
	conditions map[string]map[string]PolicyStringOrSlice,
	ctx PolicyEvalContext,
) bool {
	if len(conditions) == 0 {
		return true // No conditions means unconditional match
	}

	// All condition operators and keys must match (AND logic). Multiple
	// values for one key are ORed; a negated operator is the negation of the
	// whole ORed match, so it holds only when no value matches.
	for operator, condMap := range conditions {
		for condKey, condValues := range condMap {
			if !evaluateConditionValues(operator, condKey, condValues, ctx) {
				return false
			}
		}
	}
	return true
}

func evaluateConditionValues(
	operator, condKey string,
	condValues PolicyStringOrSlice,
	ctx PolicyEvalContext,
) bool {
	op, ok := parseConditionOperator(operator)
	if !ok {
		// Unknown operators never match (ValidateBucketPolicy rejects them).
		return false
	}
	if !conditionKeySupportedForAction(condKey, ctx.Action) {
		return false
	}
	requestValues, present := lookupConditionKey(condKey, ctx)
	return op.evaluate(requestValues, present, condValues)
}

// evaluate applies the operator to the request's values for one key.
// present reports whether the key exists in the request context at all.
func (op conditionOperator) evaluate(
	requestValues []string,
	present bool,
	condValues []string,
) bool {
	if op.kind == condNull {
		for _, v := range condValues {
			if strings.EqualFold(v, "true") && !present {
				return true
			}
			if strings.EqualFold(v, "false") && present {
				return true
			}
		}
		return false
	}
	if !present || len(requestValues) == 0 {
		if op.ifExists {
			return true
		}
		switch op.set {
		case condSetForAllValues:
			// Vacuously true over an empty set of request values.
			return true
		case condSetForAnyValue:
			return false
		}
		// A missing key never matches; a negated operator therefore holds.
		return op.negated
	}
	single := func(requestValue string) bool {
		matched := false
		for _, condValue := range condValues {
			if conditionValueMatches(op.kind, requestValue, condValue) {
				matched = true
				break
			}
		}
		return matched != op.negated
	}
	switch op.set {
	case condSetForAllValues:
		for _, v := range requestValues {
			if !single(v) {
				return false
			}
		}
		return true
	default:
		// ForAnyValue, and for a single-valued key the plain operator,
		// hold when any request value satisfies the operator.
		if op.set == condSetNone {
			matched := false
			for _, v := range requestValues {
				for _, condValue := range condValues {
					if conditionValueMatches(op.kind, v, condValue) {
						matched = true
					}
				}
			}
			return matched != op.negated
		}
		for _, v := range requestValues {
			if single(v) {
				return true
			}
		}
		return false
	}
}

// conditionValueMatches is the positive (non-negated) comparison of one
// request value against one policy value.
func conditionValueMatches(kind conditionKind, requestValue, condValue string) bool {
	switch kind {
	case condString:
		return requestValue == condValue
	case condStringIgnoreCase:
		return strings.EqualFold(requestValue, condValue)
	case condStringLike:
		return wildcardMatch(condValue, requestValue)
	case condNumericEquals, condNumericLessThan, condNumericLessThanEquals,
		condNumericGreaterThan, condNumericGreaterThanEquals:
		a, okA := parsePolicyNumber(requestValue)
		b, okB := parsePolicyNumber(condValue)
		if !okA || !okB {
			return false
		}
		return compareOrdered(kind-condNumericEquals, cmpFloat(a, b))
	case condDateEquals, condDateLessThan, condDateLessThanEquals,
		condDateGreaterThan, condDateGreaterThanEquals:
		a, okA := parsePolicyDate(requestValue)
		b, okB := parsePolicyDate(condValue)
		if !okA || !okB {
			return false
		}
		return compareOrdered(kind-condDateEquals, a.Compare(b))
	case condBool:
		return strings.EqualFold(requestValue, condValue)
	case condBinary:
		return requestValue == condValue
	case condIPAddress:
		return ipInRange(requestValue, condValue)
	case condArn:
		return arnMatches(condValue, requestValue)
	default:
		return false
	}
}

// compareOrdered maps a comparison result onto the operator at offset rel
// from the Equals operator of its family (Equals, LessThan, LessThanEquals,
// GreaterThan, GreaterThanEquals).
func compareOrdered(rel conditionKind, c int) bool {
	switch rel {
	case 0:
		return c == 0
	case 1:
		return c < 0
	case 2:
		return c <= 0
	case 3:
		return c > 0
	default:
		return c >= 0
	}
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// parsePolicyNumber parses a Numeric condition value (integer or decimal).
func parsePolicyNumber(value string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

var policyDateLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// parsePolicyDate parses a Date condition value: an ISO 8601 timestamp or a
// Unix epoch in seconds.
func parsePolicyDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(epoch, 0).UTC(), true
	}
	for _, layout := range policyDateLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// parsePolicyCIDR parses an IpAddress condition value: a CIDR block or a
// bare IP address (treated as a single-address block).
func parsePolicyCIDR(value string) (*net.IPNet, bool) {
	value = strings.TrimSpace(value)
	if _, ipNet, err := net.ParseCIDR(value); err == nil {
		return ipNet, true
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, false
	}
	bits := 128
	if ip.To4() != nil {
		ip = ip.To4()
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, true
}

func ipInRange(requestValue, condValue string) bool {
	ipNet, ok := parsePolicyCIDR(condValue)
	if !ok {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(requestValue))
	if ip == nil {
		return false
	}
	return ipNet.Contains(ip)
}

// arnMatches implements ArnEquals/ArnLike: both ARNs are split into their
// six colon-separated components and each component is matched with IAM
// wildcards; the resource component may itself contain colons.
func arnMatches(pattern, arn string) bool {
	p := strings.SplitN(pattern, ":", 6)
	a := strings.SplitN(arn, ":", 6)
	if len(p) != 6 || len(a) != 6 || p[0] != "arn" || a[0] != "arn" {
		return false
	}
	for i := range p {
		if !wildcardMatch(p[i], a[i]) {
			return false
		}
	}
	return true
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

// lookupConditionKey returns the request's values for a condition key and
// whether the key is present in the request context.
func lookupConditionKey(condKey string, ctx PolicyEvalContext) ([]string, bool) {
	// Tag keys after the "/" are case-sensitive; the key names are not.
	if name, tagKey, ok := strings.Cut(condKey, "/"); ok {
		switch strings.ToLower(name) {
		case "s3:existingobjecttag":
			v, ok := ctx.ExistingObjectTags[tagKey]
			return []string{v}, ok
		case "s3:requestobjecttag":
			v, ok := ctx.RequestObjectTags[tagKey]
			return []string{v}, ok
		}
	}

	lower := strings.ToLower(condKey)
	if values, ok := ctx.ConditionKeys[lower]; ok {
		return values, true
	}

	principal := resolvePrincipal(ctx)
	switch lower {
	case "s3:requestobjecttagkeys":
		if ctx.RequestObjectTags == nil {
			return nil, false
		}
		keys := make([]string, 0, len(ctx.RequestObjectTags))
		for k := range ctx.RequestObjectTags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys, true
	case "aws:principaltype":
		return []string{principal.principalType()}, true
	case "aws:principalarn":
		return presentIfNonEmpty(principal.ARN)
	case "aws:principalaccount":
		return presentIfNonEmpty(principal.AccountID)
	case "aws:username":
		return presentIfNonEmpty(principal.UserName)
	case "aws:userid":
		if principal.Anonymous {
			return []string{"anonymous"}, true
		}
		return presentIfNonEmpty(principal.CanonicalID)
	case "aws:currenttime":
		return []string{ctx.now().Format(time.RFC3339)}, true
	case "aws:epochtime":
		return []string{strconv.FormatInt(ctx.now().Unix(), 10)}, true
	}

	// Request headers: aws:Referer, aws:UserAgent and s3:x-amz-* keys.
	if headerName, ok := strings.CutPrefix(lower, "aws:"); ok {
		return presentIfNonEmpty(ctx.Headers[headerName])
	}
	if strings.HasPrefix(lower, "s3:") {
		headerName := condKey[len("s3:"):]
		if v := ctx.Headers[headerName]; v != "" {
			return []string{v}, true
		}
		return presentIfNonEmpty(ctx.Headers[strings.ToLower(headerName)])
	}
	return nil, false
}

func presentIfNonEmpty(v string) ([]string, bool) {
	if v == "" {
		return nil, false
	}
	return []string{v}, true
}

// now returns the request time used for aws:CurrentTime and aws:EpochTime.
func (ctx PolicyEvalContext) now() time.Time {
	if ctx.CurrentTime.IsZero() {
		return time.Now().UTC()
	}
	return ctx.CurrentTime.UTC()
}
