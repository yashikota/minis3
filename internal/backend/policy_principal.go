package backend

import "strings"

// PolicyPrincipal is the identity a request is evaluated as.
type PolicyPrincipal struct {
	// Anonymous is set for unsigned requests. An anonymous caller matches
	// only the wildcard principal "*".
	Anonymous bool
	// AccessKey is the access key the request was signed with. minis3 also
	// accepts it as a principal value for backward compatibility.
	AccessKey string
	// AccountID is the AWS account the caller belongs to.
	AccountID string
	// ARN is the caller's IAM ARN (arn:aws:iam::<account>:root or :user/...).
	ARN string
	// CanonicalID is the S3 canonical user ID of the caller.
	CanonicalID string
	// UserName is the IAM user name (empty for the account root).
	UserName string
	// Service is set when the request is made by an AWS service principal
	// such as logging.s3.amazonaws.com.
	Service string
}

// iamAccountID is the account IAM users created through the IAM API belong
// to (the account of root-access-key).
const iamAccountID = "123456789012"

// rootAccountIDs maps the access keys of the static "root" test identities to
// their 12-digit account IDs. They match what IAM GetUser reports for them.
var rootAccountIDs = map[string]string{
	"root-access-key":    "123456789012",
	"altroot-access-key": "210987654321",
}

// PrincipalForAccessKey returns the policy identity of the caller that signs
// with accessKey. An empty access key is the anonymous principal. The account
// and ARN agree with what IAM GetUser reports for the same key.
func PrincipalForAccessKey(accessKey string) *PolicyPrincipal {
	if accessKey == "" {
		return &PolicyPrincipal{Anonymous: true}
	}
	owner := OwnerForAccessKey(accessKey)
	if account, ok := rootAccountIDs[accessKey]; ok {
		return &PolicyPrincipal{
			AccessKey:   accessKey,
			AccountID:   account,
			ARN:         "arn:aws:iam::" + account + ":root",
			CanonicalID: owner.ID,
		}
	}
	return &PolicyPrincipal{
		AccessKey:   accessKey,
		AccountID:   owner.ID,
		ARN:         "arn:aws:iam::" + owner.ID + ":user/" + owner.DisplayName,
		CanonicalID: owner.ID,
		UserName:    owner.DisplayName,
	}
}

// PrincipalForIAMUser returns the policy identity of an IAM user created
// through the IAM API.
func PrincipalForIAMUser(user *IAMUser, accessKey string) *PolicyPrincipal {
	account := iamAccountID
	if parts := strings.SplitN(user.Arn, ":", 6); len(parts) == 6 && parts[4] != "" {
		account = parts[4]
	}
	return &PolicyPrincipal{
		AccessKey:   accessKey,
		AccountID:   account,
		ARN:         user.Arn,
		CanonicalID: OwnerForAccessKey(accessKey).ID,
		UserName:    user.UserName,
	}
}

// LoggingServicePrincipal is the service principal S3 server access logging
// writes log objects as.
const LoggingServicePrincipal = "logging.s3.amazonaws.com"

func resolvePrincipal(ctx PolicyEvalContext) *PolicyPrincipal {
	if ctx.Principal != nil {
		return ctx.Principal
	}
	if ctx.IsAnonymous {
		return &PolicyPrincipal{Anonymous: true}
	}
	return PrincipalForAccessKey(ctx.AccessKey)
}

// principalType returns the aws:PrincipalType condition value.
func (p *PolicyPrincipal) principalType() string {
	switch {
	case p.Anonymous:
		return "Anonymous"
	case p.Service != "":
		return "Service"
	case p.UserName == "":
		return "Account"
	default:
		return "User"
	}
}

// principalValues extracts the values listed under each principal type
// ("AWS", "CanonicalUser", "Service", "Federated"). A bare string principal
// is treated as an "AWS" principal. It returns nil for a malformed element.
func principalValues(principal any) map[string][]string {
	out := make(map[string][]string)
	ok := forEachPrincipalValue(principal, func(kind, value string) bool {
		out[kind] = append(out[kind], value)
		return false
	})
	if !ok {
		return nil
	}
	return out
}

// forEachPrincipalValue calls fn for every (type, value) pair of a
// principal element until fn returns true. It reports false if the element
// is malformed.
func forEachPrincipalValue(principal any, fn func(kind, value string) bool) bool {
	visit := func(kind string, raw any) (stop, ok bool) {
		switch v := raw.(type) {
		case string:
			return fn(kind, v), true
		case []any:
			for _, item := range v {
				s, isString := item.(string)
				if !isString {
					return false, false
				}
				if fn(kind, s) {
					return true, true
				}
			}
			return false, true
		default:
			return false, false
		}
	}
	switch p := principal.(type) {
	case string, []any:
		_, ok := visit("AWS", p)
		return ok
	case map[string]any:
		for kind, raw := range p {
			stop, ok := visit(kind, raw)
			if !ok {
				return false
			}
			if stop {
				return true
			}
		}
		return true
	default:
		return false
	}
}

func stringValues(items []any) ([]string, bool) {
	values := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		values = append(values, s)
	}
	return values, true
}

func matchesPrincipal(principal any, ctx PolicyEvalContext) bool {
	// Backward-compat: statements without Principal are treated as matching.
	// ValidateBucketPolicy rejects such statements in stored bucket policies.
	if principal == nil {
		return true
	}
	caller := resolvePrincipal(ctx)
	matched := false
	forEachPrincipalValue(principal, func(kind, value string) bool {
		matched = principalValueMatches(kind, value, caller)
		return matched
	})
	return matched
}

func principalValueMatches(kind, value string, caller *PolicyPrincipal) bool {
	if caller.Service != "" {
		// A service principal is matched only by naming the service.
		return kind == "Service" && strings.EqualFold(value, caller.Service)
	}
	if value == "*" && (kind == "AWS" || kind == "CanonicalUser") {
		// "*" (or {"AWS": "*"}) is everyone, anonymous callers included.
		return true
	}
	if caller.Anonymous {
		return false
	}
	switch kind {
	case "AWS":
		switch value {
		case caller.AccessKey, caller.ARN:
			return value != ""
		case caller.AccountID, "arn:aws:iam::" + caller.AccountID + ":root":
			// An account principal covers every identity in the account.
			return caller.AccountID != ""
		}
		return false
	case "CanonicalUser":
		return caller.CanonicalID != "" && value == caller.CanonicalID
	default:
		return false
	}
}

func isPublicPrincipal(principal any) bool {
	for kind, values := range principalValues(principal) {
		if kind != "AWS" && kind != "CanonicalUser" {
			continue
		}
		for _, value := range values {
			if value == "*" {
				return true
			}
		}
	}
	return false
}
