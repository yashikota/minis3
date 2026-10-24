package handler

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

// authzRequest mirrors a request record of formal/tla/S3Authorization.tla.
type authzRequest struct {
	caller, kind, policy, grant string
	publicPolicy                bool
	ignorePublicAcls            bool
	enforced                    bool
	restrictPublic              bool
	denySelf                    bool
}

// authzModelRequests enumerates Valid from S3Authorization.tla.
func authzModelRequests() []authzRequest {
	bools := []bool{false, true}
	var out []authzRequest
	for _, caller := range []string{"owner", "other", "anon"} {
		for _, kind := range []string{"bucketAcl", "bucketConfig", "policyMgmt", "object", "objectAcp"} {
			for _, policy := range []string{"none", "allow", "deny", "allowCondFail"} {
				for _, grant := range []string{"none", "direct", "public"} {
					for _, publicPolicy := range bools {
						for _, ignore := range bools {
							for _, enforced := range bools {
								for _, restrict := range bools {
									for _, denySelf := range bools {
										r := authzRequest{
											caller, kind, policy, grant,
											publicPolicy, ignore, enforced, restrict, denySelf,
										}
										if r.consistent() {
											out = append(out, r)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

func (r authzRequest) consistent() bool {
	if r.caller == "anon" && (r.policy == "allow" || r.policy == "allowCondFail") &&
		!r.publicPolicy {
		return false
	}
	return r.caller != "anon" || r.grant != "direct"
}

func (r authzRequest) ownerExempt() bool {
	return r.caller == "owner" && r.kind == "policyMgmt" && !r.denySelf
}

// decide transcribes Decide from S3Authorization.tla.
func (r authzRequest) decide() bool {
	switch {
	case r.policy == "deny" && !r.ownerExempt():
		return false
	case r.restrictPublic && r.publicPolicy && r.caller != "owner":
		return false
	case r.policy == "allow":
		return true
	case r.caller == "owner" && r.kind != "objectAcp":
		return true
	case r.policy == "allowCondFail", r.enforced:
		return false
	case r.kind != "bucketAcl" && r.kind != "object" && r.kind != "objectAcp":
		return false
	default:
		return r.grant == "direct" || (r.grant == "public" && !r.ignorePublicAcls)
	}
}

const authzModelBucket = "authz-model"

// authzModelKinds maps each kind to a request and the permission an ACL
// grant for it carries.
var authzModelKinds = map[string]struct {
	method, target, permission string
	objectACL                  bool
}{
	"bucketAcl":    {http.MethodGet, "/", backend.PermissionRead, false},
	"bucketConfig": {http.MethodPut, "/?tagging", backend.PermissionFullControl, false},
	"policyMgmt":   {http.MethodGet, "/?policy", backend.PermissionFullControl, false},
	"object":       {http.MethodGet, "/obj", backend.PermissionRead, true},
	"objectAcp":    {http.MethodGet, "/obj?acl", backend.PermissionReadACP, true},
}

var authzModelCallers = map[string]string{
	"owner": authzOwnerKey,
	"other": authzAltKey,
	"anon":  "",
}

func authzModelPrincipal(caller string) string {
	if caller == "anon" {
		return `"*"`
	}
	return `{"AWS":"` + authzModelCallers[caller] + `"}`
}

// setup builds a bucket whose policy, ACLs and settings realise r.
func (r authzRequest) setup(t *testing.T) *Handler {
	t.Helper()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, authzModelBucket)
	b.SetBucketOwner(authzModelBucket, authzOwnerKey)
	mustPutObject(t, b, authzModelBucket, "obj", "data")

	kind := authzModelKinds[r.kind]
	owner := backend.OwnerForAccessKey(authzOwnerKey)
	// The object belongs to a third party, so only its ACL grants access
	// to it, even for the bucket owner (GetObjectAcl).
	third := &backend.Owner{ID: strings.Repeat("3", 64), DisplayName: "third"}
	bucketACL := &backend.AccessControlPolicy{Owner: owner}
	bucketACL.AccessControlList.Grants = []backend.Grant{
		authzCanonicalGrant(owner, backend.PermissionFullControl),
	}
	objectACL := &backend.AccessControlPolicy{Owner: third}
	objectACL.AccessControlList.Grants = []backend.Grant{
		authzCanonicalGrant(third, backend.PermissionFullControl),
	}
	var grant *backend.Grant
	switch r.grant {
	case "direct":
		g := authzCanonicalGrant(
			backend.OwnerForAccessKey(authzModelCallers[r.caller]),
			kind.permission,
		)
		grant = &g
	case "public":
		grant = &backend.Grant{
			Grantee: &backend.Grantee{
				Xmlns: backend.XMLSchemaInstanceNS,
				Type:  "Group",
				URI:   backend.AllUsersURI,
			},
			Permission: kind.permission,
		}
	}
	if grant != nil {
		if kind.objectACL {
			objectACL.AccessControlList.Grants = append(objectACL.AccessControlList.Grants, *grant)
		} else {
			bucketACL.AccessControlList.Grants = append(bucketACL.AccessControlList.Grants, *grant)
		}
	}
	if err := b.PutBucketACL(authzModelBucket, bucketACL); err != nil {
		t.Fatalf("PutBucketACL: %v", err)
	}
	if err := b.PutObjectACL(authzModelBucket, "obj", "", objectACL); err != nil {
		t.Fatalf("PutObjectACL: %v", err)
	}

	action := r.action()
	resource := fmt.Sprintf(
		`["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]`,
		authzModelBucket,
		authzModelBucket,
	)
	var statements []string
	stmt := func(effect, principal, action, condition string) string {
		return fmt.Sprintf(`{"Effect":%q,"Principal":%s,"Action":%q,"Resource":%s%s}`,
			effect, principal, action, resource, condition)
	}
	principal := authzModelPrincipal(r.caller)
	switch r.policy {
	case "allow":
		statements = append(statements, stmt("Allow", principal, action, ""))
	case "deny":
		statements = append(statements, stmt("Deny", principal, action, ""))
	case "allowCondFail":
		// Test requests are plain HTTP, so this condition never holds.
		statements = append(statements, stmt("Allow", principal, action,
			`,"Condition":{"Bool":{"aws:SecureTransport":"true"}}`))
	}
	if r.publicPolicy {
		// Public, but for an action no request here uses.
		statements = append(statements, stmt("Allow", `"*"`, "s3:GetObjectTorrent", ""))
	}
	if len(statements) > 0 {
		policy := `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
		if err := b.PutBucketPolicy(authzModelBucket, policy, r.denySelf); err != nil {
			t.Fatalf("PutBucketPolicy(%s): %v", policy, err)
		}
	}
	if got := backend.IsPolicyPublic(mustGetBucketPolicy(t, b)); got != r.publicPolicy {
		t.Fatalf("policy public = %v, want %v", got, r.publicPolicy)
	}

	if r.enforced {
		enforce := func() error {
			return b.PutBucketOwnershipControls(authzModelBucket, &backend.OwnershipControls{
				Rules: []backend.OwnershipControlsRule{
					{ObjectOwnership: backend.ObjectOwnershipBucketOwnerEnforced},
				},
			})
		}
		err := enforce()
		if err != nil && grant != nil && !kind.objectACL {
			// S3 refuses BucketOwnerEnforced while the bucket ACL grants
			// anyone but the owner. The model's EnforcedIgnoresAcls shows
			// the grant cannot matter, so drop it and enforce.
			ownerOnly := &backend.AccessControlPolicy{Owner: owner}
			ownerOnly.AccessControlList.Grants = []backend.Grant{
				authzCanonicalGrant(owner, backend.PermissionFullControl),
			}
			if err := b.PutBucketACL(authzModelBucket, ownerOnly); err != nil {
				t.Fatalf("PutBucketACL: %v", err)
			}
			err = enforce()
		}
		if err != nil {
			t.Fatalf("PutBucketOwnershipControls %+v: %v", r, err)
		}
	}
	if r.ignorePublicAcls || r.restrictPublic {
		if err := b.PutPublicAccessBlock(authzModelBucket, &backend.PublicAccessBlockConfiguration{
			IgnorePublicAcls:      r.ignorePublicAcls,
			RestrictPublicBuckets: r.restrictPublic,
		}); err != nil {
			t.Fatalf("PutPublicAccessBlock: %v", err)
		}
	}
	return h
}

func (r authzRequest) action() string {
	return map[string]string{
		"bucketAcl":    "s3:ListBucket",
		"bucketConfig": "s3:PutBucketTagging",
		"policyMgmt":   "s3:GetBucketPolicy",
		"object":       "s3:GetObject",
		"objectAcp":    "s3:GetObjectAcl",
	}[r.kind]
}

func authzCanonicalGrant(owner *backend.Owner, permission string) backend.Grant {
	return backend.Grant{
		Grantee: &backend.Grantee{
			Xmlns:       backend.XMLSchemaInstanceNS,
			Type:        "CanonicalUser",
			ID:          owner.ID,
			DisplayName: owner.DisplayName,
		},
		Permission: permission,
	}
}

func mustGetBucketPolicy(t *testing.T, b *backend.Backend) string {
	t.Helper()
	bucket, ok := b.GetBucket(authzModelBucket)
	if !ok {
		t.Fatal("bucket missing")
	}
	return bucket.Policy
}

// TestAuthorizationModel checks the router's authorization of real
// requests against Decide of S3Authorization.tla for every request shape
// the model enumerates.
func TestAuthorizationModel(t *testing.T) {
	t.Parallel()
	requests := authzModelRequests()
	if len(requests) != 4800 {
		t.Fatalf("enumerated %d requests, the model has 4800", len(requests))
	}
	for _, r := range requests {
		h := r.setup(t)
		kind := authzModelKinds[r.kind]
		req := newRequest(kind.method, "http://example.test/"+authzModelBucket+kind.target, "", nil)
		if key := authzModelCallers[r.caller]; key != "" {
			req.Header.Set("Authorization", authHeader(key))
		}
		_, key := extractBucketAndKey(req.URL.Path)
		op := resolveS3Operation(req, key)
		if op.action(req.URL.Query()) != r.action() {
			t.Fatalf(
				"%s resolves to %s, want %s",
				kind.target,
				op.action(req.URL.Query()),
				r.action(),
			)
		}
		if got, want := h.authorizeOperation(
			req,
			authzModelBucket,
			key,
			op,
		), r.decide(); got != want {
			t.Fatalf("%+v: authorized = %v, model Decide = %v", r, got, want)
		}
	}
}
