package backend

import "testing"

func FuzzAclGrantSortKey(f *testing.F) {
	f.Add("Group", "http://acs.amazonaws.com/groups/global/AllUsers", "")
	f.Add("CanonicalUser", "", "user-id")
	f.Add("", "", "")
	f.Add("Group", "", "")
	f.Add("CanonicalUser", "http://acs.amazonaws.com/groups/global/AllUsers", "id")
	f.Add("AmazonCustomerByEmail", "", "")

	f.Fuzz(func(t *testing.T, gType, uri, id string) {
		grant := Grant{
			Grantee: &Grantee{Type: gType, URI: uri, ID: id},
		}
		_ = aclGrantSortKey(grant)
	})
}

func FuzzAclGrantSortKeyNilGrantee(f *testing.F) {
	f.Add(true)
	f.Add(false)

	f.Fuzz(func(t *testing.T, nilGrantee bool) {
		var grant Grant
		if !nilGrantee {
			grant.Grantee = &Grantee{Type: "CanonicalUser", ID: "id"}
		}
		_ = aclGrantSortKey(grant)
	})
}

func FuzzNewGroupGrant(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ")
	f.Add("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "WRITE")
	f.Add("http://acs.amazonaws.com/groups/s3/LogDelivery", "WRITE_ACP")
	f.Add("", "")
	f.Add("http://custom-uri", "FULL_CONTROL")

	f.Fuzz(func(t *testing.T, uri, permission string) {
		grant := newGroupGrant(uri, permission)
		if grant.Grantee == nil {
			t.Error("grantee should not be nil")
		}
	})
}

func FuzzNewCanonicalGrant(f *testing.F) {
	f.Add("owner-id", "Owner Name", "FULL_CONTROL")
	f.Add("", "", "READ")
	f.Add("user-canonical-id", "Display", "WRITE")

	f.Fuzz(func(t *testing.T, ownerID, displayName, permission string) {
		var owner *Owner
		if ownerID != "" || displayName != "" {
			owner = &Owner{ID: ownerID, DisplayName: displayName}
		}
		grant := newCanonicalGrant(owner, permission)
		if grant.Grantee == nil {
			t.Error("grantee should not be nil")
		}
	})
}

func FuzzCannedACLToPolicy(f *testing.F) {
	f.Add("private")
	f.Add("public-read")
	f.Add("public-read-write")
	f.Add("authenticated-read")
	f.Add("bucket-owner-read")
	f.Add("bucket-owner-full-control")
	f.Add("log-delivery-write")
	f.Add("")
	f.Add("invalid-acl")
	f.Add("PRIVATE")

	f.Fuzz(func(t *testing.T, cannedACL string) {
		_ = CannedACLToPolicy(cannedACL)
	})
}

func FuzzMatchesActionBackend(f *testing.F) {
	f.Add("s3:GetObject", "s3:GetObject")
	f.Add("s3:*", "s3:PutObject")
	f.Add("*", "s3:DeleteObject")
	f.Add("s3:Get*", "s3:GetObjectAcl")
	f.Add("s3:Put*", "s3:GetObject")
	f.Add("", "s3:GetObject")
	f.Add("s3:ListBucket", "s3:listbucket")

	f.Fuzz(func(t *testing.T, action, target string) {
		actions := PolicyStringOrSlice{action}
		_ = matchesAction(actions, target)
	})
}
