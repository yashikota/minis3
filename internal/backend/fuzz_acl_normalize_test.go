package backend

import "testing"

func FuzzNormalizeACL(f *testing.F) {
	f.Add("", "owner-id", "display-name", "Group", "http://acs.amazonaws.com/groups/global/AllUsers", "READ")
	f.Add("CanonicalUser", "user-id", "user-name", "CanonicalUser", "user-id-2", "FULL_CONTROL")
	f.Add("", "", "", "", "", "")
	f.Add("Group", "", "", "CanonicalUser", "id", "WRITE")

	f.Fuzz(func(t *testing.T, gType1, gID1, gDisplay1, gType2, gURI2, perm2 string) {
		acl := &AccessControlPolicy{
			Owner: &Owner{ID: gID1, DisplayName: gDisplay1},
			AccessControlList: AccessControlList{
				Grants: []Grant{
					{
						Grantee:    &Grantee{Type: gType1, ID: gID1, DisplayName: gDisplay1},
						Permission: "FULL_CONTROL",
					},
					{
						Grantee:    &Grantee{Type: gType2, URI: gURI2, ID: gID1},
						Permission: perm2,
					},
				},
			},
		}
		_ = normalizeACL(acl)
	})
}

func FuzzNormalizeACLNil(f *testing.F) {
	f.Add(true)
	f.Add(false)

	f.Fuzz(func(t *testing.T, isNil bool) {
		if isNil {
			_ = normalizeACL(nil)
		} else {
			_ = normalizeACL(&AccessControlPolicy{})
		}
	})
}

func FuzzIsACLPublicRead(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ")
	f.Add("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "FULL_CONTROL")
	f.Add("", "WRITE")
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "WRITE")

	f.Fuzz(func(t *testing.T, uri, perm string) {
		acl := &AccessControlPolicy{
			AccessControlList: AccessControlList{
				Grants: []Grant{
					{
						Grantee:    &Grantee{Type: "Group", URI: uri},
						Permission: perm,
					},
				},
			},
		}
		_ = IsACLPublicRead(acl)
	})
}

func FuzzIsACLPublicWrite(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "WRITE")
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "FULL_CONTROL")
	f.Add("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "WRITE")
	f.Add("", "WRITE")
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ")

	f.Fuzz(func(t *testing.T, uri, perm string) {
		acl := &AccessControlPolicy{
			AccessControlList: AccessControlList{
				Grants: []Grant{
					{
						Grantee:    &Grantee{Type: "Group", URI: uri},
						Permission: perm,
					},
				},
			},
		}
		_ = IsACLPublicWrite(acl)
	})
}

func FuzzBucketACLCompatibleWithOwnerEnforced(f *testing.F) {
	f.Add("owner-id", "FULL_CONTROL", "http://acs.amazonaws.com/groups/global/AllUsers", "READ")
	f.Add("owner-id", "FULL_CONTROL", "", "")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, ownerID, ownerPerm, groupURI, groupPerm string) {
		bucket := &Bucket{
			ACL: &AccessControlPolicy{
				Owner: &Owner{ID: ownerID},
				AccessControlList: AccessControlList{
					Grants: []Grant{
						{
							Grantee:    &Grantee{Type: "CanonicalUser", ID: ownerID},
							Permission: ownerPerm,
						},
					},
				},
			},
			OwnerAccessKey: "AKIAIOSFODNN7EXAMPLE",
		}
		if groupURI != "" {
			bucket.ACL.AccessControlList.Grants = append(bucket.ACL.AccessControlList.Grants, Grant{
				Grantee:    &Grantee{Type: "Group", URI: groupURI},
				Permission: groupPerm,
			})
		}
		_ = bucketACLCompatibleWithOwnerEnforced(bucket)
	})
}
