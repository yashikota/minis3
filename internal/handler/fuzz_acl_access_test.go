package handler

import (
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzEffectiveACLForResponse(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ", true)
	f.Add("http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "WRITE", true)
	f.Add("", "FULL_CONTROL", false)
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "FULL_CONTROL", false)

	f.Fuzz(func(t *testing.T, uri, perm string, ignorePublic bool) {
		acl := &backend.AccessControlPolicy{
			Owner: &backend.Owner{ID: "owner-id", DisplayName: "owner"},
			AccessControlList: backend.AccessControlList{
				Grants: []backend.Grant{
					{
						Grantee:    &backend.Grantee{Type: "Group", URI: uri},
						Permission: perm,
					},
					{
						Grantee:    &backend.Grantee{Type: "CanonicalUser", ID: "owner-id"},
						Permission: "FULL_CONTROL",
					},
				},
			},
		}
		_ = effectiveACLForResponse(acl, ignorePublic)
	})
}

func FuzzAclAllowsReadFuzz(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "READ", "user-id", false)
	f.Add(
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
		"FULL_CONTROL",
		"user-id",
		false,
	)
	f.Add("", "READ", "user-id", true)
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "WRITE", "", true)

	f.Fuzz(func(t *testing.T, uri, perm, requesterID string, isAnonymous bool) {
		acl := &backend.AccessControlPolicy{
			AccessControlList: backend.AccessControlList{
				Grants: []backend.Grant{
					{
						Grantee:    &backend.Grantee{Type: "Group", URI: uri, ID: requesterID},
						Permission: perm,
					},
				},
			},
		}
		_ = aclAllowsRead(acl, requesterID, isAnonymous)
	})
}

func FuzzAclAllowsWriteFuzz(f *testing.F) {
	f.Add("http://acs.amazonaws.com/groups/global/AllUsers", "WRITE", "user-id", false)
	f.Add(
		"http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
		"FULL_CONTROL",
		"user-id",
		false,
	)
	f.Add("", "WRITE", "", true)

	f.Fuzz(func(t *testing.T, uri, perm, requesterID string, isAnonymous bool) {
		acl := &backend.AccessControlPolicy{
			AccessControlList: backend.AccessControlList{
				Grants: []backend.Grant{
					{
						Grantee:    &backend.Grantee{Type: "Group", URI: uri, ID: requesterID},
						Permission: perm,
					},
				},
			},
		}
		_ = aclAllowsWrite(acl, requesterID, isAnonymous)
	})
}

func FuzzAclAllowsACPFuzz(f *testing.F) {
	f.Add(
		"http://acs.amazonaws.com/groups/global/AllUsers",
		"READ_ACP",
		"user-id",
		false,
		"READ_ACP",
	)
	f.Add("", "FULL_CONTROL", "owner-id", false, "WRITE_ACP")
	f.Add("", "WRITE_ACP", "", true, "WRITE_ACP")

	f.Fuzz(
		func(t *testing.T, uri, grantPerm, requesterID string, isAnonymous bool, checkPerm string) {
			acl := &backend.AccessControlPolicy{
				Owner: &backend.Owner{ID: requesterID},
				AccessControlList: backend.AccessControlList{
					Grants: []backend.Grant{
						{
							Grantee:    &backend.Grantee{Type: "Group", URI: uri, ID: requesterID},
							Permission: grantPerm,
						},
					},
				},
			}
			_ = aclAllowsACP(acl, requesterID, isAnonymous, checkPerm)
		},
	)
}

func FuzzNormalizeAndValidateACL(f *testing.F) {
	f.Add("owner-id", "owner-name", "grantee-id", "FULL_CONTROL")
	f.Add("", "", "", "")
	f.Add("invalid-id", "", "invalid-grantee", "READ")
	f.Add("owner-id", "name", "http://acs.amazonaws.com/groups/global/AllUsers", "WRITE")

	f.Fuzz(func(t *testing.T, ownerID, ownerDisplay, granteeID, perm string) {
		acl := &backend.AccessControlPolicy{
			Owner: &backend.Owner{ID: ownerID, DisplayName: ownerDisplay},
			AccessControlList: backend.AccessControlList{
				Grants: []backend.Grant{
					{
						Grantee:    &backend.Grantee{Type: "CanonicalUser", ID: granteeID},
						Permission: perm,
					},
				},
			},
		}
		_ = normalizeAndValidateACL(acl)
	})
}

func FuzzIsArchivedStorageClassHandler(f *testing.F) {
	f.Add("GLACIER")
	f.Add("DEEP_ARCHIVE")
	f.Add("STANDARD")
	f.Add("")
	f.Add("glacier")
	f.Add("REDUCED_REDUNDANCY")

	f.Fuzz(func(t *testing.T, sc string) {
		_ = isArchivedStorageClass(sc)
	})
}
