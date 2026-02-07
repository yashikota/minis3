package backend

var knownOwnersByAccessKey = map[string]Owner{
	"minis3-access-key": {
		ID:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DisplayName: "minis3",
	},
	"minis3-alt-access-key": {
		ID:          "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234",
		DisplayName: "minis3-alt",
	},
	"tenant-access-key": {
		ID:          "tenant$abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456",
		DisplayName: "tenant$user",
	},
	"iam-access-key": {
		ID:          "iam0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DisplayName: "iam-user",
	},
	"root-access-key": {
		ID:          "root123456789abcdef",
		DisplayName: "root",
	},
	"altroot-access-key": {
		ID:          "altroot123456789ab",
		DisplayName: "altroot",
	},
}

var knownOwnersByCanonicalID = func() map[string]Owner {
	owners := make(map[string]Owner, len(knownOwnersByAccessKey)+1)
	for _, owner := range knownOwnersByAccessKey {
		owners[owner.ID] = owner
	}
	def := DefaultOwner()
	owners[def.ID] = *def
	return owners
}()

var knownOwnersByEmail = map[string]Owner{
	"minis3@example.com": {
		ID:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DisplayName: "minis3",
	},
	"alt@example.com": {
		ID:          "56789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234",
		DisplayName: "minis3-alt",
	},
	"tenant@example.com": {
		ID:          "tenant$abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456",
		DisplayName: "tenant$user",
	},
	"iam@example.com": {
		ID:          "iam0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		DisplayName: "iam-user",
	},
	"root@example.com": {
		ID:          "root123456789abcdef",
		DisplayName: "root",
	},
	"altroot@example.com": {
		ID:          "altroot123456789ab",
		DisplayName: "altroot",
	},
}

// OwnerForAccessKey returns a stable canonical owner representation for an access key.
func OwnerForAccessKey(accessKey string) *Owner {
	if owner, ok := knownOwnersByAccessKey[accessKey]; ok {
		return &Owner{
			ID:          owner.ID,
			DisplayName: owner.DisplayName,
		}
	}
	if accessKey == "" {
		return DefaultOwner()
	}
	// Fallback keeps behavior deterministic for unknown but authenticated users.
	return &Owner{
		ID:          accessKey,
		DisplayName: accessKey,
	}
}

// OwnerForCanonicalID resolves a known owner by canonical user ID.
func OwnerForCanonicalID(canonicalID string) *Owner {
	if owner, ok := knownOwnersByCanonicalID[canonicalID]; ok {
		return &Owner{
			ID:          owner.ID,
			DisplayName: owner.DisplayName,
		}
	}
	return nil
}

// OwnerForEmail resolves a known owner by email address.
func OwnerForEmail(email string) *Owner {
	if owner, ok := knownOwnersByEmail[email]; ok {
		return &Owner{
			ID:          owner.ID,
			DisplayName: owner.DisplayName,
		}
	}
	return nil
}
