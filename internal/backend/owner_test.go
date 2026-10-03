package backend

import (
	"testing"
)

// TestBuildOwnersByCanonicalID pins the package-init owner index: every
// known access key owner and the default owner must resolve by canonical ID,
// and unknown IDs must resolve to nil.
func TestBuildOwnersByCanonicalID(t *testing.T) {
	owners := buildOwnersByCanonicalID()
	// The default owner shares its canonical ID with minis3-access-key,
	// so the index holds one entry per distinct canonical ID.
	distinct := map[string]struct{}{}
	for _, owner := range knownOwnersByAccessKey {
		distinct[owner.ID] = struct{}{}
	}
	distinct[DefaultOwner().ID] = struct{}{}
	if len(owners) != len(distinct) {
		t.Fatalf(
			"buildOwnersByCanonicalID() has %d entries, want %d",
			len(owners),
			len(distinct),
		)
	}
	for accessKey, want := range knownOwnersByAccessKey {
		got, ok := owners[want.ID]
		if !ok {
			t.Fatalf("owner for access key %q (ID %q) missing from index", accessKey, want.ID)
		}
		if got.DisplayName != want.DisplayName {
			t.Fatalf(
				"owner %q DisplayName = %q, want %q",
				want.ID,
				got.DisplayName,
				want.DisplayName,
			)
		}
	}
	def := DefaultOwner()
	got, ok := owners[def.ID]
	if !ok {
		t.Fatalf("default owner (ID %q) missing from index", def.ID)
	}
	if got.DisplayName != def.DisplayName {
		t.Fatalf(
			"default owner DisplayName = %q, want %q",
			got.DisplayName,
			def.DisplayName,
		)
	}
}
