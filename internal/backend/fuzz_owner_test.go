package backend

import "testing"

func FuzzOwnerForAccessKey(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("")
	f.Add("unknown-key")
	f.Add("minioadmin")
	f.Add("AKIA" + "X" + "XXXXXXXXXXXXXXX")

	f.Fuzz(func(t *testing.T, accessKey string) {
		_ = OwnerForAccessKey(accessKey)
	})
}

func FuzzOwnerForCanonicalID(f *testing.F) {
	f.Add("75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a")
	f.Add("")
	f.Add("unknown-id")
	f.Add("12345")

	f.Fuzz(func(t *testing.T, canonicalID string) {
		_ = OwnerForCanonicalID(canonicalID)
	})
}

func FuzzOwnerForEmail(f *testing.F) {
	f.Add("user@example.com")
	f.Add("")
	f.Add("invalid")
	f.Add("test@test.test")

	f.Fuzz(func(t *testing.T, email string) {
		_ = OwnerForEmail(email)
	})
}
