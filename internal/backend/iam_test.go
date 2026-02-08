package backend

import (
	"errors"
	"strings"
	"testing"
)

func TestIAMUserCRUD(t *testing.T) {
	b := New()

	t.Run("create user", func(t *testing.T) {
		user, err := b.CreateIAMUser("alice", "/test/")
		if err != nil {
			t.Fatalf("CreateIAMUser failed: %v", err)
		}
		if user.UserName != "alice" {
			t.Fatalf("UserName = %q, want alice", user.UserName)
		}
		if user.Path != "/test/" {
			t.Fatalf("Path = %q, want /test/", user.Path)
		}
		if !strings.HasPrefix(user.UserID, "AID") {
			t.Fatalf("UserID should start with AID, got %q", user.UserID)
		}
		if !strings.Contains(user.Arn, "alice") {
			t.Fatalf("Arn should contain alice, got %q", user.Arn)
		}
	})

	t.Run("create duplicate user", func(t *testing.T) {
		_, err := b.CreateIAMUser("alice", "/test/")
		if !errors.Is(err, ErrIAMUserAlreadyExists) {
			t.Fatalf("expected ErrIAMUserAlreadyExists, got %v", err)
		}
	})

	t.Run("list users", func(t *testing.T) {
		_, _ = b.CreateIAMUser("bob", "/other/")
		users := b.ListIAMUsers("")
		if len(users) != 2 {
			t.Fatalf("expected 2 users, got %d", len(users))
		}

		users = b.ListIAMUsers("/test/")
		if len(users) != 1 || users[0].UserName != "alice" {
			t.Fatalf("expected 1 user alice with /test/ prefix, got %v", users)
		}
	})

	t.Run("delete user", func(t *testing.T) {
		err := b.DeleteIAMUser("alice")
		if err != nil {
			t.Fatalf("DeleteIAMUser failed: %v", err)
		}

		users := b.ListIAMUsers("")
		if len(users) != 1 {
			t.Fatalf("expected 1 user after delete, got %d", len(users))
		}
	})

	t.Run("delete nonexistent user", func(t *testing.T) {
		err := b.DeleteIAMUser("nonexistent")
		if !errors.Is(err, ErrIAMUserNotFound) {
			t.Fatalf("expected ErrIAMUserNotFound, got %v", err)
		}
	})
}

func TestIAMAccessKeyCRUD(t *testing.T) {
	b := New()
	_, _ = b.CreateIAMUser("testuser", "/")

	t.Run("create access key", func(t *testing.T) {
		key, err := b.CreateIAMAccessKey("testuser")
		if err != nil {
			t.Fatalf("CreateIAMAccessKey failed: %v", err)
		}
		if key.UserName != "testuser" {
			t.Fatalf("UserName = %q, want testuser", key.UserName)
		}
		if !strings.HasPrefix(key.AccessKeyId, "AKIA") {
			t.Fatalf("AccessKeyId should start with AKIA, got %q", key.AccessKeyId)
		}
		if key.SecretAccessKey == "" {
			t.Fatal("SecretAccessKey should not be empty")
		}
		if key.Status != "Active" {
			t.Fatalf("Status = %q, want Active", key.Status)
		}
	})

	t.Run("create access key for nonexistent user", func(t *testing.T) {
		_, err := b.CreateIAMAccessKey("nonexistent")
		if !errors.Is(err, ErrIAMUserNotFound) {
			t.Fatalf("expected ErrIAMUserNotFound, got %v", err)
		}
	})

	t.Run("list access keys", func(t *testing.T) {
		keys := b.ListIAMAccessKeys("testuser")
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
	})

	t.Run("lookup credential", func(t *testing.T) {
		keys := b.ListIAMAccessKeys("testuser")
		secret, ok := b.LookupCredential(keys[0].AccessKeyId)
		if !ok {
			t.Fatal("LookupCredential should find dynamic key")
		}
		if secret != keys[0].SecretAccessKey {
			t.Fatalf("secret mismatch")
		}

		_, ok = b.LookupCredential("nonexistent-key")
		if ok {
			t.Fatal("LookupCredential should not find nonexistent key")
		}
	})

	t.Run("delete access key", func(t *testing.T) {
		keys := b.ListIAMAccessKeys("testuser")
		err := b.DeleteIAMAccessKey("testuser", keys[0].AccessKeyId)
		if err != nil {
			t.Fatalf("DeleteIAMAccessKey failed: %v", err)
		}

		keys = b.ListIAMAccessKeys("testuser")
		if len(keys) != 0 {
			t.Fatalf("expected 0 keys after delete, got %d", len(keys))
		}
	})

	t.Run("delete nonexistent access key", func(t *testing.T) {
		err := b.DeleteIAMAccessKey("testuser", "AKIANOTEXIST")
		if !errors.Is(err, ErrIAMAccessKeyNotFound) {
			t.Fatalf("expected ErrIAMAccessKeyNotFound, got %v", err)
		}
	})

	t.Run("delete user cleans up keys", func(t *testing.T) {
		_, _ = b.CreateIAMAccessKey("testuser")
		_, _ = b.CreateIAMAccessKey("testuser")
		keys := b.ListIAMAccessKeys("testuser")
		if len(keys) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(keys))
		}

		_ = b.DeleteIAMUser("testuser")

		// Keys should no longer be lookup-able
		for _, k := range keys {
			if _, ok := b.LookupCredential(k.AccessKeyId); ok {
				t.Fatalf("key %q should have been cleaned up", k.AccessKeyId)
			}
		}
	})
}

func TestPutBucketPolicyDenySelfAccess(t *testing.T) {
	b := New()
	_ = b.CreateBucket("test-bucket")

	policy := `{"Version":"2012-10-17","Statement":[]}`

	t.Run("default denySelfAccess is false", func(t *testing.T) {
		_ = b.PutBucketPolicy("test-bucket", policy, false)
		bucket, _ := b.GetBucket("test-bucket")
		if bucket.PolicyDenySelfAccess {
			t.Fatal("PolicyDenySelfAccess should be false")
		}
	})

	t.Run("denySelfAccess set to true", func(t *testing.T) {
		_ = b.PutBucketPolicy("test-bucket", policy, true)
		bucket, _ := b.GetBucket("test-bucket")
		if !bucket.PolicyDenySelfAccess {
			t.Fatal("PolicyDenySelfAccess should be true")
		}
	})

	t.Run("delete policy resets denySelfAccess", func(t *testing.T) {
		_ = b.PutBucketPolicy("test-bucket", policy, true)
		_ = b.DeleteBucketPolicy("test-bucket")
		bucket, _ := b.GetBucket("test-bucket")
		if bucket.PolicyDenySelfAccess {
			t.Fatal("PolicyDenySelfAccess should be false after delete")
		}
	})
}
