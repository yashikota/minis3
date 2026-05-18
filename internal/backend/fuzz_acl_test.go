package backend

import "testing"

func FuzzCannedACLToPolicyForOwner(f *testing.F) {
	f.Add("private", "owner-id", "owner-name", "bucket-owner-id", "bucket-owner-name")
	f.Add("public-read", "id", "name", "bid", "bname")
	f.Add("public-read-write", "id", "name", "bid", "bname")
	f.Add("authenticated-read", "id", "name", "bid", "bname")
	f.Add("bucket-owner-read", "id", "name", "bid", "bname")
	f.Add("bucket-owner-full-control", "id", "name", "bid", "bname")
	f.Add("log-delivery-write", "id", "name", "bid", "bname")
	f.Add("aws-exec-read", "id", "name", "bid", "bname")
	f.Add("", "id", "name", "bid", "bname")
	f.Add("unknown-acl", "id", "name", "bid", "bname")

	f.Fuzz(
		func(t *testing.T, cannedACL, ownerID, ownerName, bucketOwnerID, bucketOwnerName string) {
			owner := &Owner{ID: ownerID, DisplayName: ownerName}
			bucketOwner := &Owner{ID: bucketOwnerID, DisplayName: bucketOwnerName}
			_ = CannedACLToPolicyForOwner(cannedACL, owner, bucketOwner)
		},
	)
}
