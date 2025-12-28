package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/yashikota/minis3"
)

// setupTestClient creates a minis3 server and returns an S3 client configured to use it.
// The server is automatically closed when the test completes.
func setupTestClient(t *testing.T) *s3.Client {
	t.Helper()

	server := minis3.New()
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
			}),
		),
	)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + server.Addr())
		o.UsePathStyle = true
	})
}

func TestIntegrationWithSDK(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "integration-test-bucket"
	key := "test.txt"
	content := "integration test content"

	// 1. Create Bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// 2. Put Object
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 3. Get Object
	resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	// Verify content? Reader... skipped for brevity, status check implies success usually
	// But let's check content length or type if we set it.
	if resp.ContentLength == nil || *resp.ContentLength != int64(len(content)) {
		t.Errorf("Expected content length %d, got %v", len(content), resp.ContentLength)
	}

	// 4. Delete Object
	_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	// 5. Delete Bucket
	_, err = client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}
}

func TestCopyObject(t *testing.T) {
	client := setupTestClient(t)

	srcBucket := "src-bucket"
	dstBucket := "dst-bucket"
	srcKey := "source.txt"
	dstKey := "destination.txt"
	sameKey := "same-bucket-copy.txt"
	content := "copy object test content"

	// Register cleanup to run even if test fails
	t.Cleanup(func() {
		client.DeleteObject(
			context.TODO(),
			&s3.DeleteObjectInput{Bucket: aws.String(srcBucket), Key: aws.String(srcKey)},
		)
		client.DeleteObject(
			context.TODO(),
			&s3.DeleteObjectInput{Bucket: aws.String(srcBucket), Key: aws.String(sameKey)},
		)
		client.DeleteObject(
			context.TODO(),
			&s3.DeleteObjectInput{Bucket: aws.String(dstBucket), Key: aws.String(dstKey)},
		)
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{Bucket: aws.String(srcBucket)})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{Bucket: aws.String(dstBucket)})
	})

	// 1. Create source and destination buckets
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(srcBucket),
	})
	if err != nil {
		t.Fatalf("CreateBucket (src) failed: %v", err)
	}

	_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(dstBucket),
	})
	if err != nil {
		t.Fatalf("CreateBucket (dst) failed: %v", err)
	}

	// 2. Put source object
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(srcBucket),
		Key:    aws.String(srcKey),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 3. Copy object to another bucket
	_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(srcBucket + "/" + srcKey),
	})
	if err != nil {
		t.Fatalf("CopyObject failed: %v", err)
	}

	// 4. Verify copied object exists and has correct content
	resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(dstBucket),
		Key:    aws.String(dstKey),
	})
	if err != nil {
		t.Fatalf("GetObject (copied) failed: %v", err)
	}

	if resp.ContentLength == nil || *resp.ContentLength != int64(len(content)) {
		t.Errorf("Expected content length %d, got %v", len(content), resp.ContentLength)
	}

	// 5. Test copy within same bucket
	_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:     aws.String(srcBucket),
		Key:        aws.String(sameKey),
		CopySource: aws.String(srcBucket + "/" + srcKey),
	})
	if err != nil {
		t.Fatalf("CopyObject (same bucket) failed: %v", err)
	}

	// 6. Verify same-bucket copy
	resp, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(srcBucket),
		Key:    aws.String(sameKey),
	})
	if err != nil {
		t.Fatalf("GetObject (same bucket copy) failed: %v", err)
	}

	if resp.ContentLength == nil || *resp.ContentLength != int64(len(content)) {
		t.Errorf("Expected content length %d, got %v", len(content), resp.ContentLength)
	}
}

func TestDeleteObjects(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "delete-objects-test"
	keys := []string{"file1.txt", "file2.txt", "file3.txt"}
	content := "test content"

	// Cleanup
	t.Cleanup(func() {
		for _, key := range keys {
			client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(key),
			})
		}
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// 1. Create Bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// 2. Put Objects
	for _, key := range keys {
		_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   strings.NewReader(content),
		})
		if err != nil {
			t.Fatalf("PutObject failed for %s: %v", key, err)
		}
	}

	// 3. Delete multiple objects (file1.txt, file2.txt)
	deleteInput := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: aws.String("file1.txt")},
				{Key: aws.String("file2.txt")},
				{Key: aws.String("nonexistent.txt")}, // Should succeed even if not exists
			},
		},
	}

	deleteResp, err := client.DeleteObjects(context.TODO(), deleteInput)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}

	// 4. Verify response
	if len(deleteResp.Deleted) != 3 {
		t.Errorf("Expected 3 deleted objects, got %d", len(deleteResp.Deleted))
	}

	// 5. Verify file1.txt and file2.txt are deleted
	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("file1.txt"),
	})
	if err == nil {
		t.Error("Expected file1.txt to be deleted, but GetObject succeeded")
	}

	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("file2.txt"),
	})
	if err == nil {
		t.Error("Expected file2.txt to be deleted, but GetObject succeeded")
	}

	// 6. Verify file3.txt still exists
	getResp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("file3.txt"),
	})
	if err != nil {
		t.Fatalf("GetObject for file3.txt failed: %v", err)
	}
	if getResp.ContentLength == nil || *getResp.ContentLength != int64(len(content)) {
		t.Errorf(
			"Expected file3.txt content length %d, got %v",
			len(content),
			getResp.ContentLength,
		)
	}
}

func TestDeleteObjectsQuietMode(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "delete-objects-quiet-test"

	// Cleanup
	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String("file.txt"),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// 1. Create Bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// 2. Put Object
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("file.txt"),
		Body:   strings.NewReader("content"),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	// 3. Delete with quiet mode
	deleteInput := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: aws.String("file.txt")},
			},
			Quiet: aws.Bool(true),
		},
	}

	deleteResp, err := client.DeleteObjects(context.TODO(), deleteInput)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}

	// In quiet mode, successful deletions should not be returned
	if len(deleteResp.Deleted) != 0 {
		t.Errorf("Expected 0 deleted objects in quiet mode, got %d", len(deleteResp.Deleted))
	}

	// Verify file is actually deleted
	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("file.txt"),
	})
	if err == nil {
		t.Error("Expected file.txt to be deleted, but GetObject succeeded")
	}
}

func TestListObjectsV2(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "list-objects-v2-test"

	// Cleanup
	t.Cleanup(func() {
		// Delete all test objects
		keys := []string{
			"file1.txt",
			"file2.txt",
			"photos/2024/jan/a.jpg",
			"photos/2024/jan/b.jpg",
			"photos/2024/feb/c.jpg",
			"docs/readme.md",
		}
		for _, key := range keys {
			client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(key),
			})
		}
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// 1. Create Bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// 2. Put test objects
	testObjects := map[string]string{
		"file1.txt":             "content1",
		"file2.txt":             "content2",
		"photos/2024/jan/a.jpg": "photo-a",
		"photos/2024/jan/b.jpg": "photo-b",
		"photos/2024/feb/c.jpg": "photo-c",
		"docs/readme.md":        "readme",
	}

	for key, content := range testObjects {
		_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   strings.NewReader(content),
		})
		if err != nil {
			t.Fatalf("PutObject failed for %s: %v", key, err)
		}
	}

	// 3. Test: List all objects (no prefix, no delimiter)
	t.Run("ListAll", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		if *resp.KeyCount != 6 {
			t.Errorf("Expected 6 objects, got %d", *resp.KeyCount)
		}
		if resp.IsTruncated == nil || *resp.IsTruncated {
			t.Error("Expected IsTruncated to be false")
		}
	})

	// 4. Test: List with prefix
	t.Run("ListWithPrefix", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
			Prefix: aws.String("photos/"),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		if *resp.KeyCount != 3 {
			t.Errorf("Expected 3 objects with prefix 'photos/', got %d", *resp.KeyCount)
		}
	})

	// 5. Test: List with delimiter (simulate directories)
	t.Run("ListWithDelimiter", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket:    aws.String(bucketName),
			Delimiter: aws.String("/"),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		// Should have 2 files (file1.txt, file2.txt) and 2 common prefixes (photos/, docs/)
		if len(resp.Contents) != 2 {
			t.Errorf("Expected 2 objects, got %d", len(resp.Contents))
		}
		if len(resp.CommonPrefixes) != 2 {
			t.Errorf("Expected 2 common prefixes, got %d", len(resp.CommonPrefixes))
		}
	})

	// 6. Test: List with prefix and delimiter
	t.Run("ListWithPrefixAndDelimiter", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket:    aws.String(bucketName),
			Prefix:    aws.String("photos/2024/"),
			Delimiter: aws.String("/"),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		// Should have 0 direct objects and 2 common prefixes (jan/, feb/)
		if len(resp.Contents) != 0 {
			t.Errorf("Expected 0 objects, got %d", len(resp.Contents))
		}
		if len(resp.CommonPrefixes) != 2 {
			t.Errorf("Expected 2 common prefixes (jan/, feb/), got %d", len(resp.CommonPrefixes))
		}
	})

	// 7. Test: List with max-keys
	t.Run("ListWithMaxKeys", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket:  aws.String(bucketName),
			MaxKeys: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		if *resp.KeyCount != 2 {
			t.Errorf("Expected 2 objects with max-keys=2, got %d", *resp.KeyCount)
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			t.Error("Expected IsTruncated to be true")
		}
	})

	// 8. Test: Empty bucket (after prefix filter)
	t.Run("ListNonExistentPrefix", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket: aws.String(bucketName),
			Prefix: aws.String("nonexistent/"),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		if *resp.KeyCount != 0 {
			t.Errorf("Expected 0 objects for nonexistent prefix, got %d", *resp.KeyCount)
		}
	})

	// 9. Test: max-keys=0 should return 0 objects
	t.Run("ListWithMaxKeysZero", func(t *testing.T) {
		resp, err := client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
			Bucket:  aws.String(bucketName),
			MaxKeys: aws.Int32(0),
		})
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}

		if *resp.KeyCount != 0 {
			t.Errorf("Expected 0 objects with max-keys=0, got %d", *resp.KeyCount)
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			t.Error("Expected IsTruncated to be true with max-keys=0")
		}
	})
}

func TestBucketOperations(t *testing.T) {
	client := setupTestClient(t)

	// 1. Test: Create bucket
	t.Run("CreateBucket", func(t *testing.T) {
		bucketName := "test-create-bucket"
		t.Cleanup(func() {
			client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
				Bucket: aws.String(bucketName),
			})
		})

		_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}
	})

	// 2. Test: Create duplicate bucket returns BucketAlreadyOwnedByYou
	t.Run("CreateDuplicateBucket", func(t *testing.T) {
		bucketName := "test-duplicate-bucket"
		t.Cleanup(func() {
			client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
				Bucket: aws.String(bucketName),
			})
		})

		// Create first time
		_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("First CreateBucket failed: %v", err)
		}

		// Create second time - should get BucketAlreadyOwnedByYou error
		_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil {
			t.Fatal("Expected error when creating duplicate bucket")
		}
		// Check error type using SDK typed error
		var baoby *types.BucketAlreadyOwnedByYou
		if !errors.As(err, &baoby) {
			t.Errorf("Expected BucketAlreadyOwnedByYou error, got: %v", err)
		}
	})

	// 3. Test: HeadBucket returns correct headers
	t.Run("HeadBucket", func(t *testing.T) {
		bucketName := "test-head-bucket"
		t.Cleanup(func() {
			client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
				Bucket: aws.String(bucketName),
			})
		})

		_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		resp, err := client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("HeadBucket failed: %v", err)
		}

		// Check BucketRegion is returned
		if resp.BucketRegion == nil || *resp.BucketRegion != "us-east-1" {
			t.Errorf("Expected BucketRegion us-east-1, got %v", resp.BucketRegion)
		}

		// AccessPointAlias should be false for regular buckets
		if resp.AccessPointAlias == nil || *resp.AccessPointAlias {
			t.Errorf("Expected AccessPointAlias false, got %v", resp.AccessPointAlias)
		}
	})

	// 4. Test: HeadBucket for non-existent bucket
	t.Run("HeadNonExistentBucket", func(t *testing.T) {
		_, err := client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
			Bucket: aws.String("non-existent-bucket"),
		})
		if err == nil {
			t.Fatal("Expected error for non-existent bucket")
		}
	})

	// 5. Test: DeleteBucket non-empty
	t.Run("DeleteNonEmptyBucket", func(t *testing.T) {
		bucketName := "test-delete-nonempty"
		objectKey := "test.txt"
		t.Cleanup(func() {
			client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(objectKey),
			})
			client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
				Bucket: aws.String(bucketName),
			})
		})

		_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("CreateBucket failed: %v", err)
		}

		_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
			Body:   strings.NewReader("content"),
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}

		// Try to delete non-empty bucket
		_, err = client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil {
			t.Fatal("Expected error when deleting non-empty bucket")
		}
		// Check error type using smithy.APIError
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "BucketNotEmpty" {
			t.Errorf("Expected BucketNotEmpty error, got: %v", err)
		}
	})

	// 6. Test: ListBuckets with pagination
	t.Run("ListBucketsWithPagination", func(t *testing.T) {
		buckets := []string{"page-aa", "page-ab", "page-ba", "page-bb", "page-ca"}
		t.Cleanup(func() {
			for _, name := range buckets {
				client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
					Bucket: aws.String(name),
				})
			}
		})

		for _, name := range buckets {
			_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
				Bucket: aws.String(name),
			})
			if err != nil {
				t.Fatalf("CreateBucket failed for %s: %v", name, err)
			}
		}

		// First page: get first 2 buckets with prefix "page-"
		resp1, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{
			Prefix:     aws.String("page-"),
			MaxBuckets: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("ListBuckets (page 1) failed: %v", err)
		}

		if len(resp1.Buckets) != 2 {
			t.Errorf("Expected 2 buckets in first page, got %d", len(resp1.Buckets))
		}

		// Verify first page is truncated
		if resp1.ContinuationToken == nil || *resp1.ContinuationToken == "" {
			t.Error("Expected ContinuationToken for truncated response")
		}

		// Second page: use continuation token
		resp2, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{
			Prefix:            aws.String("page-"),
			MaxBuckets:        aws.Int32(2),
			ContinuationToken: resp1.ContinuationToken,
		})
		if err != nil {
			t.Fatalf("ListBuckets (page 2) failed: %v", err)
		}

		if len(resp2.Buckets) != 2 {
			t.Errorf("Expected 2 buckets in second page, got %d", len(resp2.Buckets))
		}

		// Verify no overlap between pages
		if len(resp1.Buckets) > 0 && len(resp2.Buckets) > 0 {
			if *resp1.Buckets[len(resp1.Buckets)-1].Name >= *resp2.Buckets[0].Name {
				t.Error("Expected second page buckets to come after first page")
			}
		}

		// Third page: get remaining bucket
		resp3, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{
			Prefix:            aws.String("page-"),
			MaxBuckets:        aws.Int32(2),
			ContinuationToken: resp2.ContinuationToken,
		})
		if err != nil {
			t.Fatalf("ListBuckets (page 3) failed: %v", err)
		}

		if len(resp3.Buckets) != 1 {
			t.Errorf("Expected 1 bucket in third page, got %d", len(resp3.Buckets))
		}

		// Total should be 5
		total := len(resp1.Buckets) + len(resp2.Buckets) + len(resp3.Buckets)
		if total != 5 {
			t.Errorf("Expected 5 total buckets across all pages, got %d", total)
		}

		// Verify owner is set
		if resp1.Owner == nil || resp1.Owner.ID == nil {
			t.Error("Expected Owner with ID")
		}
	})

	// 7. Test: CreateBucket with LocationConstraint
	t.Run("CreateBucketWithLocationConstraint", func(t *testing.T) {
		bucketName := "test-location-constraint"
		t.Cleanup(func() {
			client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
				Bucket: aws.String(bucketName),
			})
		})

		// Create bucket with LocationConstraint (should be accepted but ignored in mock)
		_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
			CreateBucketConfiguration: &types.CreateBucketConfiguration{
				LocationConstraint: types.BucketLocationConstraintApNortheast1,
			},
		})
		if err != nil {
			t.Fatalf("CreateBucket with LocationConstraint failed: %v", err)
		}

		// Verify bucket was created
		_, err = client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("HeadBucket failed: %v", err)
		}
	})

	// 8. Test: ListBuckets with prefix filter
	t.Run("ListBucketsWithPrefix", func(t *testing.T) {
		buckets := []string{"prefix-test-a", "prefix-test-b", "other-bucket"}
		t.Cleanup(func() {
			for _, name := range buckets {
				client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
					Bucket: aws.String(name),
				})
			}
		})

		for _, name := range buckets {
			_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
				Bucket: aws.String(name),
			})
			if err != nil {
				t.Fatalf("CreateBucket failed for %s: %v", name, err)
			}
		}

		// List with prefix filter using Prefix field
		resp, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{
			Prefix: aws.String("prefix-test"),
		})
		if err != nil {
			t.Fatalf("ListBuckets with prefix failed: %v", err)
		}

		// Should have exactly 2 buckets with prefix "prefix-test"
		if len(resp.Buckets) != 2 {
			t.Errorf("Expected 2 buckets with prefix 'prefix-test', got %d", len(resp.Buckets))
		}

		// Verify all returned buckets have the correct prefix
		for _, b := range resp.Buckets {
			if !strings.HasPrefix(*b.Name, "prefix-test") {
				t.Errorf("Expected bucket name to start with 'prefix-test', got %s", *b.Name)
			}
		}
	})
}

func TestListObjectsV1(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "list-objects-v1-test"

	// Define test objects first to derive cleanup keys from the map
	testObjects := map[string]string{
		"file1.txt":             "content1",
		"file2.txt":             "content2",
		"photos/2024/jan/a.jpg": "photo-a",
		"photos/2024/jan/b.jpg": "photo-b",
		"photos/2024/feb/c.jpg": "photo-c",
		"docs/readme.md":        "readme",
	}

	// Cleanup
	t.Cleanup(func() {
		for key := range testObjects {
			client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(key),
			})
		}
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// 1. Create Bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// 2. Put test objects

	for key, content := range testObjects {
		_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   strings.NewReader(content),
		})
		if err != nil {
			t.Fatalf("PutObject failed for %s: %v", key, err)
		}
	}

	// 3. Test: List all objects (no prefix, no delimiter)
	t.Run("ListAll", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		if len(resp.Contents) != 6 {
			t.Errorf("Expected 6 objects, got %d", len(resp.Contents))
		}
		if resp.IsTruncated == nil || *resp.IsTruncated {
			t.Error("Expected IsTruncated to be false")
		}
	})

	// 4. Test: List with prefix
	t.Run("ListWithPrefix", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket: aws.String(bucketName),
			Prefix: aws.String("photos/"),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		if len(resp.Contents) != 3 {
			t.Errorf("Expected 3 objects with prefix 'photos/', got %d", len(resp.Contents))
		}
	})

	// 5. Test: List with delimiter (simulate directories)
	t.Run("ListWithDelimiter", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket:    aws.String(bucketName),
			Delimiter: aws.String("/"),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		// Should have 2 files (file1.txt, file2.txt) and 2 common prefixes (photos/, docs/)
		if len(resp.Contents) != 2 {
			t.Errorf("Expected 2 objects, got %d", len(resp.Contents))
		}
		if len(resp.CommonPrefixes) != 2 {
			t.Errorf("Expected 2 common prefixes, got %d", len(resp.CommonPrefixes))
		}
	})

	// 6. Test: List with prefix and delimiter
	t.Run("ListWithPrefixAndDelimiter", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket:    aws.String(bucketName),
			Prefix:    aws.String("photos/2024/"),
			Delimiter: aws.String("/"),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		// Should have 0 direct objects and 2 common prefixes (jan/, feb/)
		if len(resp.Contents) != 0 {
			t.Errorf("Expected 0 objects, got %d", len(resp.Contents))
		}
		if len(resp.CommonPrefixes) != 2 {
			t.Errorf("Expected 2 common prefixes (jan/, feb/), got %d", len(resp.CommonPrefixes))
		}
	})

	// 7. Test: List with max-keys
	t.Run("ListWithMaxKeys", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket:  aws.String(bucketName),
			MaxKeys: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		if len(resp.Contents) != 2 {
			t.Errorf("Expected 2 objects with max-keys=2, got %d", len(resp.Contents))
		}
		if resp.IsTruncated == nil || !*resp.IsTruncated {
			t.Error("Expected IsTruncated to be true")
		}
	})

	// 8. Test: List with marker (pagination)
	t.Run("ListWithMarker", func(t *testing.T) {
		// First, get the first 2 keys
		resp1, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket:  aws.String(bucketName),
			MaxKeys: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		if len(resp1.Contents) != 2 {
			t.Fatalf("Expected 2 objects, got %d", len(resp1.Contents))
		}

		// Use the last key as marker to get the next page
		lastKey := *resp1.Contents[1].Key
		resp2, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket:  aws.String(bucketName),
			Marker:  aws.String(lastKey),
			MaxKeys: aws.Int32(2),
		})
		if err != nil {
			t.Fatalf("ListObjects with marker failed: %v", err)
		}

		// Should get the next 2 objects
		if len(resp2.Contents) != 2 {
			t.Errorf("Expected 2 objects after marker, got %d", len(resp2.Contents))
		}

		// First key in second response should be greater than marker
		if *resp2.Contents[0].Key <= lastKey {
			t.Errorf(
				"Expected first key after marker to be greater than %s, got %s",
				lastKey,
				*resp2.Contents[0].Key,
			)
		}
	})

	// 9. Test: Empty bucket (after prefix filter)
	t.Run("ListNonExistentPrefix", func(t *testing.T) {
		resp, err := client.ListObjects(context.TODO(), &s3.ListObjectsInput{
			Bucket: aws.String(bucketName),
			Prefix: aws.String("nonexistent/"),
		})
		if err != nil {
			t.Fatalf("ListObjects failed: %v", err)
		}

		if len(resp.Contents) != 0 {
			t.Errorf("Expected 0 objects for nonexistent prefix, got %d", len(resp.Contents))
		}
	})
}

func TestGetBucketLocation(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "location-test-bucket"
	t.Cleanup(func() {
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Create bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	// Get location
	resp, err := client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("GetBucketLocation failed: %v", err)
	}

	// For us-east-1 (default), LocationConstraint should be empty
	if resp.LocationConstraint != "" {
		t.Logf("LocationConstraint: %v", resp.LocationConstraint)
	}
}

func TestBucketTagging(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "tagging-test-bucket"
	t.Cleanup(func() {
		client.DeleteBucketTagging(context.TODO(), &s3.DeleteBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Create bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	t.Run("NoTagsInitially", func(t *testing.T) {
		_, err := client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		// Should return NoSuchTagSet error
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchTagSet" {
			t.Errorf("Expected NoSuchTagSet error, got: %v", err)
		}
	})

	t.Run("PutAndGetTags", func(t *testing.T) {
		_, err := client.PutBucketTagging(context.TODO(), &s3.PutBucketTaggingInput{
			Bucket: aws.String(bucketName),
			Tagging: &types.Tagging{
				TagSet: []types.Tag{
					{Key: aws.String("Project"), Value: aws.String("Test")},
					{Key: aws.String("Environment"), Value: aws.String("Dev")},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketTagging failed: %v", err)
		}

		resp, err := client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetBucketTagging failed: %v", err)
		}

		if len(resp.TagSet) != 2 {
			t.Errorf("Expected 2 tags, got %d", len(resp.TagSet))
		}
	})

	t.Run("DeleteTags", func(t *testing.T) {
		_, err := client.DeleteBucketTagging(context.TODO(), &s3.DeleteBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketTagging failed: %v", err)
		}

		_, err = client.GetBucketTagging(context.TODO(), &s3.GetBucketTaggingInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchTagSet" {
			t.Errorf("Expected NoSuchTagSet error after delete, got: %v", err)
		}
	})
}

func TestDeleteObjectsWithVersioning(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "delete-objects-versioning-test"

	// Cleanup helper for versioned bucket
	cleanupVersionedBucket := func() {
		// List all versions and delete them
		versResp, err := client.ListObjectVersions(context.TODO(), &s3.ListObjectVersionsInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil {
			// Delete all versions
			for _, v := range versResp.Versions {
				client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
					Bucket:    aws.String(bucketName),
					Key:       v.Key,
					VersionId: v.VersionId,
				})
			}
			// Delete all delete markers
			for _, dm := range versResp.DeleteMarkers {
				client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
					Bucket:    aws.String(bucketName),
					Key:       dm.Key,
					VersionId: dm.VersionId,
				})
			}
		}
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	}
	t.Cleanup(cleanupVersionedBucket)

	// 1. Create bucket and enable versioning
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	_, err = client.PutBucketVersioning(context.TODO(), &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucketName),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		t.Fatalf("PutBucketVersioning failed: %v", err)
	}

	// 2. Create multiple versions of an object
	key := "versioned-file.txt"
	var versionIds []string

	for i := 1; i <= 3; i++ {
		resp, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   strings.NewReader("content version " + string(rune('0'+i))),
		})
		if err != nil {
			t.Fatalf("PutObject (version %d) failed: %v", i, err)
		}
		if resp.VersionId != nil {
			versionIds = append(versionIds, *resp.VersionId)
		}
	}

	if len(versionIds) < 3 {
		t.Fatalf("Expected 3 version IDs, got %d", len(versionIds))
	}

	// 3. Delete specific version using DeleteObjects
	t.Run("DeleteSpecificVersion", func(t *testing.T) {
		deleteResp, err := client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{Key: aws.String(key), VersionId: aws.String(versionIds[1])}, // Delete middle version
				},
			},
		})
		if err != nil {
			t.Fatalf("DeleteObjects failed: %v", err)
		}

		if len(deleteResp.Deleted) != 1 {
			t.Errorf("Expected 1 deleted object, got %d", len(deleteResp.Deleted))
		}
		if deleteResp.Deleted[0].VersionId == nil || *deleteResp.Deleted[0].VersionId != versionIds[1] {
			t.Errorf("Expected deleted version ID %s, got %v", versionIds[1], deleteResp.Deleted[0].VersionId)
		}

		// Verify deleted version is gone
		_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:    aws.String(bucketName),
			Key:       aws.String(key),
			VersionId: aws.String(versionIds[1]),
		})
		if err == nil {
			t.Error("Expected error getting deleted version, but succeeded")
		}

		// Verify other versions still exist
		_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:    aws.String(bucketName),
			Key:       aws.String(key),
			VersionId: aws.String(versionIds[0]),
		})
		if err != nil {
			t.Errorf("First version should still exist: %v", err)
		}

		_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:    aws.String(bucketName),
			Key:       aws.String(key),
			VersionId: aws.String(versionIds[2]),
		})
		if err != nil {
			t.Errorf("Third version should still exist: %v", err)
		}
	})

	// 4. Delete non-existent version (should succeed)
	t.Run("DeleteNonExistentVersion", func(t *testing.T) {
		deleteResp, err := client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{Key: aws.String(key), VersionId: aws.String("nonexistent-version-id")},
				},
			},
		})
		if err != nil {
			t.Fatalf("DeleteObjects should succeed even for non-existent version: %v", err)
		}

		// S3 returns success for non-existent versions
		if len(deleteResp.Deleted) != 1 {
			t.Errorf("Expected 1 deleted entry (even for non-existent), got %d", len(deleteResp.Deleted))
		}
	})

	// 5. Test DeleteMarker behavior
	t.Run("DeleteMarkerCreation", func(t *testing.T) {
		// Delete without version ID creates a delete marker
		deleteResp, err := client.DeleteObjects(context.TODO(), &s3.DeleteObjectsInput{
			Bucket: aws.String(bucketName),
			Delete: &types.Delete{
				Objects: []types.ObjectIdentifier{
					{Key: aws.String(key)}, // No VersionId = create delete marker
				},
			},
		})
		if err != nil {
			t.Fatalf("DeleteObjects failed: %v", err)
		}

		if len(deleteResp.Deleted) != 1 {
			t.Errorf("Expected 1 deleted object, got %d", len(deleteResp.Deleted))
		}
		if deleteResp.Deleted[0].DeleteMarker == nil || !*deleteResp.Deleted[0].DeleteMarker {
			t.Error("Expected DeleteMarker to be true")
		}
		if deleteResp.Deleted[0].DeleteMarkerVersionId == nil || *deleteResp.Deleted[0].DeleteMarkerVersionId == "" {
			t.Error("Expected DeleteMarkerVersionId to be set")
		}

		// Now GetObject should fail (object appears deleted)
		_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err == nil {
			t.Error("Expected error getting object with delete marker, but succeeded")
		}
	})
}

func TestBucketPolicy(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "policy-test-bucket"
	t.Cleanup(func() {
		client.DeleteBucketPolicy(context.TODO(), &s3.DeleteBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Create bucket
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	policy := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::policy-test-bucket/*"
			}
		]
	}`

	t.Run("NoPolicyInitially", func(t *testing.T) {
		_, err := client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchBucketPolicy" {
			t.Errorf("Expected NoSuchBucketPolicy error, got: %v", err)
		}
	})

	t.Run("PutAndGetPolicy", func(t *testing.T) {
		_, err := client.PutBucketPolicy(context.TODO(), &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucketName),
			Policy: aws.String(policy),
		})
		if err != nil {
			t.Fatalf("PutBucketPolicy failed: %v", err)
		}

		resp, err := client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetBucketPolicy failed: %v", err)
		}

		if resp.Policy == nil || *resp.Policy == "" {
			t.Error("Expected policy to be returned")
		}
	})

	t.Run("DeletePolicy", func(t *testing.T) {
		_, err := client.DeleteBucketPolicy(context.TODO(), &s3.DeleteBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketPolicy failed: %v", err)
		}

		_, err = client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchBucketPolicy" {
			t.Errorf("Expected NoSuchBucketPolicy error after delete, got: %v", err)
		}
	})
}
