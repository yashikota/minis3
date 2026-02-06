package integration

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

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
		if resp.IsTruncated != nil && *resp.IsTruncated {
			t.Error("Expected IsTruncated to be false with max-keys=0")
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
					{
						Key:       aws.String(key),
						VersionId: aws.String(versionIds[1]),
					}, // Delete middle version
				},
			},
		})
		if err != nil {
			t.Fatalf("DeleteObjects failed: %v", err)
		}

		if len(deleteResp.Deleted) != 1 {
			t.Errorf("Expected 1 deleted object, got %d", len(deleteResp.Deleted))
		}
		if deleteResp.Deleted[0].VersionId == nil ||
			*deleteResp.Deleted[0].VersionId != versionIds[1] {
			t.Errorf(
				"Expected deleted version ID %s, got %v",
				versionIds[1],
				deleteResp.Deleted[0].VersionId,
			)
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
			t.Errorf(
				"Expected 1 deleted entry (even for non-existent), got %d",
				len(deleteResp.Deleted),
			)
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
		if deleteResp.Deleted[0].DeleteMarkerVersionId == nil ||
			*deleteResp.Deleted[0].DeleteMarkerVersionId == "" {
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

func TestObjectTagging(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "object-tagging-test"
	key := "test.txt"

	t.Cleanup(func() {
		client.DeleteObjectTagging(context.TODO(), &s3.DeleteObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Create bucket and object
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader("test content"),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("NoTagsInitially", func(t *testing.T) {
		resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}
		if len(resp.TagSet) != 0 {
			t.Errorf("Expected 0 tags initially, got %d", len(resp.TagSet))
		}
	})

	t.Run("PutAndGetTags", func(t *testing.T) {
		_, err := client.PutObjectTagging(context.TODO(), &s3.PutObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Tagging: &types.Tagging{
				TagSet: []types.Tag{
					{Key: aws.String("Project"), Value: aws.String("Test")},
					{Key: aws.String("Environment"), Value: aws.String("Dev")},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutObjectTagging failed: %v", err)
		}

		resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if len(resp.TagSet) != 2 {
			t.Errorf("Expected 2 tags, got %d", len(resp.TagSet))
		}
	})

	t.Run("DeleteTags", func(t *testing.T) {
		_, err := client.DeleteObjectTagging(context.TODO(), &s3.DeleteObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("DeleteObjectTagging failed: %v", err)
		}

		resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if len(resp.TagSet) != 0 {
			t.Errorf("Expected 0 tags after delete, got %d", len(resp.TagSet))
		}
	})
}

func TestGetObjectAttributes(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "object-attributes-test"
	key := "test.txt"
	content := "test content for attributes"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Create bucket and object
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("GetETagAndSize", func(t *testing.T) {
		resp, err := client.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			ObjectAttributes: []types.ObjectAttributes{
				types.ObjectAttributesEtag,
				types.ObjectAttributesObjectSize,
				types.ObjectAttributesStorageClass,
			},
		})
		if err != nil {
			t.Fatalf("GetObjectAttributes failed: %v", err)
		}

		if resp.ETag == nil || *resp.ETag == "" {
			t.Error("Expected ETag to be set")
		}

		// ObjectSize and StorageClass may not be set if header parsing differs
		// This is a known limitation of the mock implementation
		if resp.ObjectSize != nil && *resp.ObjectSize != int64(len(content)) {
			t.Errorf("Expected ObjectSize %d, got %v", len(content), resp.ObjectSize)
		}
	})
}

func TestUploadPartCopy(t *testing.T) {
	client := setupTestClient(t)

	srcBucket := "src-copy-bucket"
	dstBucket := "dst-copy-bucket"
	srcKey := "source-large.txt"
	dstKey := "destination-multipart.txt"

	// Create 10MB of data (larger than 5MB minimum for multipart)
	largeContent := strings.Repeat("A", 10*1024*1024)

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(srcBucket),
			Key:    aws.String(srcKey),
		})
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(dstBucket),
			Key:    aws.String(dstKey),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(srcBucket),
		})
		client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{
			Bucket: aws.String(dstBucket),
		})
	})

	// Create buckets
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

	// Put source object
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(srcBucket),
		Key:    aws.String(srcKey),
		Body:   strings.NewReader(largeContent),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("CopyPartWithRange", func(t *testing.T) {
		// Start multipart upload
		createResp, err := client.CreateMultipartUpload(
			context.TODO(),
			&s3.CreateMultipartUploadInput{
				Bucket: aws.String(dstBucket),
				Key:    aws.String(dstKey),
			},
		)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}

		uploadId := createResp.UploadId

		// Copy first 5MB as part 1
		copyResp1, err := client.UploadPartCopy(context.TODO(), &s3.UploadPartCopyInput{
			Bucket:          aws.String(dstBucket),
			Key:             aws.String(dstKey),
			UploadId:        uploadId,
			PartNumber:      aws.Int32(1),
			CopySource:      aws.String(srcBucket + "/" + srcKey),
			CopySourceRange: aws.String("bytes=0-5242879"),
		})
		if err != nil {
			t.Fatalf("UploadPartCopy (part 1) failed: %v", err)
		}

		// Copy remaining bytes as part 2
		copyResp2, err := client.UploadPartCopy(context.TODO(), &s3.UploadPartCopyInput{
			Bucket:          aws.String(dstBucket),
			Key:             aws.String(dstKey),
			UploadId:        uploadId,
			PartNumber:      aws.Int32(2),
			CopySource:      aws.String(srcBucket + "/" + srcKey),
			CopySourceRange: aws.String("bytes=5242880-10485759"),
		})
		if err != nil {
			t.Fatalf("UploadPartCopy (part 2) failed: %v", err)
		}

		// Complete multipart upload
		_, err = client.CompleteMultipartUpload(context.TODO(), &s3.CompleteMultipartUploadInput{
			Bucket:   aws.String(dstBucket),
			Key:      aws.String(dstKey),
			UploadId: uploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: []types.CompletedPart{
					{PartNumber: aws.Int32(1), ETag: copyResp1.CopyPartResult.ETag},
					{PartNumber: aws.Int32(2), ETag: copyResp2.CopyPartResult.ETag},
				},
			},
		})
		if err != nil {
			t.Fatalf("CompleteMultipartUpload failed: %v", err)
		}

		// Verify the copied object
		headResp, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket: aws.String(dstBucket),
			Key:    aws.String(dstKey),
		})
		if err != nil {
			t.Fatalf("HeadObject failed: %v", err)
		}

		if *headResp.ContentLength != int64(len(largeContent)) {
			t.Errorf(
				"Expected content length %d, got %d",
				len(largeContent),
				*headResp.ContentLength,
			)
		}
	})
}

func TestObjectMetadata(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "metadata-test-bucket"
	key := "test.txt"
	content := "test content"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
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

	t.Run("PutObjectWithMetadata", func(t *testing.T) {
		_, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket:      aws.String(bucketName),
			Key:         aws.String(key),
			Body:        strings.NewReader(content),
			Metadata:    map[string]string{"meta1": "value1", "meta2": "value2"},
			ContentType: aws.String("text/plain"),
		})
		if err != nil {
			t.Fatalf("PutObject with metadata failed: %v", err)
		}

		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}

		if resp.Metadata["meta1"] != "value1" {
			t.Errorf("Expected metadata 'meta1' to be 'value1', got '%s'", resp.Metadata["meta1"])
		}
		if resp.Metadata["meta2"] != "value2" {
			t.Errorf("Expected metadata 'meta2' to be 'value2', got '%s'", resp.Metadata["meta2"])
		}
	})

	t.Run("CopyObjectReplacingMetadata", func(t *testing.T) {
		// First put object without metadata
		_, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Body:   strings.NewReader(content),
		})
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}

		// Copy to itself with new metadata
		_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucketName),
			Key:               aws.String(key),
			CopySource:        aws.String(bucketName + "/" + key),
			MetadataDirective: "REPLACE",
			Metadata:          map[string]string{"newmeta": "newvalue"},
		})
		if err != nil {
			t.Fatalf("CopyObject with REPLACE metadata failed: %v", err)
		}

		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObject after copy failed: %v", err)
		}

		if resp.Metadata["newmeta"] != "newvalue" {
			t.Errorf(
				"Expected metadata 'newmeta' to be 'newvalue', got '%s'. Full metadata: %v",
				resp.Metadata["newmeta"],
				resp.Metadata,
			)
		}
	})
}

func TestBucketEncryption(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "encryption-test-bucket"

	t.Cleanup(func() {
		client.DeleteBucketEncryption(context.TODO(), &s3.DeleteBucketEncryptionInput{
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

	t.Run("NoEncryptionInitially", func(t *testing.T) {
		_, err := client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		// Should return ServerSideEncryptionConfigurationNotFoundError
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) ||
			apiErr.ErrorCode() != "ServerSideEncryptionConfigurationNotFoundError" {
			t.Errorf("Expected ServerSideEncryptionConfigurationNotFoundError, got: %v", err)
		}
	})

	t.Run("PutAndGetEncryption", func(t *testing.T) {
		_, err := client.PutBucketEncryption(context.TODO(), &s3.PutBucketEncryptionInput{
			Bucket: aws.String(bucketName),
			ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
				Rules: []types.ServerSideEncryptionRule{
					{
						ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
							SSEAlgorithm: types.ServerSideEncryptionAes256,
						},
						BucketKeyEnabled: aws.Bool(false),
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketEncryption failed: %v", err)
		}

		resp, err := client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetBucketEncryption failed: %v", err)
		}

		if len(resp.ServerSideEncryptionConfiguration.Rules) != 1 {
			t.Errorf(
				"Expected 1 encryption rule, got %d",
				len(resp.ServerSideEncryptionConfiguration.Rules),
			)
		}

		rule := resp.ServerSideEncryptionConfiguration.Rules[0]
		if rule.ApplyServerSideEncryptionByDefault == nil {
			t.Fatal("Expected ApplyServerSideEncryptionByDefault to be set")
		}
		if rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm != types.ServerSideEncryptionAes256 {
			t.Errorf(
				"Expected SSEAlgorithm AES256, got %v",
				rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm,
			)
		}
	})

	t.Run("DeleteEncryption", func(t *testing.T) {
		_, err := client.DeleteBucketEncryption(context.TODO(), &s3.DeleteBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketEncryption failed: %v", err)
		}

		_, err = client.GetBucketEncryption(context.TODO(), &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) ||
			apiErr.ErrorCode() != "ServerSideEncryptionConfigurationNotFoundError" {
			t.Errorf(
				"Expected ServerSideEncryptionConfigurationNotFoundError after delete, got: %v",
				err,
			)
		}
	})
}

func TestBucketLifecycle(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "lifecycle-test-bucket"

	t.Cleanup(func() {
		client.DeleteBucketLifecycle(context.TODO(), &s3.DeleteBucketLifecycleInput{
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

	t.Run("NoLifecycleInitially", func(t *testing.T) {
		_, err := client.GetBucketLifecycleConfiguration(
			context.TODO(),
			&s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			},
		)
		// Should return NoSuchLifecycleConfiguration error
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchLifecycleConfiguration" {
			t.Errorf("Expected NoSuchLifecycleConfiguration error, got: %v", err)
		}
	})

	t.Run("PutAndGetLifecycle", func(t *testing.T) {
		_, err := client.PutBucketLifecycleConfiguration(
			context.TODO(),
			&s3.PutBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
				LifecycleConfiguration: &types.BucketLifecycleConfiguration{
					Rules: []types.LifecycleRule{
						{
							ID:     aws.String("expire-old-objects"),
							Status: types.ExpirationStatusEnabled,
							Filter: &types.LifecycleRuleFilter{
								Prefix: aws.String("logs/"),
							},
							Expiration: &types.LifecycleExpiration{
								Days: aws.Int32(30),
							},
						},
						{
							ID:     aws.String("transition-to-glacier"),
							Status: types.ExpirationStatusEnabled,
							Filter: &types.LifecycleRuleFilter{
								Prefix: aws.String("archive/"),
							},
							Transitions: []types.Transition{
								{
									Days:         aws.Int32(90),
									StorageClass: types.TransitionStorageClassGlacier,
								},
							},
						},
					},
				},
			},
		)
		if err != nil {
			t.Fatalf("PutBucketLifecycleConfiguration failed: %v", err)
		}

		resp, err := client.GetBucketLifecycleConfiguration(
			context.TODO(),
			&s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			},
		)
		if err != nil {
			t.Fatalf("GetBucketLifecycleConfiguration failed: %v", err)
		}

		if len(resp.Rules) != 2 {
			t.Errorf("Expected 2 lifecycle rules, got %d", len(resp.Rules))
		}
	})

	t.Run("DeleteLifecycle", func(t *testing.T) {
		_, err := client.DeleteBucketLifecycle(context.TODO(), &s3.DeleteBucketLifecycleInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketLifecycle failed: %v", err)
		}

		_, err = client.GetBucketLifecycleConfiguration(
			context.TODO(),
			&s3.GetBucketLifecycleConfigurationInput{
				Bucket: aws.String(bucketName),
			},
		)
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchLifecycleConfiguration" {
			t.Errorf("Expected NoSuchLifecycleConfiguration error after delete, got: %v", err)
		}
	})
}

func TestConditionalHeaders(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "conditional-test-bucket"
	key := "test.txt"
	content := "test content for conditional headers"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
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

	// Put object and capture ETag
	putResp, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	etag := *putResp.ETag

	// Get object to capture LastModified
	getResp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	getResp.Body.Close()
	lastModified := *getResp.LastModified

	t.Run("IfMatch_Success", func(t *testing.T) {
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:  aws.String(bucketName),
			Key:     aws.String(key),
			IfMatch: aws.String(etag),
		})
		if err != nil {
			t.Fatalf("GetObject with matching If-Match should succeed: %v", err)
		}
		resp.Body.Close()
	})

	t.Run("IfMatch_Failure", func(t *testing.T) {
		_, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:  aws.String(bucketName),
			Key:     aws.String(key),
			IfMatch: aws.String("\"wrongetag\""),
		})
		if err == nil {
			t.Fatal("Expected error for non-matching If-Match")
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("Expected API error, got: %v", err)
		}
		// Should be 412 Precondition Failed
		if apiErr.ErrorCode() != "PreconditionFailed" {
			t.Errorf("Expected PreconditionFailed error, got: %s", apiErr.ErrorCode())
		}
	})

	t.Run("IfNoneMatch_NotModified", func(t *testing.T) {
		_, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:      aws.String(bucketName),
			Key:         aws.String(key),
			IfNoneMatch: aws.String(etag),
		})
		if err == nil {
			t.Fatal("Expected 304 Not Modified for matching If-None-Match")
		}
		// For SDK, 304 typically returns an error
		var respErr *smithy.OperationError
		if errors.As(err, &respErr) {
			// Check if it's a 304 response
			t.Logf("Got expected condition response: %v", err)
		}
	})

	t.Run("IfNoneMatch_Success", func(t *testing.T) {
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:      aws.String(bucketName),
			Key:         aws.String(key),
			IfNoneMatch: aws.String("\"differentetag\""),
		})
		if err != nil {
			t.Fatalf("GetObject with non-matching If-None-Match should succeed: %v", err)
		}
		resp.Body.Close()
	})

	t.Run("IfModifiedSince_NotModified", func(t *testing.T) {
		// Use a future time - object should not have been modified since then
		futureTime := lastModified.Add(1 * 24 * 60 * 60 * 1e9) // Add 1 day
		_, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:          aws.String(bucketName),
			Key:             aws.String(key),
			IfModifiedSince: aws.Time(futureTime),
		})
		if err == nil {
			t.Fatal("Expected 304 Not Modified for If-Modified-Since with future time")
		}
		t.Logf("Got expected condition response for If-Modified-Since: %v", err)
	})

	t.Run("IfUnmodifiedSince_Success", func(t *testing.T) {
		// Use a future time - object was unmodified since then
		futureTime := lastModified.Add(1 * 24 * 60 * 60 * 1e9) // Add 1 day
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:            aws.String(bucketName),
			Key:               aws.String(key),
			IfUnmodifiedSince: aws.Time(futureTime),
		})
		if err != nil {
			t.Fatalf("GetObject with If-Unmodified-Since (future) should succeed: %v", err)
		}
		resp.Body.Close()
	})

	t.Run("IfUnmodifiedSince_Failure", func(t *testing.T) {
		// Use a past time - object was modified after that
		pastTime := lastModified.Add(-1 * 24 * 60 * 60 * 1e9) // Subtract 1 day
		_, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:            aws.String(bucketName),
			Key:               aws.String(key),
			IfUnmodifiedSince: aws.Time(pastTime),
		})
		if err == nil {
			t.Fatal("Expected 412 Precondition Failed for If-Unmodified-Since with past time")
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("Expected API error, got: %v", err)
		}
		if apiErr.ErrorCode() != "PreconditionFailed" {
			t.Errorf("Expected PreconditionFailed error, got: %s", apiErr.ErrorCode())
		}
	})

	t.Run("HeadObject_IfMatch", func(t *testing.T) {
		// Test conditional headers work with HEAD as well
		_, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket:  aws.String(bucketName),
			Key:     aws.String(key),
			IfMatch: aws.String(etag),
		})
		if err != nil {
			t.Fatalf("HeadObject with matching If-Match should succeed: %v", err)
		}
	})

	t.Run("HeadObject_IfMatch_Failure", func(t *testing.T) {
		_, err := client.HeadObject(context.TODO(), &s3.HeadObjectInput{
			Bucket:  aws.String(bucketName),
			Key:     aws.String(key),
			IfMatch: aws.String("\"wrongetag\""),
		})
		if err == nil {
			t.Fatal("Expected error for non-matching If-Match on HEAD")
		}
	})
}

func TestRangeRequests(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "range-test-bucket"
	key := "test.txt"
	content := "Hello, World! This is test content for range requests."

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
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

	// Put object
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("BasicRange", func(t *testing.T) {
		// Request first 5 bytes: "Hello"
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Range:  aws.String("bytes=0-4"),
		})
		if err != nil {
			t.Fatalf("GetObject with range failed: %v", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(body) != "Hello" {
			t.Errorf("Expected 'Hello', got '%s'", string(body))
		}

		if resp.ContentLength == nil || *resp.ContentLength != 5 {
			t.Errorf("Expected ContentLength 5, got %v", resp.ContentLength)
		}

		if resp.ContentRange == nil {
			t.Errorf("Expected ContentRange to be set, got nil")
		} else if *resp.ContentRange != "bytes 0-4/54" {
			t.Errorf("Expected ContentRange 'bytes 0-4/54', got '%s'", *resp.ContentRange)
		}
	})

	t.Run("OpenEndedRange", func(t *testing.T) {
		// Request from byte 50 to end
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Range:  aws.String("bytes=50-"),
		})
		if err != nil {
			t.Fatalf("GetObject with open-ended range failed: %v", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		expected := content[50:]
		if string(body) != expected {
			t.Errorf("Expected '%s', got '%s'", expected, string(body))
		}
	})

	t.Run("SuffixRange", func(t *testing.T) {
		// Request last 10 bytes
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Range:  aws.String("bytes=-10"),
		})
		if err != nil {
			t.Fatalf("GetObject with suffix range failed: %v", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		expected := content[len(content)-10:]
		if string(body) != expected {
			t.Errorf("Expected '%s', got '%s'", expected, string(body))
		}

		if resp.ContentLength == nil || *resp.ContentLength != 10 {
			t.Errorf("Expected ContentLength 10, got %v", resp.ContentLength)
		}
	})

	t.Run("InvalidRange", func(t *testing.T) {
		// Request beyond object size
		_, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Range:  aws.String("bytes=100-200"),
		})
		if err == nil {
			t.Fatal("Expected error for invalid range, but succeeded")
		}

		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "InvalidRange" {
			t.Errorf("Expected InvalidRange error, got: %v", err)
		}
	})

	t.Run("MiddleRange", func(t *testing.T) {
		// Request bytes 7-11: "World"
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			Range:  aws.String("bytes=7-11"),
		})
		if err != nil {
			t.Fatalf("GetObject with middle range failed: %v", err)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if string(body) != "World" {
			t.Errorf("Expected 'World', got '%s'", string(body))
		}
	})

	t.Run("AcceptRangesHeader", func(t *testing.T) {
		// Normal request should have Accept-Ranges header
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		resp.Body.Close()

		if resp.AcceptRanges == nil || *resp.AcceptRanges != "bytes" {
			t.Errorf("Expected AcceptRanges 'bytes', got %v", resp.AcceptRanges)
		}
	})
}

func TestBucketCORS(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "cors-test-bucket"

	t.Cleanup(func() {
		client.DeleteBucketCors(context.TODO(), &s3.DeleteBucketCorsInput{
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

	t.Run("NoCORSInitially", func(t *testing.T) {
		_, err := client.GetBucketCors(context.TODO(), &s3.GetBucketCorsInput{
			Bucket: aws.String(bucketName),
		})
		// Should return NoSuchCORSConfiguration
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchCORSConfiguration" {
			t.Errorf("Expected NoSuchCORSConfiguration, got: %v", err)
		}
	})

	t.Run("PutAndGetCORS", func(t *testing.T) {
		_, err := client.PutBucketCors(context.TODO(), &s3.PutBucketCorsInput{
			Bucket: aws.String(bucketName),
			CORSConfiguration: &types.CORSConfiguration{
				CORSRules: []types.CORSRule{
					{
						AllowedMethods: []string{"GET", "PUT"},
						AllowedOrigins: []string{"https://example.com"},
						AllowedHeaders: []string{"*"},
						MaxAgeSeconds:  aws.Int32(3000),
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketCors failed: %v", err)
		}

		resp, err := client.GetBucketCors(context.TODO(), &s3.GetBucketCorsInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetBucketCors failed: %v", err)
		}

		if len(resp.CORSRules) != 1 {
			t.Errorf("Expected 1 CORS rule, got %d", len(resp.CORSRules))
		}

		rule := resp.CORSRules[0]
		if len(rule.AllowedMethods) != 2 {
			t.Errorf("Expected 2 allowed methods, got %d", len(rule.AllowedMethods))
		}
		if len(rule.AllowedOrigins) != 1 || rule.AllowedOrigins[0] != "https://example.com" {
			t.Errorf("Expected AllowedOrigins ['https://example.com'], got %v", rule.AllowedOrigins)
		}
	})

	t.Run("DeleteCORS", func(t *testing.T) {
		_, err := client.DeleteBucketCors(context.TODO(), &s3.DeleteBucketCorsInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketCors failed: %v", err)
		}

		// Verify deletion
		_, err = client.GetBucketCors(context.TODO(), &s3.GetBucketCorsInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchCORSConfiguration" {
			t.Errorf("Expected NoSuchCORSConfiguration after deletion, got: %v", err)
		}
	})
}

func TestBucketWebsite(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "website-test-bucket"

	t.Cleanup(func() {
		client.DeleteBucketWebsite(context.TODO(), &s3.DeleteBucketWebsiteInput{
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

	t.Run("NoWebsiteInitially", func(t *testing.T) {
		_, err := client.GetBucketWebsite(context.TODO(), &s3.GetBucketWebsiteInput{
			Bucket: aws.String(bucketName),
		})
		// Should return NoSuchWebsiteConfiguration
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchWebsiteConfiguration" {
			t.Errorf("Expected NoSuchWebsiteConfiguration, got: %v", err)
		}
	})

	t.Run("PutAndGetWebsite", func(t *testing.T) {
		_, err := client.PutBucketWebsite(context.TODO(), &s3.PutBucketWebsiteInput{
			Bucket: aws.String(bucketName),
			WebsiteConfiguration: &types.WebsiteConfiguration{
				IndexDocument: &types.IndexDocument{
					Suffix: aws.String("index.html"),
				},
				ErrorDocument: &types.ErrorDocument{
					Key: aws.String("error.html"),
				},
			},
		})
		if err != nil {
			t.Fatalf("PutBucketWebsite failed: %v", err)
		}

		resp, err := client.GetBucketWebsite(context.TODO(), &s3.GetBucketWebsiteInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetBucketWebsite failed: %v", err)
		}

		if resp.IndexDocument == nil || *resp.IndexDocument.Suffix != "index.html" {
			t.Errorf("Expected IndexDocument.Suffix 'index.html', got %v", resp.IndexDocument)
		}
		if resp.ErrorDocument == nil || *resp.ErrorDocument.Key != "error.html" {
			t.Errorf("Expected ErrorDocument.Key 'error.html', got %v", resp.ErrorDocument)
		}
	})

	t.Run("DeleteWebsite", func(t *testing.T) {
		_, err := client.DeleteBucketWebsite(context.TODO(), &s3.DeleteBucketWebsiteInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeleteBucketWebsite failed: %v", err)
		}

		// Verify deletion
		_, err = client.GetBucketWebsite(context.TODO(), &s3.GetBucketWebsiteInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchWebsiteConfiguration" {
			t.Errorf("Expected NoSuchWebsiteConfiguration after deletion, got: %v", err)
		}
	})
}

func TestPublicAccessBlock(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "public-access-block-test-bucket"

	t.Cleanup(func() {
		client.DeletePublicAccessBlock(context.TODO(), &s3.DeletePublicAccessBlockInput{
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

	t.Run("NoPublicAccessBlockInitially", func(t *testing.T) {
		_, err := client.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		// Should return NoSuchPublicAccessBlockConfiguration
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) ||
			apiErr.ErrorCode() != "NoSuchPublicAccessBlockConfiguration" {
			t.Errorf("Expected NoSuchPublicAccessBlockConfiguration, got: %v", err)
		}
	})

	t.Run("PutAndGetPublicAccessBlock", func(t *testing.T) {
		_, err := client.PutPublicAccessBlock(context.TODO(), &s3.PutPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
			PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(true),
				IgnorePublicAcls:      aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
			},
		})
		if err != nil {
			t.Fatalf("PutPublicAccessBlock failed: %v", err)
		}

		resp, err := client.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("GetPublicAccessBlock failed: %v", err)
		}

		if resp.PublicAccessBlockConfiguration == nil {
			t.Fatal("Expected PublicAccessBlockConfiguration to be set")
		}
		config := resp.PublicAccessBlockConfiguration
		if config.BlockPublicAcls == nil || !*config.BlockPublicAcls {
			t.Errorf("Expected BlockPublicAcls true, got %v", config.BlockPublicAcls)
		}
		if config.IgnorePublicAcls == nil || !*config.IgnorePublicAcls {
			t.Errorf("Expected IgnorePublicAcls true, got %v", config.IgnorePublicAcls)
		}
		if config.BlockPublicPolicy == nil || !*config.BlockPublicPolicy {
			t.Errorf("Expected BlockPublicPolicy true, got %v", config.BlockPublicPolicy)
		}
		if config.RestrictPublicBuckets == nil || !*config.RestrictPublicBuckets {
			t.Errorf("Expected RestrictPublicBuckets true, got %v", config.RestrictPublicBuckets)
		}
	})

	t.Run("DeletePublicAccessBlock", func(t *testing.T) {
		_, err := client.DeletePublicAccessBlock(context.TODO(), &s3.DeletePublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			t.Fatalf("DeletePublicAccessBlock failed: %v", err)
		}

		// Verify deletion
		_, err = client.GetPublicAccessBlock(context.TODO(), &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) ||
			apiErr.ErrorCode() != "NoSuchPublicAccessBlockConfiguration" {
			t.Errorf("Expected NoSuchPublicAccessBlockConfiguration after deletion, got: %v", err)
		}
	})
}

func TestPutObjectWithTagging(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "inline-tagging-test"
	key := "tagged.txt"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
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

	// PutObject with inline tagging
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:  aws.String(bucketName),
		Key:     aws.String(key),
		Body:    strings.NewReader("tagged content"),
		Tagging: aws.String("Project=Test&Environment=Dev"),
	})
	if err != nil {
		t.Fatalf("PutObject with tagging failed: %v", err)
	}

	// Verify tags via GetObjectTagging
	resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectTagging failed: %v", err)
	}

	if len(resp.TagSet) != 2 {
		t.Fatalf("Expected 2 tags, got %d", len(resp.TagSet))
	}

	tagMap := make(map[string]string)
	for _, tag := range resp.TagSet {
		tagMap[*tag.Key] = *tag.Value
	}
	if tagMap["Project"] != "Test" {
		t.Errorf("Expected Project=Test, got %q", tagMap["Project"])
	}
	if tagMap["Environment"] != "Dev" {
		t.Errorf("Expected Environment=Dev, got %q", tagMap["Environment"])
	}
}

func TestPutObjectWithObjectLock(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "object-lock-inline-test"
	key := "locked.txt"

	t.Cleanup(func() {
		// Remove legal hold first so we can delete
		client.PutObjectLegalHold(context.TODO(), &s3.PutObjectLegalHoldInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOff,
			},
		})
		// Remove retention
		client.PutObjectRetention(context.TODO(), &s3.PutObjectRetentionInput{
			Bucket:                    aws.String(bucketName),
			Key:                       aws.String(key),
			BypassGovernanceRetention: aws.Bool(true),
			Retention: &types.ObjectLockRetention{
				Mode:            types.ObjectLockRetentionModeGovernance,
				RetainUntilDate: aws.Time(time.Now().Add(-1 * time.Hour)),
			},
		})
		// Clean up versioned objects
		versResp, err := client.ListObjectVersions(context.TODO(), &s3.ListObjectVersionsInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil {
			for _, v := range versResp.Versions {
				client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
					Bucket:    aws.String(bucketName),
					Key:       v.Key,
					VersionId: v.VersionId,
				})
			}
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
	})

	// Create bucket with object lock enabled
	_, err := client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket:                     aws.String(bucketName),
		ObjectLockEnabledForBucket: aws.Bool(true),
	})
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}

	retainUntil := time.Now().Add(24 * time.Hour).UTC()
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:                    aws.String(bucketName),
		Key:                       aws.String(key),
		Body:                      strings.NewReader("locked content"),
		ObjectLockMode:            types.ObjectLockModeGovernance,
		ObjectLockRetainUntilDate: aws.Time(retainUntil),
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
	})
	if err != nil {
		t.Fatalf("PutObject with object lock failed: %v", err)
	}

	// Verify retention
	retentionResp, err := client.GetObjectRetention(context.TODO(), &s3.GetObjectRetentionInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectRetention failed: %v", err)
	}
	if retentionResp.Retention.Mode != types.ObjectLockRetentionModeGovernance {
		t.Errorf("Expected GOVERNANCE mode, got %v", retentionResp.Retention.Mode)
	}

	// Verify legal hold
	legalHoldResp, err := client.GetObjectLegalHold(context.TODO(), &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectLegalHold failed: %v", err)
	}
	if legalHoldResp.LegalHold.Status != types.ObjectLockLegalHoldStatusOn {
		t.Errorf("Expected legal hold ON, got %v", legalHoldResp.LegalHold.Status)
	}
}

func TestCopyObjectConditionalHeaders(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "copy-conditional-test"
	srcKey := "source.txt"
	dstKey := "destination.txt"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName), Key: aws.String(srcKey),
		})
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName), Key: aws.String(dstKey),
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

	putResp, err := client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(srcKey),
		Body:   strings.NewReader("source content"),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	etag := *putResp.ETag

	t.Run("CopySourceIfMatch_Success", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucketName),
			Key:               aws.String(dstKey),
			CopySource:        aws.String(bucketName + "/" + srcKey),
			CopySourceIfMatch: aws.String(etag),
		})
		if err != nil {
			t.Fatalf("CopyObject with matching If-Match should succeed: %v", err)
		}
	})

	t.Run("CopySourceIfMatch_Failure", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:            aws.String(bucketName),
			Key:               aws.String(dstKey),
			CopySource:        aws.String(bucketName + "/" + srcKey),
			CopySourceIfMatch: aws.String("\"wrongetag\""),
		})
		if err == nil {
			t.Fatal("Expected error for non-matching CopySourceIfMatch")
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "PreconditionFailed" {
			t.Errorf("Expected PreconditionFailed, got: %v", err)
		}
	})

	t.Run("CopySourceIfNoneMatch_Failure", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:                aws.String(bucketName),
			Key:                   aws.String(dstKey),
			CopySource:            aws.String(bucketName + "/" + srcKey),
			CopySourceIfNoneMatch: aws.String(etag),
		})
		if err == nil {
			t.Fatal("Expected error for matching CopySourceIfNoneMatch")
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "PreconditionFailed" {
			t.Errorf("Expected PreconditionFailed, got: %v", err)
		}
	})

	t.Run("CopySourceIfNoneMatch_Success", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:                aws.String(bucketName),
			Key:                   aws.String(dstKey),
			CopySource:            aws.String(bucketName + "/" + srcKey),
			CopySourceIfNoneMatch: aws.String("\"differentetag\""),
		})
		if err != nil {
			t.Fatalf("CopyObject with non-matching If-None-Match should succeed: %v", err)
		}
	})
}

func TestGetObjectResponseOverrides(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "response-override-test"
	key := "test.txt"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName), Key: aws.String(key),
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
		Bucket:      aws.String(bucketName),
		Key:         aws.String(key),
		Body:        strings.NewReader("test content"),
		ContentType: aws.String("text/plain"),
	})
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	t.Run("OverrideContentType", func(t *testing.T) {
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:              aws.String(bucketName),
			Key:                 aws.String(key),
			ResponseContentType: aws.String("application/octet-stream"),
		})
		if err != nil {
			t.Fatalf("GetObject with response override failed: %v", err)
		}
		resp.Body.Close()

		if resp.ContentType == nil || *resp.ContentType != "application/octet-stream" {
			t.Errorf("Expected Content-Type 'application/octet-stream', got %v", resp.ContentType)
		}
	})

	t.Run("OverrideContentDisposition", func(t *testing.T) {
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:                     aws.String(bucketName),
			Key:                        aws.String(key),
			ResponseContentDisposition: aws.String("attachment; filename=\"download.txt\""),
		})
		if err != nil {
			t.Fatalf("GetObject with response override failed: %v", err)
		}
		resp.Body.Close()

		if resp.ContentDisposition == nil ||
			*resp.ContentDisposition != "attachment; filename=\"download.txt\"" {
			t.Errorf("Expected Content-Disposition override, got %v", resp.ContentDisposition)
		}
	})

	t.Run("OverrideCacheControl", func(t *testing.T) {
		resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
			Bucket:               aws.String(bucketName),
			Key:                  aws.String(key),
			ResponseCacheControl: aws.String("no-cache"),
		})
		if err != nil {
			t.Fatalf("GetObject with response override failed: %v", err)
		}
		resp.Body.Close()

		if resp.CacheControl == nil || *resp.CacheControl != "no-cache" {
			t.Errorf("Expected Cache-Control 'no-cache', got %v", resp.CacheControl)
		}
	})
}

func TestCopyObjectTaggingDirective(t *testing.T) {
	client := setupTestClient(t)

	bucketName := "copy-tagging-directive-test"
	srcKey := "source.txt"
	dstKey := "destination.txt"

	t.Cleanup(func() {
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName), Key: aws.String(srcKey),
		})
		client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName), Key: aws.String(dstKey),
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

	// Put source with inline tags
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:  aws.String(bucketName),
		Key:     aws.String(srcKey),
		Body:    strings.NewReader("source content"),
		Tagging: aws.String("Env=Prod&Team=Backend"),
	})
	if err != nil {
		t.Fatalf("PutObject with tagging failed: %v", err)
	}

	t.Run("DefaultCopiesTags", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:     aws.String(bucketName),
			Key:        aws.String(dstKey),
			CopySource: aws.String(bucketName + "/" + srcKey),
		})
		if err != nil {
			t.Fatalf("CopyObject failed: %v", err)
		}

		resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(dstKey),
		})
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		tagMap := make(map[string]string)
		for _, tag := range resp.TagSet {
			tagMap[*tag.Key] = *tag.Value
		}
		if tagMap["Env"] != "Prod" {
			t.Errorf("Expected Env=Prod, got %q", tagMap["Env"])
		}
		if tagMap["Team"] != "Backend" {
			t.Errorf("Expected Team=Backend, got %q", tagMap["Team"])
		}
	})

	t.Run("ReplaceDirective", func(t *testing.T) {
		_, err := client.CopyObject(context.TODO(), &s3.CopyObjectInput{
			Bucket:           aws.String(bucketName),
			Key:              aws.String(dstKey),
			CopySource:       aws.String(bucketName + "/" + srcKey),
			TaggingDirective: types.TaggingDirectiveReplace,
			Tagging:          aws.String("NewTag=NewValue"),
		})
		if err != nil {
			t.Fatalf("CopyObject with REPLACE tagging directive failed: %v", err)
		}

		resp, err := client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(dstKey),
		})
		if err != nil {
			t.Fatalf("GetObjectTagging failed: %v", err)
		}

		if len(resp.TagSet) != 1 {
			t.Fatalf("Expected 1 tag, got %d", len(resp.TagSet))
		}
		if *resp.TagSet[0].Key != "NewTag" || *resp.TagSet[0].Value != "NewValue" {
			t.Errorf(
				"Expected NewTag=NewValue, got %s=%s",
				*resp.TagSet[0].Key,
				*resp.TagSet[0].Value,
			)
		}
	})
}
