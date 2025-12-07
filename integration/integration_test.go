package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
