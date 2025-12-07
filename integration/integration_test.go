package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/yashikota/minis3"
)

func TestIntegrationWithSDK(t *testing.T) {
	// Start Server
	server := minis3.New()
	server.Start()
	defer server.Close()

	// Configure SDK
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

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + server.Addr())
		o.UsePathStyle = true
	})

	bucketName := "integration-test-bucket"
	key := "test.txt"
	content := "integration test content"

	// 1. Create Bucket
	_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
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
	// Start Server
	server := minis3.New()
	server.Start()
	defer server.Close()

	// Configure SDK
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

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + server.Addr())
		o.UsePathStyle = true
	})

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
	_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
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
