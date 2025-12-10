# Minis3 🪣

Sometimes you want to test code which uses S3, without making it a full-blown integration test. Minis3 implements (parts of) the S3 server, to be used in unittests. It enables a simple, cheap, in-memory, S3 replacement, with a real TCP interface. Think of it as the S3 version of `net/http/httptest`

## 📋 Supported Operations

**Legend:** ✅ = Full support | ⚠️ = Partial support (basic features only) | ⌛ = Not implemented

### 🪣 Bucket Operations

| Operation | Status | Unsupported Features |
| --------- | ------ | -------------------- |
| ListBuckets | ⚠️ | ContinuationToken, Prefix, MaxBuckets |
| CreateBucket | ⚠️ | LocationConstraint, ACL, ObjectLockConfiguration, GrantFullControl, GrantRead, GrantReadACP, GrantWrite, GrantWriteACP, ObjectOwnership |
| DeleteBucket | ⚠️ | ExpectedBucketOwner |
| HeadBucket | ⚠️ | ExpectedBucketOwner |
| GetBucketLocation | ⌛ | |
| GetBucketVersioning | ⌛ | |
| PutBucketVersioning | ⌛ | |
| GetBucketTagging | ⌛ | |
| PutBucketTagging | ⌛ | |
| DeleteBucketTagging | ⌛ | |
| GetBucketPolicy | ⌛ | |
| PutBucketPolicy | ⌛ | |
| DeleteBucketPolicy | ⌛ | |

### 📦 Object Operations

| Operation | Status | Unsupported Features |
| --------- | ------ | -------------------- |
| PutObject | ⚠️ | ACL, CacheControl, ContentDisposition, ContentEncoding, ContentLanguage, Expires, GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP, Metadata, ServerSideEncryption, StorageClass, WebsiteRedirectLocation, SSECustomerAlgorithm, SSECustomerKey, SSEKMSKeyId, Tagging, ObjectLockMode, ObjectLockRetainUntilDate, ObjectLockLegalHoldStatus, ChecksumAlgorithm |
| GetObject | ⚠️ | IfMatch, IfModifiedSince, IfNoneMatch, IfUnmodifiedSince, Range, ResponseCacheControl, ResponseContentDisposition, ResponseContentEncoding, ResponseContentLanguage, ResponseContentType, ResponseExpires, VersionId, SSECustomerAlgorithm, SSECustomerKey, PartNumber, ChecksumMode |
| DeleteObject | ⚠️ | VersionId, MFA, BypassGovernanceRetention, ExpectedBucketOwner |
| DeleteObjects | ⚠️ | VersionId (per object), MFA, BypassGovernanceRetention, ExpectedBucketOwner, ChecksumAlgorithm |
| CopyObject | ⚠️ | ACL, CacheControl, ChecksumAlgorithm, ContentDisposition, ContentEncoding, ContentLanguage, ContentType, CopySourceIfMatch, CopySourceIfModifiedSince, CopySourceIfNoneMatch, CopySourceIfUnmodifiedSince, Expires, GrantFullControl, GrantRead, GrantReadACP, GrantWriteACP, Metadata, MetadataDirective, TaggingDirective, ServerSideEncryption, StorageClass, WebsiteRedirectLocation, SSECustomerAlgorithm, SSECustomerKey, SSEKMSKeyId, CopySourceSSECustomerAlgorithm, CopySourceSSECustomerKey, Tagging, ObjectLockMode, ObjectLockRetainUntilDate, ObjectLockLegalHoldStatus |
| HeadObject | ⚠️ | IfMatch, IfModifiedSince, IfNoneMatch, IfUnmodifiedSince, Range, VersionId, SSECustomerAlgorithm, SSECustomerKey, PartNumber, ChecksumMode |
| ListObjects | ⚠️ | RequestPayer, ExpectedBucketOwner, OptionalObjectAttributes |
| ListObjectsV2 | ⚠️ | ContinuationToken, StartAfter, FetchOwner, EncodingType, ExpectedBucketOwner, OptionalObjectAttributes |
| ListObjectVersions | ⌛ | |
| GetObjectAttributes | ⌛ | |
| GetObjectTagging | ⌛ | |
| PutObjectTagging | ⌛ | |
| DeleteObjectTagging | ⌛ | |
| GetObjectAcl | ⌛ | |
| PutObjectAcl | ⌛ | |

### 📤 Multipart Upload Operations

| Operation | Status | Unsupported Features |
| --------- | ------ | -------------------- |
| CreateMultipartUpload | ⌛ | |
| UploadPart | ⌛ | |
| UploadPartCopy | ⌛ | |
| CompleteMultipartUpload | ⌛ | |
| AbortMultipartUpload | ⌛ | |
| ListMultipartUploads | ⌛ | |
| ListParts | ⌛ | |

## Installation

```bash
go get github.com/yashikota/minis3
```

## Example

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/yashikota/minis3"
)

func main() {
	// 1. Start minis3
	server := minis3.New()
	server.Start()
	defer server.Close()
	fmt.Printf("minis3 started at %s\n", server.Addr())

	// 2. Configure AWS SDK to use minis3
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "minis3",
					SecretAccessKey: "minis3",
					SessionToken:    "",
				}, nil
			}),
		),
	)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + server.Addr())
		o.UsePathStyle = true // Important: minis3 currently supports path style
	})

	// 3. Create Bucket
	bucketName := "example-bucket"
	_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("failed to create bucket: %v", err)
	}
	fmt.Printf("Created bucket: %s\n", bucketName)

	// 4. Put Object
	key := "example-key"
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader("Hello from minis3 example!"),
	})
	if err != nil {
		log.Fatalf("failed to put object: %v", err)
	}
	fmt.Printf("Put object: %s\n", key)

	// 5. Get Object
	resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Fatalf("failed to get object: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read object body: %v", err)
	}
	fmt.Printf("Got object content body: %s\n", string(bodyBytes))
	fmt.Printf("Got object content type: %s\n", *resp.ContentType)
}
```

## Credits

[Miniredis](https://github.com/alicebob/miniredis) is a Redis test server, used in Go unittests. Minis3 is inspired by Miniredis.  
