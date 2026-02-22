# Minis3 🪣

[![codecov](https://codecov.io/gh/yashikota/minis3/graph/badge.svg?token=16VPV4FWZE)](https://codecov.io/gh/yashikota/minis3)
[![s3-tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/yashikota/minis3/main/.github/badges/s3-tests.json&cacheSeconds=300)](https://github.com/yashikota/minis3/actions/workflows/s3tests.yaml)

Sometimes you want to test code which uses S3, without making it a full-blown integration test. Minis3 implements (parts of) the S3 server, to be used in unittests. It enables a simple, cheap, in-memory, S3 replacement, with a real TCP interface. Think of it as the S3 version of `net/http/httptest`

## Usage

### Use as a Go package

```bash
go get github.com/yashikota/minis3
```

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
					AccessKeyID:     "test",
					SecretAccessKey: "test",
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

### Run as a standalone S3-compatible server

Install the binary:  

```bash
go install github.com/yashikota/minis3/cmd/minis3@latest
```

Or download from [Releases](https://github.com/yashikota/minis3/releases/latest).  

Start the server (default port is `9191`):  

```bash
minis3
```

Use a custom port:  

```bash
minis3 --port 9000
```

Health check:  

```bash
curl -i http://127.0.0.1:9191/health
```

## 📋 Supported Operations

> [!Note]
> Minis3 is a single-region, single-owner in-memory mock server. Features like `ExpectedBucketOwner`, `BucketRegion` filter, and multi-region support are intentionally not implemented as they are not meaningful in a mock environment.
> Minis3 validates the `x-amz-mfa` header format but does not perform actual TOTP authentication (no secret keys). Any correctly formatted MFA header is accepted for testing purposes.

### Support Summary

| Area | Status | Implemented APIs |
| ---- | ------ | ---------------- |
| Bucket operations | ✅ Full support | 32 |
| Object operations | ✅ Full support | 15 |
| Object Lock operations | ✅ Full support | 6 |
| Multipart upload operations | ✅ Full support | 7 |

### Operation List (by category)

<details>
<summary>🪣 Bucket operations (32)</summary>

`ListBuckets`, `CreateBucket`, `DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketTagging`, `PutBucketTagging`, `DeleteBucketTagging`, `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketAcl`, `PutBucketAcl`, `GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetBucketLifecycleConfiguration`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle`, `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `GetBucketWebsite`, `PutBucketWebsite`, `DeleteBucketWebsite`, `GetPublicAccessBlock`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`

</details>

<details>
<summary>📦 Object operations (15)</summary>

`PutObject`, `GetObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`, `HeadObject`, `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectAttributes`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`

</details>

<details>
<summary>🔒 Object Lock operations (6)</summary>

`GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetObjectRetention`, `PutObjectRetention`, `GetObjectLegalHold`, `PutObjectLegalHold`

</details>

<details>
<summary>📤 Multipart upload operations (7)</summary>

`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`, `ListParts`, `UploadPartCopy`

</details>

### API-Specific Limitations

| Operation | Unsupported optional fields |
| --------- | --------------------------- |
| `UploadPartCopy` | `CopySourceSSECustomerAlgorithm`, `CopySourceSSECustomerKey`, `CopySourceSSECustomerKeyMD5`, `SSECustomerAlgorithm`, `SSECustomerKey`, `SSECustomerKeyMD5` |

### Additional Features

- **Conditional Headers:** If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since (for GetObject/HeadObject)
- **Presigned URLs:** SigV4 and SigV2 presigned URL verification
- **AWS Chunked Encoding:** Transparent decoding of `aws-chunked` transfer encoding
- **Response Header Overrides:** GetObject query parameters (`response-content-type`, `response-content-disposition`, etc.)
- **Copy Source Conditionals:** `x-amz-copy-source-if-match`, `x-amz-copy-source-if-none-match`, `x-amz-copy-source-if-modified-since`, `x-amz-copy-source-if-unmodified-since`
- **Object Lock Enforcement:** Delete-time retention/legal hold checks with `x-amz-bypass-governance-retention` support
- **StorageClass:** Supported on PutObject, CopyObject, and multipart uploads
- **SSE Headers:** Server-side encryption headers are stored and returned (mock only, no actual encryption)
- **Request IDs:** `x-amz-request-id` and `x-amz-id-2` headers on every response
- **Metadata/Tagging Directives:** `x-amz-metadata-directive` and `x-amz-tagging-directive` for CopyObject
- **Content-Type Default:** Defaults to `application/octet-stream` when not specified

## 🧪 Development & Testing

- `task lint`: Run lint and formatting checks.
- `task unit-test`: Run unit tests with race detection and shuffled order.
- `task sdk-test`: Run integration tests in `integration/sdk`.
- `task s3-test`: Run Ceph `s3-tests` in Docker.
- `task test`: Run `unit-test`, `sdk-test`, and `s3-test`.

### `task s3-test` marker policy

By default, `task s3-test` excludes tests marked with `fails_on_aws` and `fails_on_rgw` via `PYTEST_ADDOPTS` in `integration/s3-test/compose.yaml`.

This keeps the default suite focused on AWS-compatible behavior and avoids known non-AWS/non-RGW expectation tests in daily runs.

To run the full suite (including those markers), run from `integration/s3-test`:

```bash
docker compose run --rm -e PYTEST_ADDOPTS="" s3tests
```

## Credits

[Miniredis](https://github.com/alicebob/miniredis) is a Redis test server, used in Go unittests. Minis3 is inspired by Miniredis.  
