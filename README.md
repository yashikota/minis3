# Minis3 🪣

[![codecov](https://codecov.io/gh/yashikota/minis3/graph/badge.svg?token=16VPV4FWZE)](https://codecov.io/gh/yashikota/minis3)
[![s3-tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/yashikota/minis3/main/.github/badges/s3-tests.json&cacheSeconds=300)](https://github.com/yashikota/minis3/actions/workflows/s3tests.yaml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/yashikota/minis3)

Sometimes you want to test code which uses S3, without making it a full-blown integration test. Minis3 implements (parts of) the S3 server, to be used in unittests. It enables a simple, cheap, in-memory, S3 replacement, with a real TCP interface. Think of it as the S3 version of `net/http/httptest`

<img width="962" height="873" alt="minis3" src="https://github.com/user-attachments/assets/cc204216-f665-4f08-b6e4-bc56cfb0bd3b" />

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
| Bucket operations | ✅ Full support | 41 |
| Object operations | ✅ Full support | 17 |
| Object Lock operations | ✅ Full support | 6 |
| Multipart upload operations | ✅ Full support | 7 |

### Operation List (by category)

<details>
<summary>🪣 Bucket operations (41)</summary>

`ListBuckets`, `CreateBucket`, `DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketTagging`, `PutBucketTagging`, `DeleteBucketTagging`, `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicyStatus`, `GetBucketAcl`, `PutBucketAcl`, `GetBucketOwnershipControls`, `PutBucketOwnershipControls`, `DeleteBucketOwnershipControls`, `GetBucketRequestPayment`, `PutBucketRequestPayment`, `GetBucketLogging`, `PutBucketLogging`, `DeleteBucketLogging`, `GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetBucketLifecycleConfiguration`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle`, `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `GetBucketWebsite`, `PutBucketWebsite`, `DeleteBucketWebsite`, `GetPublicAccessBlock`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`

</details>

<details>
<summary>📦 Object operations (17)</summary>

`PutObject`, `GetObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`, `HeadObject`, `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectAttributes`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`, `RestoreObject`, `PostObject` (browser-based multipart form upload)

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

| Operation | Unsupported optional fields / simplified behavior |
| --------- | ------------------------------------------------- |
| `UploadPartCopy` | `CopySourceSSECustomerAlgorithm`, `CopySourceSSECustomerKey`, `CopySourceSSECustomerKeyMD5`, `SSECustomerAlgorithm`, `SSECustomerKey`, `SSECustomerKeyMD5` |
| `RestoreObject` | Restores complete instantly; `x-amz-restore` always reports `ongoing-request="false"` once restored |
| `PutObject` / `CopyObject` with `aws:kms` | `x-amz-server-side-encryption-aws-kms-key-id` is optional (omitted → default key is assumed, per AWS); headers are stored, no actual encryption |
| `PutBucketPolicy` | Policies are validated strictly (unknown elements, actions, condition operators or malformed values are rejected with `MalformedPolicy`); `Principal`/`NotPrincipal` (`AWS` account IDs, account-root and user ARNs, `CanonicalUser`, `Service`), `Action`/`NotAction`, `Resource`/`NotResource` and every IAM condition operator family (String, Numeric, Date, Bool, Binary, IpAddress, Arn, Null, with `IfExists` and `ForAllValues`/`ForAnyValue`) are evaluated. `NotPrincipal` with `Allow` is rejected; `Resource` may be omitted and duplicate `Sid`s are accepted (as RGW does) |
| `GetObject` `Range` | One range per request, as in AWS. A multi-range, reversed or malformed header is ignored and the whole object is returned with 200; a range that starts past the end, or `bytes=-0`, returns 416 `InvalidRange` |
| MFA Delete | `x-amz-mfa` must be present and well formed (`<serial> <code>`); the code itself is not checked |

### Additional Features

- **Conditional Headers:** If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since (for GetObject/HeadObject)
- **Presigned URLs:** SigV4 and SigV2 presigned URLs are verified (signature, access key and expiry)
- **SigV2 `Authorization` header:** the access key, the HMAC-SHA1 signature and the `Date`/`x-amz-date` skew are verified
- **AWS Chunked Encoding:** Transparent decoding of `aws-chunked` transfer encoding
- **Response Header Overrides:** GetObject query parameters (`response-content-type`, `response-content-disposition`, etc.)
- **Copy Source Conditionals:** `x-amz-copy-source-if-match`, `x-amz-copy-source-if-none-match`, `x-amz-copy-source-if-modified-since`, `x-amz-copy-source-if-unmodified-since`
- **Authorization:** Every operation is authorized with the IAM action from the S3 API Reference (for example `DeleteBucketTagging` → `s3:PutBucketTagging`, `GetObject?versionId` → `s3:GetObjectVersion`), against the bucket policy, ownership, ACLs (READ/WRITE/READ_ACP/WRITE_ACP only grant the actions AWS maps them to), Object Ownership and the public access block. `DeleteObjects` authorizes each key and reports denied keys as `AccessDenied`; POST Object authorizes the form's signer. As in RGW, only the bucket owner may change bucket logging
- **Object Lock Enforcement:** Delete-time retention/legal hold checks with `x-amz-bypass-governance-retention` support (honoured only when the caller holds `s3:BypassGovernanceRetention`)
- **StorageClass:** Supported on PutObject, CopyObject, and multipart uploads
- **SSE Headers:** Server-side encryption headers are stored and returned (mock only, no actual encryption)
- **Request IDs:** `x-amz-request-id` and `x-amz-id-2` headers on every response
- **Metadata/Tagging Directives:** `x-amz-metadata-directive` and `x-amz-tagging-directive` for CopyObject
- **Content-Type Default:** Defaults to `application/octet-stream` when not specified
- **POST Object (browser upload):** `POST /{bucket}` with `multipart/form-data` (`key`, `file` fields, optional POST policy/signature validation, tagging, checksum, and metadata fields)
- **Bucket logging flush (test extension):** `POST /{bucket}?logging` force-flushes pending server-access-log batches for the bucket
- **CreateBucket idempotency:** Re-creating an already-owned bucket returns success (`200`) instead of an error
- **Admin ForceDeleteBucket (test extension):** `DELETE /_minis3/buckets/{bucket}` removes a bucket and all its objects unconditionally

## 🧪 Development & Testing

- `task lint`: Run lint and formatting checks.
- `task unit-test`: Run unit tests with race detection and shuffled order.
- `task sdk-test`: Run integration tests in `integration/sdk`.
- `task s3-test`: Run Ceph `s3-tests` in Docker.
- `task test`: Run `unit-test`, `sdk-test`, and `s3-test`.
- `task formal`: Model-check the TLA+ specifications in `formal/tla` with the static TLC binary from [tlc-static](https://github.com/yashikota/tlc-static) (downloaded and checksum-verified on first run; no Java needed) and run the Go model-based tests.
- `task tobari`: Measure scoped coverage with tobari (outputs `./tobari/tobari.json`).
- `task tobari-html`: Generate an HTML coverage report from `tobari/tobari.json`.

### Formal verification

`formal/tla` holds TLA+ specifications that the TLC model checker explores exhaustively within small bounds:

- `S3Versioning.tla`: versioning states (Unset → Enabled ⇄ Suspended), null-version replacement, delete markers, permanent deletes, Object Lock and legal holds. Invariants include a unique null version, unique version IDs, newest-first ordering, and "Object Lock implies versioning enabled"; temporal properties include "a bucket never returns to unversioned" and "a version under legal hold is never removed".
- `S3BucketPolicy.tla`: bucket policy evaluation over every statement shape (Principal/NotPrincipal, Action/NotAction, Resource/NotResource, conditions). TLC checks that the implementation-shaped single-pass fold equals the declarative "explicit Deny wins, else any Allow" semantics, that statement order is irrelevant, that Deny is sticky and Allow is monotone, that anonymous callers are matched only through `*`, and that the Not* elements are exact complements. `S3BucketPolicyPairs.cfg` explores all two-statement policies.
- `S3Authorization.tla`: the access decision for one request, over every combination of caller (owner, other user, anonymous), action kind, policy verdict, public policy, ACL grant, Object Ownership and public access block settings (4,800 requests). TLC checks that the implementation's sequence of checks equals a declarative rule, that an explicit Deny wins except for the owner managing the policy, that BucketOwnerEnforced ignores ACLs, that IgnorePublicAcls and RestrictPublicBuckets behave as documented, that a failed conditional Allow does not fall back to ACLs, that configuration actions need ownership or a policy, and that grants and Allows are monotone while the blocks only ever restrict.
- `S3PolicyCondition.tla`: the IAM condition operator algebra over every match relation: negation is the complement for plain operators, `IfExists` only changes the missing-key case, `ForAllValues`/`ForAnyValue` on empty sets, De Morgan duality between the set qualifiers and negation, value lists are disjunctions, and `Null` is a presence test.
- `S3ListPaging.tla`: the continuation-marker rules shared by ListObjects V1/V2, ListObjectVersions and ListMultipartUploads (common prefixes count toward max-keys; resuming after `(key, version)`). TLC checks that paging returns every entry exactly once, in order, sets IsTruncated exactly when entries remain, and terminates.

The implementation is tied to the models by Go tests that run the same rules against the real backend:

- `internal/backend/model_versioning_test.go`: a reference model of the versioning spec stepped in lockstep with the backend over random operation sequences (`TestVersioningModelRandomSequences`, `FuzzVersioningModel`).
- `internal/backend/paging_property_test.go`: page-by-page listings compared against an independent oracle (`TestListPagingProperties`, `FuzzListPagingProperties`).
- `internal/handler/authorization_model_test.go`: builds every request of the authorization model against a real bucket and compares the router's decision with the model (`TestAuthorizationModel`); `internal/handler/operations_test.go` checks the operation → IAM action table for every route and that exactly those actions decide each operation (`TestOperationTable`, `TestOperationAuthorizationMatrix`).
- `internal/backend/policy_model_test.go`: the policy and condition models transcribed in Go and compared against the real policy validator and evaluator for every single statement, every statement pair, and random long policies (`TestBucketPolicyModel*`, `TestPolicyConditionModel`).

Run everything with `task formal`, or only TLC with `formal/tla/check.sh`.

### `task s3-test` marker policy

By default, `task s3-test` excludes tests marked with `fails_on_aws` and `fails_on_rgw` via `PYTEST_ADDOPTS` in `integration/s3-test/compose.yaml`.

This keeps the default suite focused on AWS-compatible behavior and avoids known non-AWS/non-RGW expectation tests in daily runs.

To run the full suite (including those markers), run from `integration/s3-test`:

```bash
docker compose run --rm -e PYTEST_ADDOPTS="" s3tests
```

## Credits

[Miniredis](https://github.com/alicebob/miniredis) is a Redis test server, used in Go unittests. Minis3 is inspired by Miniredis.  
