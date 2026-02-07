# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

This project uses [Task](https://taskfile.dev/) as the task runner (requires `task` CLI):

- `task lint` - Run golangci-lint with auto-fix and formatting
- `task test` - Run all tests
- `task unit-test` - Run unit test
- `task sdk-test` - Run sdk test
- `task s3-test` - Run s3-test (all tests via Docker Compose)
- `task s3-test-summary` - Show s3-test pass/fail/skip summary from log
- `go test -v -run TestName ./...` - Run a specific test

### Running Individual s3-tests

s3-test uses Docker Compose with Ceph s3-tests (pytest). To run individual tests:

```bash
cd integration/s3-test

# Start minis3 container first
docker compose up -d minis3

# Run a single test by name
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short s3tests/functional/test_s3.py::test_bucket_list_empty

# Run tests by marker (category)
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m tagging s3tests/functional/test_s3.py
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m copy s3tests/functional/test_s3.py
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m encryption s3tests/functional/test_s3.py
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m lifecycle s3tests/functional/test_s3.py
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m list_objects_v2 s3tests/functional/test_s3.py
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -m bucket_policy s3tests/functional/test_s3.py

# Run tests by keyword pattern
docker compose run --rm --entrypoint "" s3tests pytest -v --tb=short -k "test_copy" s3tests/functional/test_s3.py

# After testing, stop minis3
docker compose down
```

Note: When modifying minis3 source, rebuild with `docker compose build minis3` before re-running tests.

The project uses [aqua](https://aquaproj.github.io/) for tool management in CI.

## Architecture

Minis3 is an in-memory S3 mock server for Go unit tests, inspired by [miniredis](https://github.com/alicebob/miniredis).

### Core Structure

- `minis3.go` - Main server entry point. Creates HTTP server on random port, routes requests based on path:
  - `/` → ListBuckets (service-level)
  - `/bucket` → Bucket operations (PUT/DELETE/HEAD)
  - `/bucket/key` → Object operations (PUT/GET/DELETE/HEAD)

- `internal/backend/backend.go` - In-memory storage layer. Thread-safe (sync.RWMutex) maps holding buckets and objects.

- `internal/api/api.go` - S3 XML response types and error formatting helpers.

- `integration/` - Separate Go module with tests using the real AWS SDK v2 client.

### Usage Pattern

```go
server := minis3.New()
server.Start()
defer server.Close()
// Use server.Addr() as endpoint with path-style addressing
```

Must use `UsePathStyle = true` in AWS SDK client options (virtual-hosted style not supported).

## Supported S3 Operations

**Bucket Operations:** ListBuckets, CreateBucket, DeleteBucket, HeadBucket, GetBucketLocation, GetBucketVersioning, PutBucketVersioning, GetBucketTagging, PutBucketTagging, DeleteBucketTagging, GetBucketPolicy, PutBucketPolicy, DeleteBucketPolicy, GetBucketAcl, PutBucketAcl, GetObjectLockConfiguration, PutObjectLockConfiguration, GetBucketLifecycleConfiguration, PutBucketLifecycleConfiguration, DeleteBucketLifecycle, GetBucketEncryption, PutBucketEncryption, DeleteBucketEncryption, GetBucketCors, PutBucketCors, DeleteBucketCors, GetBucketWebsite, PutBucketWebsite, DeleteBucketWebsite, GetPublicAccessBlock, PutPublicAccessBlock, DeletePublicAccessBlock.

**Object Operations:** PutObject, GetObject (with Range header support), DeleteObject, HeadObject, CopyObject, DeleteObjects, ListObjects, ListObjectsV2, ListObjectVersions, GetObjectAcl, PutObjectAcl, GetObjectTagging, PutObjectTagging, DeleteObjectTagging, GetObjectAttributes.

**Conditional Headers:** If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since (for GetObject/HeadObject).

**Object Lock Operations:** GetObjectLockConfiguration, PutObjectLockConfiguration, GetObjectRetention, PutObjectRetention, GetObjectLegalHold, PutObjectLegalHold.

**Multipart Upload Operations:** CreateMultipartUpload, UploadPart, UploadPartCopy, CompleteMultipartUpload, AbortMultipartUpload, ListMultipartUploads, ListParts.

**Presigned URLs:** SigV4 / SigV2 presigned URL verification.

**Additional Features:**
- AWS chunked encoding
- Response header overrides (GetObject query params)
- Copy source conditional headers (x-amz-copy-source-if-match, etc.)
- Object Lock enforcement on delete (bypass-governance-retention)
- StorageClass support
- SSE header support (mock: store and return, no actual encryption)
- x-amz-request-id / x-amz-id-2 headers
- Metadata/Tagging directives in CopyObject
- Content-Type default to application/octet-stream
