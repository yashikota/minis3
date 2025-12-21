# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

This project uses [Task](https://taskfile.dev/) as the task runner (requires `task` CLI):

- `task lint` - Run golangci-lint with auto-fix and formatting
- `task test` - Run all tests
- `task unit-test` - Run unit test
- `task sdk-test` - Run sdk test
- `task s3-test` - Run s3-test
- `go test -v -run TestName ./...` - Run a specific test

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

ListBuckets, CreateBucket, DeleteBucket, HeadBucket, PutObject, GetObject, DeleteObject, HeadObject, CopyObject, DeleteObjects, ListObjects, ListObjectsV2.
