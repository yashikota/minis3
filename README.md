# minis3

Sometimes you want to test code which uses S3, without making it a full-blown integration test. Minis3 implements (parts of) the S3 server, to be used in unittests. It enables a simple, cheap, in-memory, S3 replacement, with a real TCP interface. Think of it as the S3 version of `net/http/httptest`  

## Commands

| Method | Status |
| ------- | ------ |
| ListBuckets | ✅ |
| CreateBucket | ✅ |
| DeleteBucket | ✅ |
| PutObject | ✅ |
| GetObject | ✅ |
| DeleteObject | ✅ |
| CopyObject | ⌛ |
| HeadBucket | ✅ |
| HeadObject | ✅ |
| ListObjectsV2 | ⌛ |

## Installation

```bash
go get github.com/yashikota/minis3
```

## Usage


See the `example/` directory for a complete example.

```go
s := minis3.New()
s.Start()
defer s.Close()

// Use s.Addr() to configure your S3 client
```

## Credits

[Miniredis](https://github.com/bsm/miniredis) is a Redis test server, used in Go unittests. Minis3 is inspired by Miniredis.
