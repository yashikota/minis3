package backend

import (
	"errors"
	"time"
)

// Sentinel errors for CopyObject
var (
	ErrSourceBucketNotFound      = errors.New("source bucket not found")
	ErrDestinationBucketNotFound = errors.New("destination bucket not found")
	ErrSourceObjectNotFound      = errors.New("source object not found")
)

// Bucket represents an S3 bucket
type Bucket struct {
	Name         string
	CreationDate time.Time
	Objects      map[string]*Object
}

// Object represents an S3 object
type Object struct {
	Key           string
	LastModified  time.Time
	ETag          string
	Size          int64
	ContentType   string
	Data          []byte
	ChecksumCRC32 string
}

// DeleteObjectResult represents the result of deleting a single object
type DeleteObjectResult struct {
	Key     string
	Deleted bool
	Error   error
}
