package backend

import (
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"
)

// Backend holds the state of the S3 world.
type Backend struct {
	mu      sync.RWMutex
	buckets map[string]*Bucket
}

// Bucket represents an S3 bucket containing objects and metadata
type Bucket struct {
	Name         string
	CreationDate time.Time
	Objects      map[string]*Object
}

// Object represents an S3 object with its metadata and content
type Object struct {
	Key           string
	LastModified  time.Time
	ETag          string
	Size          int64
	ContentType   string
	Data          []byte
	ChecksumCRC32 string
}

var (
	ErrBucketNotFound            = errors.New("bucket not found")
	ErrBucketNotEmpty            = errors.New("bucket not empty")
	ErrBucketAlreadyExists       = errors.New("bucket already exists")
	ErrObjectNotFound            = errors.New("object not found")
	ErrSourceBucketNotFound      = errors.New("source bucket not found")
	ErrDestinationBucketNotFound = errors.New("destination bucket not found")
	ErrSourceObjectNotFound      = errors.New("source object not found")
)

func New() *Backend {
	return &Backend{
		buckets: make(map[string]*Bucket),
	}
}

func WriteError(w http.ResponseWriter, code int, s3Code, message string) {
	w.WriteHeader(code)
	// S3 errors are XML
	resp := ErrorResponse{
		Code:    s3Code,
		Message: message,
	}
	output, err := xml.Marshal(resp)
	if err != nil {
		log.Fatalln("Failed to marshal XML error response:", err)
		return
	}
	// Ignore write errors as we cannot recover from them here.
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(output)
}
