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
	Name             string
	CreationDate     time.Time
	VersioningStatus VersioningStatus // Versioning state (Unset, Enabled, Suspended)
	MFADelete        MFADeleteStatus  // MFA Delete configuration
	Objects          map[string]*ObjectVersions
	Location         string            // Region location constraint (empty = us-east-1)
	Tags             map[string]string // Bucket tags
	Policy           string            // Bucket policy (JSON)
	ACL              *AccessControlPolicy
}

// ObjectVersions holds all versions of an object.
type ObjectVersions struct {
	Versions []*Object // Most recent first (descending order by time)
}

// Object represents an S3 object with its metadata and content
type Object struct {
	Key            string
	VersionId      string // "null" for unversioned, generated ID for versioned
	IsLatest       bool
	IsDeleteMarker bool
	LastModified   time.Time
	ETag           string
	Size           int64
	ContentType    string
	Data           []byte // nil for DeleteMarker
	ChecksumCRC32  string
	ACL            *AccessControlPolicy
	// Metadata fields
	Metadata           map[string]string // x-amz-meta-* custom metadata
	CacheControl       string            // Cache-Control header
	Expires            *time.Time        // Expires header
	ContentEncoding    string            // Content-Encoding header
	ContentLanguage    string            // Content-Language header
	ContentDisposition string            // Content-Disposition header
}

// PutObjectOptions contains options for PutObject operation.
type PutObjectOptions struct {
	ContentType        string
	Metadata           map[string]string
	CacheControl       string
	Expires            *time.Time
	ContentEncoding    string
	ContentLanguage    string
	ContentDisposition string
}

var (
	ErrBucketNotFound            = errors.New("bucket not found")
	ErrBucketNotEmpty            = errors.New("bucket not empty")
	ErrBucketAlreadyExists       = errors.New("bucket already exists")
	ErrBucketAlreadyOwnedByYou   = errors.New("bucket already owned by you")
	ErrInvalidBucketName         = errors.New("invalid bucket name")
	ErrObjectNotFound            = errors.New("object not found")
	ErrSourceBucketNotFound      = errors.New("source bucket not found")
	ErrDestinationBucketNotFound = errors.New("destination bucket not found")
	ErrSourceObjectNotFound      = errors.New("source object not found")
	ErrVersionNotFound           = errors.New("version not found")
	ErrMethodNotAllowed          = errors.New("method not allowed")
	ErrMFADeleteRequired         = errors.New("MFA delete required")
	ErrNoSuchTagSet              = errors.New("the TagSet does not exist")
	ErrNoSuchBucketPolicy        = errors.New("the bucket policy does not exist")
	ErrMalformedPolicy           = errors.New("malformed policy document")
	ErrInvalidRequest            = errors.New("invalid request")
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
