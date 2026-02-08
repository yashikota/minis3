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
	uploads map[string]*MultipartUpload // key: uploadId
}

var (
	xmlMarshal = xml.Marshal
	logFatalf  = log.Fatalf
)

// Bucket represents an S3 bucket containing objects and metadata
type Bucket struct {
	Name                    string
	CreationDate            time.Time
	OwnerAccessKey          string           // Access key of the bucket creator
	VersioningStatus        VersioningStatus // Versioning state (Unset, Enabled, Suspended)
	MFADelete               MFADeleteStatus  // MFA Delete configuration
	Objects                 map[string]*ObjectVersions
	Location                string            // Region location constraint (empty = us-east-1)
	Tags                    map[string]string // Bucket tags
	Policy                  string            // Bucket policy (JSON)
	ACL                     *AccessControlPolicy
	ObjectOwnership         string // BucketOwnerEnforced, BucketOwnerPreferred, ObjectWriter
	RequestPaymentPayer     string // BucketOwner or Requester
	LoggingConfiguration    *BucketLoggingStatus
	LoggingConfigModifiedAt time.Time
	LoggingObjectKey        string
	LoggingLastEventAt      time.Time
	ObjectLockEnabled       bool                               // Whether object lock is enabled
	ObjectLockConfiguration *ObjectLockConfiguration           // Default object lock configuration
	LifecycleConfiguration  *LifecycleConfiguration            // Lifecycle rules
	EncryptionConfiguration *ServerSideEncryptionConfiguration // Default encryption settings
	CORSConfiguration       *CORSConfiguration                 // CORS rules
	WebsiteConfiguration    *WebsiteConfiguration              // Static website hosting settings
	PublicAccessBlock       *PublicAccessBlockConfiguration    // Public access block settings
}

// ObjectVersions holds all versions of an object.
type ObjectVersions struct {
	Versions []*Object // Most recent first (descending order by time)
}

// Object represents an S3 object with its metadata and content
type Object struct {
	Key               string
	VersionId         string // "null" for unversioned, generated ID for versioned
	IsLatest          bool
	IsDeleteMarker    bool
	LastModified      time.Time
	ETag              string
	Size              int64
	ContentType       string
	Data              []byte // nil for DeleteMarker
	ChecksumAlgorithm string // CRC32, CRC32C, SHA1, SHA256
	ChecksumType      string // FULL_OBJECT or COMPOSITE
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumCRC64NVME string
	ChecksumSHA1      string
	ChecksumSHA256    string
	Owner             *Owner
	ACL               *AccessControlPolicy
	Tags              map[string]string // Object tags
	// Metadata fields
	Metadata           map[string]string // x-amz-meta-* custom metadata
	CacheControl       string            // Cache-Control header
	Expires            *time.Time        // Expires header
	ContentEncoding    string            // Content-Encoding header
	ContentLanguage    string            // Content-Language header
	ContentDisposition string            // Content-Disposition header
	// Object Lock fields
	RetentionMode   string     // GOVERNANCE or COMPLIANCE
	RetainUntilDate *time.Time // Retention until date
	LegalHoldStatus string     // ON or OFF
	// Storage class
	StorageClass string // e.g., STANDARD, REDUCED_REDUNDANCY, etc.
	// Server-Side Encryption fields
	ServerSideEncryption string // AES256, aws:kms, etc.
	SSEKMSKeyId          string // KMS key ID (only for aws:kms)
	SSECustomerAlgorithm string // AES256 (for SSE-C)
	SSECustomerKeyMD5    string // MD5 of customer-provided key (for SSE-C)
	// Website redirect
	WebsiteRedirectLocation string // x-amz-website-redirect-location
	// Multipart part info (populated after CompleteMultipartUpload)
	Parts []ObjectPart
}

// ObjectPart represents a part of a multipart upload object.
type ObjectPart struct {
	PartNumber int
	Size       int64
	ETag       string
	// Part-level checksums for multipart objects.
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumCRC64NVME string
	ChecksumSHA1      string
	ChecksumSHA256    string
}

// PutObjectOptions contains options for PutObject operation.
type PutObjectOptions struct {
	ContentType             string
	Metadata                map[string]string
	Owner                   *Owner
	CacheControl            string
	Expires                 *time.Time
	ContentEncoding         string
	ContentLanguage         string
	ContentDisposition      string
	Tags                    map[string]string // Inline tags from x-amz-tagging header
	RetentionMode           string            // Object Lock retention mode (GOVERNANCE or COMPLIANCE)
	RetainUntilDate         *time.Time        // Object Lock retain until date
	LegalHoldStatus         string            // Object Lock legal hold (ON or OFF)
	StorageClass            string            // Storage class (e.g., STANDARD)
	ServerSideEncryption    string            // Server-side encryption algorithm
	SSEKMSKeyId             string            // KMS key ID for SSE-KMS
	SSECustomerAlgorithm    string            // AES256 (for SSE-C)
	SSECustomerKeyMD5       string            // MD5 of customer-provided key (for SSE-C)
	WebsiteRedirectLocation string            // x-amz-website-redirect-location
	ChecksumAlgorithm       string            // CRC32, CRC32C, SHA1, SHA256
	ChecksumCRC32           string            // Client-provided CRC32 checksum
	ChecksumCRC32C          string            // Client-provided CRC32C checksum
	ChecksumCRC64NVME       string            // Client-provided CRC64NVME checksum
	ChecksumSHA1            string            // Client-provided SHA1 checksum
	ChecksumSHA256          string            // Client-provided SHA256 checksum
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
	ErrNoSuchUpload              = errors.New("the specified upload does not exist")
	ErrInvalidPart               = errors.New(
		"one or more of the specified parts could not be found",
	)
	ErrInvalidPartOrder = errors.New("the list of parts was not in ascending order")
	ErrEntityTooSmall   = errors.New(
		"your proposed upload is smaller than the minimum allowed object size",
	)
	ErrObjectLockNotEnabled = errors.New(
		"object lock is not enabled for this bucket",
	)
	ErrNoSuchObjectLockConfig = errors.New(
		"the object lock configuration does not exist",
	)
	ErrObjectLocked            = errors.New("object is locked")
	ErrInvalidObjectLockConfig = errors.New(
		"invalid object lock configuration",
	)
	ErrInvalidRetentionPeriod = errors.New(
		"the retention period must be extended, not shortened",
	)
	ErrInvalidRange = errors.New(
		"the requested range is not satisfiable",
	)
	ErrNoSuchLifecycleConfiguration = errors.New(
		"the lifecycle configuration does not exist",
	)
	ErrServerSideEncryptionConfigurationNotFound = errors.New(
		"the server side encryption configuration was not found",
	)
	ErrNoSuchCORSConfiguration = errors.New(
		"the CORS configuration does not exist",
	)
	ErrNoSuchWebsiteConfiguration = errors.New(
		"the website configuration does not exist",
	)
	ErrNoSuchPublicAccessBlockConfiguration = errors.New(
		"the public access block configuration was not found",
	)
	ErrOwnershipControlsNotFound = errors.New(
		"the ownership controls were not found",
	)
	ErrAccessControlListNotSupported = errors.New(
		"the bucket does not allow ACLs",
	)
	ErrPreconditionFailed = errors.New("precondition failed")
	ErrBadDigest          = errors.New("the content-md5 you specified did not match what we received")
)

func New() *Backend {
	return &Backend{
		buckets: make(map[string]*Bucket),
		uploads: make(map[string]*MultipartUpload),
	}
}

func WriteError(w http.ResponseWriter, code int, s3Code, message string) {
	w.WriteHeader(code)
	// S3 errors are XML
	resp := ErrorResponse{
		Code:      s3Code,
		Message:   message,
		RequestID: w.Header().Get("x-amz-request-id"),
		HostId:    w.Header().Get("x-amz-id-2"),
	}
	output, err := xmlMarshal(resp)
	if err != nil {
		logFatalf("Failed to marshal XML error response: %v", err)
		return
	}
	// Ignore write errors as we cannot recover from them here.
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(output)
}
