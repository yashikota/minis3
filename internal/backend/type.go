package backend

import (
	"encoding/xml"
	"time"
)

type ListAllMyBucketsResult struct {
	XMLName           xml.Name      `xml:"ListAllMyBucketsResult"`
	Owner             *Owner        `xml:"Owner"`
	Buckets           []BucketInfo  `xml:"Buckets>Bucket"`
	ContinuationToken string        `xml:"ContinuationToken,omitempty"`
	Prefix            string        `xml:"Prefix,omitempty"`
	Summary           *UsageSummary `xml:"Summary,omitempty"`
}

// UsageSummary contains RGW-style account usage quota information.
type UsageSummary struct {
	QuotaMaxBytes             string `xml:"QuotaMaxBytes"`
	QuotaMaxBuckets           string `xml:"QuotaMaxBuckets"`
	QuotaMaxObjCount          string `xml:"QuotaMaxObjCount"`
	QuotaMaxBytesPerBucket    string `xml:"QuotaMaxBytesPerBucket"`
	QuotaMaxObjCountPerBucket string `xml:"QuotaMaxObjCountPerBucket"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type BucketInfo struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListBucketsOptions contains options for listing buckets.
type ListBucketsOptions struct {
	Prefix            string
	MaxBuckets        int
	ContinuationToken string
}

// ListBucketsResult contains the result of listing buckets.
type ListBucketsResult struct {
	Buckets           []*Bucket
	ContinuationToken string
	IsTruncated       bool
}

type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

type DeleteRequest struct {
	XMLName xml.Name           `xml:"Delete"`
	Objects []ObjectIdentifier `xml:"Object"`
	Quiet   bool               `xml:"Quiet"`
}

type ObjectIdentifier struct {
	Key              string `xml:"Key"`
	VersionId        string `xml:"VersionId,omitempty"`
	ETag             string `xml:"ETag,omitempty"`
	LastModifiedTime string `xml:"LastModifiedTime,omitempty"`
	Size             *int64 `xml:"Size,omitempty"`
}

type DeleteResult struct {
	XMLName xml.Name        `xml:"DeleteResult"`
	Xmlns   string          `xml:"xmlns,attr,omitempty"`
	Deleted []DeletedObject `xml:"Deleted,omitempty"`
	Errors  []DeleteError   `xml:"Error,omitempty"`
}

type DeletedObject struct {
	Key                   string `xml:"Key"`
	VersionId             string `xml:"VersionId,omitempty"`
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionId string `xml:"DeleteMarkerVersionId,omitempty"`
}

type DeleteError struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
}

type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
	HostId    string   `xml:"HostId"` // optional but common
}

// DeleteObjectsResult represents the result of deleting a single object in batch delete.
type DeleteObjectsResult struct {
	Key                   string
	VersionId             string
	DeleteMarker          bool
	DeleteMarkerVersionId string
	Error                 error
}

type ListBucketV2Result struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Xmlns                 string         `xml:"xmlns,attr,omitempty"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	MaxKeys               int            `xml:"MaxKeys"`
	KeyCount              int            `xml:"KeyCount"`
	IsTruncated           bool           `xml:"IsTruncated"`
	ContinuationToken     *string        `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	Contents              []ObjectInfo   `xml:"Contents,omitempty"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
}

type ListObjectsV2Result struct {
	Objects               []*Object
	CommonPrefixes        []string
	IsTruncated           bool
	KeyCount              int
	NextContinuationToken string
}

type ObjectInfo struct {
	Key               string         `xml:"Key"`
	LastModified      string         `xml:"LastModified"`
	ETag              string         `xml:"ETag"`
	Size              int64          `xml:"Size"`
	StorageClass      string         `xml:"StorageClass"`
	Owner             *Owner         `xml:"Owner,omitempty"`
	ChecksumAlgorithm []string       `xml:"ChecksumAlgorithm,omitempty"`
	RestoreStatus     *RestoreStatus `xml:"RestoreStatus,omitempty"`
}

// RestoreStatus represents the restore status of an object (for optional object attributes).
type RestoreStatus struct {
	IsRestoreInProgress bool   `xml:"IsRestoreInProgress"`
	RestoreExpiryDate   string `xml:"RestoreExpiryDate,omitempty"`
}

// RestoreRequest represents the XML body for POST /{key}?restore.
type RestoreRequest struct {
	XMLName              xml.Name              `xml:"RestoreRequest"`
	Days                 int                   `xml:"Days,omitempty"`
	GlacierJobParameters *GlacierJobParameters `xml:"GlacierJobParameters,omitempty"`
}

// GlacierJobParameters configures the retrieval tier for GLACIER restores.
type GlacierJobParameters struct {
	Tier string `xml:"Tier"` // Standard, Expedited, Bulk
}

type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type ListBucketV1Result struct {
	XMLName        xml.Name       `xml:"ListBucketResult"`
	Xmlns          string         `xml:"xmlns,attr,omitempty"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Marker         string         `xml:"Marker"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	IsTruncated    bool           `xml:"IsTruncated"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	Contents       []ObjectInfo   `xml:"Contents,omitempty"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
}

type ListObjectsV1Result struct {
	Objects        []*Object
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string
}

// CreateBucketConfiguration represents the XML body for CreateBucket request.
type CreateBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint"`
	ObjectOwnership    string   `xml:"ObjectOwnership,omitempty"`
}

// OwnershipControls configures object ownership behavior for a bucket.
type OwnershipControls struct {
	XMLName xml.Name                `xml:"OwnershipControls"`
	Xmlns   string                  `xml:"xmlns,attr,omitempty"`
	Rules   []OwnershipControlsRule `xml:"Rule"`
}

// OwnershipControlsRule is a rule under OwnershipControls.
type OwnershipControlsRule struct {
	ObjectOwnership string `xml:"ObjectOwnership"`
}

// BucketLoggingStatus is the XML request/response for bucket logging.
type BucketLoggingStatus struct {
	XMLName        xml.Name        `xml:"BucketLoggingStatus"`
	Xmlns          string          `xml:"xmlns,attr,omitempty"`
	LoggingEnabled *LoggingEnabled `xml:"LoggingEnabled,omitempty"`
}

// LoggingEnabled configures server access logging destination.
type LoggingEnabled struct {
	TargetBucket          string                 `xml:"TargetBucket"`
	TargetPrefix          string                 `xml:"TargetPrefix"`
	LoggingType           string                 `xml:"LoggingType,omitempty"`
	ObjectRollTime        int                    `xml:"ObjectRollTime,omitempty"`
	RecordsBatchSize      int                    `xml:"RecordsBatchSize,omitempty"`
	Filter                *LoggingFilter         `xml:"Filter,omitempty"`
	TargetGrants          *TargetGrants          `xml:"TargetGrants,omitempty"`
	TargetObjectKeyFormat *TargetObjectKeyFormat `xml:"TargetObjectKeyFormat,omitempty"`
}

const (
	BucketLoggingTypeStandard = "Standard"
	BucketLoggingTypeJournal  = "Journal"
	DefaultObjectRollTime     = 5
)

type LoggingFilter struct {
	Key *LoggingKeyFilter `xml:"Key,omitempty"`
}

type LoggingKeyFilter struct {
	FilterRules []FilterRule `xml:"FilterRule,omitempty"`
}

type FilterRule struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

// TargetGrants groups optional grants under TargetGrants.
type TargetGrants struct {
	Grants []Grant `xml:"Grant,omitempty"`
}

// TargetObjectKeyFormat controls the log object key format.
type TargetObjectKeyFormat struct {
	SimplePrefix      *SimplePrefix      `xml:"SimplePrefix,omitempty"`
	PartitionedPrefix *PartitionedPrefix `xml:"PartitionedPrefix,omitempty"`
}

type SimplePrefix struct{}

type PartitionedPrefix struct {
	PartitionDateSource string `xml:"PartitionDateSource,omitempty"`
}

// ListVersionsResult is the XML response for ListObjectVersions.
// Field order matches AWS S3 API response structure.
type ListVersionsResult struct {
	XMLName             xml.Name       `xml:"ListVersionsResult"`
	Xmlns               string         `xml:"xmlns,attr,omitempty"`
	IsTruncated         bool           `xml:"IsTruncated"`
	KeyMarker           string         `xml:"KeyMarker"`
	VersionIdMarker     string         `xml:"VersionIdMarker"`
	NextKeyMarker       string         `xml:"NextKeyMarker,omitempty"`
	NextVersionIdMarker string         `xml:"NextVersionIdMarker,omitempty"`
	Versions            []VersionInfo  `xml:"Version,omitempty"`
	DeleteMarkers       []DeleteMarker `xml:"DeleteMarker,omitempty"`
	Name                string         `xml:"Name"`
	Prefix              string         `xml:"Prefix"`
	Delimiter           string         `xml:"Delimiter,omitempty"`
	MaxKeys             int            `xml:"MaxKeys"`
	CommonPrefixes      []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType        string         `xml:"EncodingType,omitempty"`
}

// VersionInfo represents a single version in ListObjectVersions.
type VersionInfo struct {
	Key          string `xml:"Key"`
	VersionId    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        *Owner `xml:"Owner,omitempty"`
}

// DeleteMarker represents a delete marker in ListObjectVersions.
type DeleteMarker struct {
	Key          string `xml:"Key"`
	VersionId    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	Owner        *Owner `xml:"Owner,omitempty"`
}

// VersioningConfiguration represents the XML body for PutBucketVersioning
// and the XML response for GetBucketVersioning.
type VersioningConfiguration struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	Xmlns     string   `xml:"xmlns,attr,omitempty"`
	Status    string   `xml:"Status,omitempty"`
	MFADelete string   `xml:"MfaDelete,omitempty"`
}

// RequestPaymentConfiguration is the XML body for bucket request payment APIs.
type RequestPaymentConfiguration struct {
	XMLName xml.Name `xml:"RequestPaymentConfiguration"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	Payer   string   `xml:"Payer"`
}

const (
	RequestPayerBucketOwner = "BucketOwner"
	RequestPayerRequester   = "Requester"
)

// ListObjectVersionsResult is the internal result for ListObjectVersions.
type ListObjectVersionsResult struct {
	Versions            []*Object
	DeleteMarkers       []*Object
	CommonPrefixes      []string
	IsTruncated         bool
	NextKeyMarker       string
	NextVersionIdMarker string
}

// LocationConstraint represents the response for GetBucketLocation.
// For us-east-1, the content is empty (null in S3 terms).
type LocationConstraint struct {
	XMLName            xml.Name `xml:"LocationConstraint"`
	Xmlns              string   `xml:"xmlns,attr,omitempty"`
	LocationConstraint string   `xml:",chardata"`
}

// Tag represents a single tag key-value pair.
type Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// Tagging represents the request/response for bucket tagging operations.
type Tagging struct {
	XMLName xml.Name `xml:"Tagging"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	TagSet  []Tag    `xml:"TagSet>Tag"`
}

// AccessControlPolicy represents an S3 ACL.
type AccessControlPolicy struct {
	XMLName           xml.Name          `xml:"AccessControlPolicy"`
	Xmlns             string            `xml:"xmlns,attr,omitempty"`
	XmlnsXsi          string            `xml:"xmlns:xsi,attr,omitempty"`
	Owner             *Owner            `xml:"Owner"`
	AccessControlList AccessControlList `xml:"AccessControlList"`
}

// AccessControlList contains the grants for an ACL.
type AccessControlList struct {
	Grants []Grant `xml:"Grant"`
}

// Grant represents a single permission grant.
type Grant struct {
	Grantee    *Grantee `xml:"Grantee"`
	Permission string   `xml:"Permission"`
}

// Grantee represents the entity receiving permission.
type Grantee struct {
	XMLName      xml.Name `xml:"Grantee"`
	Xmlns        string   `xml:"xmlns:xsi,attr,omitempty"`
	Type         string   `xml:"xsi:type,attr"`
	ID           string   `xml:"ID,omitempty"`
	DisplayName  string   `xml:"DisplayName,omitempty"`
	EmailAddress string   `xml:"EmailAddress,omitempty"`
	URI          string   `xml:"URI,omitempty"`
}

// CannedACL represents predefined ACL values.
type CannedACL string

const (
	ACLPrivate           CannedACL = "private"
	ACLPublicRead        CannedACL = "public-read"
	ACLPublicReadWrite   CannedACL = "public-read-write"
	ACLAuthenticatedRead CannedACL = "authenticated-read"
	ACLBucketOwnerRead   CannedACL = "bucket-owner-read"
	ACLBucketOwnerFull   CannedACL = "bucket-owner-full-control"
)

// ACL permission constants.
const (
	PermissionFullControl = "FULL_CONTROL"
	PermissionRead        = "READ"
	PermissionWrite       = "WRITE"
	PermissionReadACP     = "READ_ACP"
	PermissionWriteACP    = "WRITE_ACP"
)

// Well-known grantee URIs.
const (
	AllUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	AuthenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// MultipartUpload represents an in-progress multipart upload.
type MultipartUpload struct {
	UploadId             string
	Bucket               string
	Key                  string
	Initiator            *Owner
	Owner                *Owner
	Initiated            string // RFC3339 formatted time
	Parts                map[int]*PartInfo
	ContentType          string
	Metadata             map[string]string
	Tags                 map[string]string
	CacheControl         string
	Expires              *time.Time
	ContentEncoding      string
	ContentLanguage      string
	ContentDisposition   string
	RetentionMode        string
	RetainUntilDate      *time.Time
	LegalHoldStatus      string
	StorageClass         string
	ServerSideEncryption string
	SSEKMSKeyId          string
	SSECustomerAlgorithm string
	SSECustomerKeyMD5    string
	ChecksumAlgorithm    string
	ChecksumType         string
	ChecksumCRC32        string
	ChecksumCRC32C       string
	ChecksumCRC64NVME    string
	ChecksumSHA1         string
	ChecksumSHA256       string
}

// PartInfo represents an uploaded part.
type PartInfo struct {
	PartNumber        int
	ETag              string
	Size              int64
	Data              []byte
	LastModified      string // RFC3339 formatted time
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumCRC64NVME string
	ChecksumSHA1      string
	ChecksumSHA256    string
}

// InitiateMultipartUploadResult is the XML response for CreateMultipartUpload.
type InitiateMultipartUploadResult struct {
	XMLName           xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns             string   `xml:"xmlns,attr,omitempty"`
	Bucket            string   `xml:"Bucket"`
	Key               string   `xml:"Key"`
	UploadId          string   `xml:"UploadId"`
	ChecksumAlgorithm string   `xml:"ChecksumAlgorithm,omitempty"`
	ChecksumType      string   `xml:"ChecksumType,omitempty"`
}

// CompleteMultipartUploadRequest is the XML request for CompleteMultipartUpload.
type CompleteMultipartUploadRequest struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []CompletePart `xml:"Part"`
}

// CompletePart represents a part in CompleteMultipartUpload request.
type CompletePart struct {
	PartNumber        int    `xml:"PartNumber"`
	ETag              string `xml:"ETag"`
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
}

// CompleteMultipartUploadResult is the XML response for CompleteMultipartUpload.
type CompleteMultipartUploadResult struct {
	XMLName           xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns             string   `xml:"xmlns,attr,omitempty"`
	Location          string   `xml:"Location"`
	Bucket            string   `xml:"Bucket"`
	Key               string   `xml:"Key"`
	ETag              string   `xml:"ETag"`
	ChecksumCRC32     string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string   `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string   `xml:"ChecksumSHA256,omitempty"`
	ChecksumType      string   `xml:"ChecksumType,omitempty"`
}

// ListMultipartUploadsResult is the XML response for ListMultipartUploads.
type ListMultipartUploadsResult struct {
	XMLName            xml.Name       `xml:"ListMultipartUploadsResult"`
	Xmlns              string         `xml:"xmlns,attr,omitempty"`
	Bucket             string         `xml:"Bucket"`
	KeyMarker          string         `xml:"KeyMarker"`
	UploadIdMarker     string         `xml:"UploadIdMarker"`
	NextKeyMarker      string         `xml:"NextKeyMarker,omitempty"`
	NextUploadIdMarker string         `xml:"NextUploadIdMarker,omitempty"`
	MaxUploads         int            `xml:"MaxUploads"`
	IsTruncated        bool           `xml:"IsTruncated"`
	Uploads            []UploadInfo   `xml:"Upload,omitempty"`
	Prefix             string         `xml:"Prefix,omitempty"`
	Delimiter          string         `xml:"Delimiter,omitempty"`
	CommonPrefixes     []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType       string         `xml:"EncodingType,omitempty"`
}

// UploadInfo represents an upload in ListMultipartUploads response.
type UploadInfo struct {
	Key          string `xml:"Key"`
	UploadId     string `xml:"UploadId"`
	Initiator    *Owner `xml:"Initiator"`
	Owner        *Owner `xml:"Owner"`
	StorageClass string `xml:"StorageClass"`
	Initiated    string `xml:"Initiated"`
}

// ListPartsResult is the XML response for ListParts.
type ListPartsResult struct {
	XMLName              xml.Name   `xml:"ListPartsResult"`
	Xmlns                string     `xml:"xmlns,attr,omitempty"`
	Bucket               string     `xml:"Bucket"`
	Key                  string     `xml:"Key"`
	UploadId             string     `xml:"UploadId"`
	Initiator            *Owner     `xml:"Initiator"`
	Owner                *Owner     `xml:"Owner"`
	StorageClass         string     `xml:"StorageClass"`
	PartNumberMarker     int        `xml:"PartNumberMarker"`
	NextPartNumberMarker int        `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int        `xml:"MaxParts"`
	IsTruncated          bool       `xml:"IsTruncated"`
	Parts                []PartItem `xml:"Part,omitempty"`
}

// PartItem represents a part in ListParts response.
type PartItem struct {
	PartNumber        int    `xml:"PartNumber"`
	LastModified      string `xml:"LastModified"`
	ETag              string `xml:"ETag"`
	Size              int64  `xml:"Size"`
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
}

// ObjectLockConfiguration represents the bucket's Object Lock configuration.
type ObjectLockConfiguration struct {
	XMLName           xml.Name        `xml:"ObjectLockConfiguration"`
	Xmlns             string          `xml:"xmlns,attr,omitempty"`
	ObjectLockEnabled string          `xml:"ObjectLockEnabled,omitempty"`
	Rule              *ObjectLockRule `xml:"Rule,omitempty"`
}

// ObjectLockRule contains the default retention rule.
type ObjectLockRule struct {
	DefaultRetention *DefaultRetention `xml:"DefaultRetention,omitempty"`
}

// DefaultRetention represents the default retention settings.
type DefaultRetention struct {
	Mode  string `xml:"Mode,omitempty"` // GOVERNANCE or COMPLIANCE
	Days  int    `xml:"Days,omitempty"`
	Years int    `xml:"Years,omitempty"`
}

// ObjectLockRetention represents the retention settings for an object.
type ObjectLockRetention struct {
	XMLName         xml.Name `xml:"Retention"`
	Xmlns           string   `xml:"xmlns,attr,omitempty"`
	Mode            string   `xml:"Mode,omitempty"`
	RetainUntilDate string   `xml:"RetainUntilDate,omitempty"`
}

// ObjectLockLegalHold represents the legal hold status for an object.
type ObjectLockLegalHold struct {
	XMLName xml.Name `xml:"LegalHold"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	Status  string   `xml:"Status"` // ON or OFF
}

// S3Xmlns is the standard S3 XML namespace used in API responses.
const S3Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"

// XMLSchemaInstanceNS is the XML schema instance namespace for xsi:type attributes.
const XMLSchemaInstanceNS = "http://www.w3.org/2001/XMLSchema-instance"

// Object Lock mode constants.
const (
	RetentionModeGovernance = "GOVERNANCE"
	RetentionModeCompliance = "COMPLIANCE"
	LegalHoldStatusOn       = "ON"
	LegalHoldStatusOff      = "OFF"
)

// CopyPartResult is the XML response for UploadPartCopy.
type CopyPartResult struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// GetObjectAttributesResponse is the XML response for GetObjectAttributes.
type GetObjectAttributesResponse struct {
	XMLName      xml.Name                        `xml:"GetObjectAttributesResponse"`
	Xmlns        string                          `xml:"xmlns,attr,omitempty"`
	ETag         string                          `xml:"ETag,omitempty"`
	Checksum     *GetObjectAttributesChecksum    `xml:"Checksum,omitempty"`
	ObjectParts  *GetObjectAttributesObjectParts `xml:"ObjectParts,omitempty"`
	StorageClass string                          `xml:"StorageClass,omitempty"`
	ObjectSize   *int64                          `xml:"ObjectSize,omitempty"`
}

// GetObjectAttributesChecksum contains checksum information.
type GetObjectAttributesChecksum struct {
	ChecksumType      string `xml:"ChecksumType,omitempty"`
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
}

// GetObjectAttributesObjectParts contains multipart upload information.
type GetObjectAttributesObjectParts struct {
	IsTruncated          bool                          `xml:"IsTruncated"`
	MaxParts             int                           `xml:"MaxParts"`
	NextPartNumberMarker int                           `xml:"NextPartNumberMarker,omitempty"`
	PartNumberMarker     int                           `xml:"PartNumberMarker"`
	PartsCount           int                           `xml:"PartsCount,omitempty"`
	TotalPartsCount      int                           `xml:"TotalPartsCount,omitempty"`
	Parts                []GetObjectAttributesPartItem `xml:"Part,omitempty"`
}

// GetObjectAttributesPartItem represents a part in GetObjectAttributes response.
type GetObjectAttributesPartItem struct {
	PartNumber        int    `xml:"PartNumber"`
	Size              int64  `xml:"Size"`
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
}

// Object ownership mode constants.
const (
	ObjectOwnershipBucketOwnerEnforced  = "BucketOwnerEnforced"
	ObjectOwnershipBucketOwnerPreferred = "BucketOwnerPreferred"
	ObjectOwnershipObjectWriter         = "ObjectWriter"
)

// LifecycleConfiguration represents bucket lifecycle rules.
type LifecycleConfiguration struct {
	XMLName xml.Name        `xml:"LifecycleConfiguration"`
	Xmlns   string          `xml:"xmlns,attr,omitempty"`
	Rules   []LifecycleRule `xml:"Rule"`
}

// LifecycleRule represents a single lifecycle rule.
type LifecycleRule struct {
	ID                             string                          `xml:"ID,omitempty"`
	Status                         string                          `xml:"Status"` // Enabled or Disabled
	Prefix                         string                          `xml:"Prefix,omitempty"`
	Filter                         *LifecycleFilter                `xml:"Filter,omitempty"`
	Expiration                     *LifecycleExpiration            `xml:"Expiration,omitempty"`
	Transition                     []LifecycleTransition           `xml:"Transition,omitempty"`
	NoncurrentVersionExpiration    *NoncurrentVersionExpiration    `xml:"NoncurrentVersionExpiration,omitempty"`
	NoncurrentVersionTransition    []NoncurrentVersionTransition   `xml:"NoncurrentVersionTransition,omitempty"`
	AbortIncompleteMultipartUpload *AbortIncompleteMultipartUpload `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

// LifecycleFilter specifies which objects the rule applies to.
type LifecycleFilter struct {
	Prefix                string              `xml:"Prefix,omitempty"`
	Tag                   *Tag                `xml:"Tag,omitempty"`
	And                   *LifecycleFilterAnd `xml:"And,omitempty"`
	ObjectSizeGreaterThan int64               `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    int64               `xml:"ObjectSizeLessThan,omitempty"`
}

// LifecycleFilterAnd represents AND logic for filter conditions.
type LifecycleFilterAnd struct {
	Prefix                string `xml:"Prefix,omitempty"`
	Tags                  []Tag  `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan int64  `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    int64  `xml:"ObjectSizeLessThan,omitempty"`
}

// LifecycleExpiration defines when objects expire.
type LifecycleExpiration struct {
	Days                      int    `xml:"Days,omitempty"`
	Date                      string `xml:"Date,omitempty"`
	ExpiredObjectDeleteMarker bool   `xml:"ExpiredObjectDeleteMarker,omitempty"`
}

// LifecycleTransition defines when objects transition to a different storage class.
type LifecycleTransition struct {
	Days         int    `xml:"Days,omitempty"`
	Date         string `xml:"Date,omitempty"`
	StorageClass string `xml:"StorageClass"`
}

// NoncurrentVersionExpiration defines when noncurrent versions expire.
type NoncurrentVersionExpiration struct {
	NoncurrentDays          int `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions int `xml:"NewerNoncurrentVersions,omitempty"`
}

// NoncurrentVersionTransition defines when noncurrent versions transition.
type NoncurrentVersionTransition struct {
	NoncurrentDays          int    `xml:"NoncurrentDays,omitempty"`
	StorageClass            string `xml:"StorageClass"`
	NewerNoncurrentVersions int    `xml:"NewerNoncurrentVersions,omitempty"`
}

// AbortIncompleteMultipartUpload defines when incomplete multipart uploads are aborted.
type AbortIncompleteMultipartUpload struct {
	DaysAfterInitiation int `xml:"DaysAfterInitiation"`
}

// Lifecycle status constants.
const (
	LifecycleStatusEnabled  = "Enabled"
	LifecycleStatusDisabled = "Disabled"
)

// ServerSideEncryptionConfiguration represents bucket default encryption settings.
type ServerSideEncryptionConfiguration struct {
	XMLName xml.Name                   `xml:"ServerSideEncryptionConfiguration"`
	Xmlns   string                     `xml:"xmlns,attr,omitempty"`
	Rules   []ServerSideEncryptionRule `xml:"Rule"`
}

// ServerSideEncryptionRule represents a single encryption rule.
type ServerSideEncryptionRule struct {
	ApplyServerSideEncryptionByDefault *ServerSideEncryptionByDefault `xml:"ApplyServerSideEncryptionByDefault,omitempty"`
	BucketKeyEnabled                   bool                           `xml:"BucketKeyEnabled,omitempty"`
}

// ServerSideEncryptionByDefault represents the default encryption settings.
type ServerSideEncryptionByDefault struct {
	SSEAlgorithm   string `xml:"SSEAlgorithm"`             // AES256, aws:kms, aws:kms:dsse
	KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"` // Only for aws:kms
}

// SSE algorithm constants.
const (
	SSEAlgorithmAES256  = "AES256"
	SSEAlgorithmAWSKMS  = "aws:kms"
	SSEAlgorithmKMSDSSE = "aws:kms:dsse"
)

// CORSConfiguration represents bucket CORS settings.
type CORSConfiguration struct {
	XMLName   xml.Name   `xml:"CORSConfiguration"`
	Xmlns     string     `xml:"xmlns,attr,omitempty"`
	CORSRules []CORSRule `xml:"CORSRule"`
}

// CORSRule represents a single CORS rule.
type CORSRule struct {
	ID             string   `xml:"ID,omitempty"`
	AllowedHeaders []string `xml:"AllowedHeader,omitempty"`
	AllowedMethods []string `xml:"AllowedMethod"`
	AllowedOrigins []string `xml:"AllowedOrigin"`
	ExposeHeaders  []string `xml:"ExposeHeader,omitempty"`
	MaxAgeSeconds  int      `xml:"MaxAgeSeconds,omitempty"`
}

// WebsiteConfiguration represents bucket static website hosting settings.
type WebsiteConfiguration struct {
	XMLName               xml.Name               `xml:"WebsiteConfiguration"`
	Xmlns                 string                 `xml:"xmlns,attr,omitempty"`
	IndexDocument         *IndexDocument         `xml:"IndexDocument,omitempty"`
	ErrorDocument         *ErrorDocument         `xml:"ErrorDocument,omitempty"`
	RedirectAllRequestsTo *RedirectAllRequestsTo `xml:"RedirectAllRequestsTo,omitempty"`
	RoutingRules          []RoutingRule          `xml:"RoutingRules>RoutingRule,omitempty"`
}

// IndexDocument specifies the index document for the website.
type IndexDocument struct {
	Suffix string `xml:"Suffix"`
}

// ErrorDocument specifies the error document for the website.
type ErrorDocument struct {
	Key string `xml:"Key"`
}

// RedirectAllRequestsTo specifies redirect for all requests.
type RedirectAllRequestsTo struct {
	HostName string `xml:"HostName"`
	Protocol string `xml:"Protocol,omitempty"`
}

// RoutingRule represents a single routing rule.
type RoutingRule struct {
	Condition *RoutingRuleCondition `xml:"Condition,omitempty"`
	Redirect  *RoutingRuleRedirect  `xml:"Redirect"`
}

// RoutingRuleCondition specifies when a routing rule applies.
type RoutingRuleCondition struct {
	HttpErrorCodeReturnedEquals string `xml:"HttpErrorCodeReturnedEquals,omitempty"`
	KeyPrefixEquals             string `xml:"KeyPrefixEquals,omitempty"`
}

// RoutingRuleRedirect specifies where to redirect.
type RoutingRuleRedirect struct {
	HostName             string `xml:"HostName,omitempty"`
	HttpRedirectCode     string `xml:"HttpRedirectCode,omitempty"`
	Protocol             string `xml:"Protocol,omitempty"`
	ReplaceKeyPrefixWith string `xml:"ReplaceKeyPrefixWith,omitempty"`
	ReplaceKeyWith       string `xml:"ReplaceKeyWith,omitempty"`
}

// PublicAccessBlockConfiguration represents bucket public access block settings.
type PublicAccessBlockConfiguration struct {
	XMLName               xml.Name `xml:"PublicAccessBlockConfiguration"`
	Xmlns                 string   `xml:"xmlns,attr,omitempty"`
	BlockPublicAcls       bool     `xml:"BlockPublicAcls"`
	IgnorePublicAcls      bool     `xml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool     `xml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool     `xml:"RestrictPublicBuckets"`
}

// PolicyStatus represents bucket policy status (public/non-public).
type PolicyStatus struct {
	XMLName  xml.Name `xml:"PolicyStatus"`
	Xmlns    string   `xml:"xmlns,attr,omitempty"`
	IsPublic bool     `xml:"IsPublic"`
}

// PostBucketLoggingResult is the XML response for POST ?logging flush.
type PostBucketLoggingResult struct {
	XMLName              xml.Name `xml:"PostBucketLoggingResult"`
	Xmlns                string   `xml:"xmlns,attr,omitempty"`
	FlushedLoggingObject string   `xml:"FlushedLoggingObject"`
}

// PutBucketLoggingResult is the XML response for PUT ?logging extension output.
type PutBucketLoggingResult struct {
	XMLName              xml.Name `xml:"PutBucketLoggingOutput"`
	Xmlns                string   `xml:"xmlns,attr,omitempty"`
	FlushedLoggingObject string   `xml:"FlushedLoggingObject"`
}

// IsArchivedStorageClass returns true if the storage class is an archived tier.
func IsArchivedStorageClass(sc string) bool {
	return sc == "GLACIER" || sc == "DEEP_ARCHIVE"
}
