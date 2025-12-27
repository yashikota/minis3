package backend

import (
	"encoding/xml"
)

type ListAllMyBucketsResult struct {
	XMLName           xml.Name     `xml:"ListAllMyBucketsResult"`
	Owner             *Owner       `xml:"Owner"`
	Buckets           []BucketInfo `xml:"Buckets>Bucket"`
	ContinuationToken string       `xml:"ContinuationToken,omitempty"`
	Prefix            string       `xml:"Prefix,omitempty"`
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
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
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
	XMLName        xml.Name       `xml:"ListBucketResult"`
	Xmlns          string         `xml:"xmlns,attr,omitempty"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	KeyCount       int            `xml:"KeyCount"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Contents       []ObjectInfo   `xml:"Contents,omitempty"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
}

type ListObjectsV2Result struct {
	Objects        []*Object
	CommonPrefixes []string
	IsTruncated    bool
	KeyCount       int
}

type ObjectInfo struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
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
	XMLName     xml.Name `xml:"Grantee"`
	Xmlns       string   `xml:"xmlns:xsi,attr,omitempty"`
	Type        string   `xml:"xsi:type,attr"`
	ID          string   `xml:"ID,omitempty"`
	DisplayName string   `xml:"DisplayName,omitempty"`
	URI         string   `xml:"URI,omitempty"`
}

// CannedACL represents predefined ACL values.
type CannedACL string

const (
	ACLPrivate           CannedACL = "private"
	ACLPublicRead        CannedACL = "public-read"
	ACLPublicReadWrite   CannedACL = "public-read-write"
	ACLAuthenticatedRead CannedACL = "authenticated-read"
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
