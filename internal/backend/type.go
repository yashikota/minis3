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

type DeleteObjectResult struct {
	Key     string
	Deleted bool
	Error   error
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
	XMLName             xml.Name        `xml:"ListVersionsResult"`
	Xmlns               string          `xml:"xmlns,attr,omitempty"`
	IsTruncated         bool            `xml:"IsTruncated"`
	KeyMarker           string          `xml:"KeyMarker"`
	VersionIdMarker     string          `xml:"VersionIdMarker"`
	NextKeyMarker       string          `xml:"NextKeyMarker,omitempty"`
	NextVersionIdMarker string          `xml:"NextVersionIdMarker,omitempty"`
	Versions            []VersionInfo   `xml:"Version,omitempty"`
	DeleteMarkers       []DeleteMarker  `xml:"DeleteMarker,omitempty"`
	Name                string          `xml:"Name"`
	Prefix              string          `xml:"Prefix"`
	Delimiter           string          `xml:"Delimiter,omitempty"`
	MaxKeys             int             `xml:"MaxKeys"`
	CommonPrefixes      []CommonPrefix  `xml:"CommonPrefixes,omitempty"`
	EncodingType        string          `xml:"EncodingType,omitempty"`
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
