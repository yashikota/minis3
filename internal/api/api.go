package api

import (
	"encoding/xml"
	"net/http"
)

// XML structs for S3 responses
type ListAllMyBucketsResult struct {
	XMLName xml.Name     `xml:"ListAllMyBucketsResult"`
	Owner   *Owner       `xml:"Owner"`
	Buckets []BucketInfo `xml:"Buckets>Bucket"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type BucketInfo struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// CopyObjectResult is the response for CopyObject
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// ErrorResponse is the standard S3 error response
type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
	HostId    string   `xml:"HostId"` // optional but common
}

func WriteError(w http.ResponseWriter, code int, s3Code, message string) {
	w.WriteHeader(code)
	// S3 errors are XML
	resp := ErrorResponse{
		Code:    s3Code,
		Message: message,
	}
	output, _ := xml.Marshal(resp)
	// Ignore write errors as we cannot recover from them here.
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(output)
}
