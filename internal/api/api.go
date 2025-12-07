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
	w.Write([]byte(xml.Header))
	w.Write(output)
}
