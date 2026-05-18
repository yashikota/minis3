package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzGetMultipartFormValue(f *testing.F) {
	f.Add("key", "value", "key")
	f.Add("Content-Type", "image/png", "content-type")
	f.Add("file", "data", "file")
	f.Add("", "", "missing")

	f.Fuzz(func(t *testing.T, fieldKey, fieldVal, searchKey string) {
		fields := map[string]string{}
		if fieldKey != "" {
			fields[fieldKey] = fieldVal
		}
		_ = getMultipartFormValue(fields, searchKey)
	})
}

func FuzzParseOptionalObjectAttributes(f *testing.F) {
	f.Add("ETag")
	f.Add("Checksum")
	f.Add("ObjectParts")
	f.Add("StorageClass")
	f.Add("ObjectSize")
	f.Add("ETag, Checksum, ObjectParts")
	f.Add("")

	f.Fuzz(func(t *testing.T, attrs string) {
		req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		if attrs != "" {
			req.Header.Set("x-amz-object-attributes", attrs)
		}
		_ = parseOptionalObjectAttributes(req)
	})
}

func FuzzQueryHasInsensitive(f *testing.F) {
	f.Add("uploadId", "uploads")
	f.Add("UploadId", "uploadid")
	f.Add("tagging", "TAGGING")
	f.Add("", "")
	f.Add("versioning", "versioning")

	f.Fuzz(func(t *testing.T, queryKey, searchKey string) {
		req, err := http.NewRequest(http.MethodGet, "/bucket/key", nil)
		if err != nil {
			return
		}
		if queryKey != "" {
			q := req.URL.Query()
			q.Set(queryKey, "")
			req.URL.RawQuery = q.Encode()
		}
		_ = queryHasInsensitive(req, searchKey)
	})
}
