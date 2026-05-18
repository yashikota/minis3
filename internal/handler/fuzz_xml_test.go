package handler

import (
	"encoding/xml"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzXMLObjectLockConfiguration(f *testing.F) {
	f.Add([]byte(`<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`))
	f.Add([]byte(`<ObjectLockConfiguration></ObjectLockConfiguration>`))
	f.Add([]byte(`not xml`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var config backend.ObjectLockConfiguration
		_ = xml.Unmarshal(data, &config)
	})
}

func FuzzXMLDeleteRequest(f *testing.F) {
	f.Add([]byte(`<Delete><Object><Key>test</Key></Object></Delete>`))
	f.Add([]byte(`<Delete><Quiet>true</Quiet></Delete>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req backend.DeleteRequest
		_ = xml.Unmarshal(data, &req)
	})
}

func FuzzXMLCompleteMultipartUpload(f *testing.F) {
	f.Add([]byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"abc"</ETag></Part></CompleteMultipartUpload>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req backend.CompleteMultipartUploadRequest
		_ = xml.Unmarshal(data, &req)
	})
}

func FuzzXMLTagging(f *testing.F) {
	f.Add([]byte(`<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var tagging backend.Tagging
		_ = xml.Unmarshal(data, &tagging)
	})
}
