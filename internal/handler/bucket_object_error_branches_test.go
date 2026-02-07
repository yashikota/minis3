package handler

import (
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestBucketErrorBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "bucket-errors")

	t.Run("list objects no such bucket", func(t *testing.T) {
		w1 := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing?list-type=2", "", nil),
		)
		requireStatus(t, w1, http.StatusNotFound)
		requireS3ErrorCode(t, w1, "NoSuchBucket")
		w2 := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing", "", nil),
		)
		requireStatus(t, w2, http.StatusNotFound)
		requireS3ErrorCode(t, w2, "NoSuchBucket")
		w3 := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing?versions", "", nil),
		)
		requireStatus(t, w3, http.StatusNotFound)
		requireS3ErrorCode(t, w3, "NoSuchBucket")
	})

	t.Run("versioning invalid status", func(t *testing.T) {
		payload := `<VersioningConfiguration><Status>Oops</Status></VersioningConfiguration>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/bucket-errors?versioning",
				payload,
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("versioning no such bucket", func(t *testing.T) {
		payload := `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
		w := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/missing?versioning", payload, nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
		w2 := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing?versioning", "", nil),
		)
		requireStatus(t, w2, http.StatusNotFound)
		requireS3ErrorCode(t, w2, "NoSuchBucket")
	})

	t.Run("location no such bucket", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing?location", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("tagging no such tag set and invalid tag", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?tagging", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchTagSet")
		bad := `<Tagging><TagSet><Tag><Key></Key><Value>v</Value></Tag></TagSet></Tagging>`
		wPut := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket-errors?tagging", bad, nil),
		)
		requireStatus(t, wPut, http.StatusBadRequest)
		requireS3ErrorCode(t, wPut, "InvalidTag")
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?tagging", "", nil),
		)
		requireStatus(t, wDel, http.StatusNotFound)
		requireS3ErrorCode(t, wDel, "NoSuchBucket")
	})

	t.Run("policy not found malformed and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?policy", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchBucketPolicy")
		wPutBad := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket-errors?policy", `{"bad":`, nil),
		)
		requireStatus(t, wPutBad, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutBad, "MalformedPolicy")
		wDel := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?policy", "", nil),
		)
		requireStatus(t, wDel, http.StatusNotFound)
		requireS3ErrorCode(t, wDel, "NoSuchBucket")
	})

	t.Run("acl errors", func(t *testing.T) {
		wGet := doRequest(h, newRequest(http.MethodGet, "http://example.test/missing?acl", "", nil))
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchBucket")
		wPutMalformed := doRequest(
			h,
			newRequest(http.MethodPut, "http://example.test/bucket-errors?acl", "<bad", nil),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedACLError")
	})

	t.Run("lifecycle missing config and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?lifecycle", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchLifecycleConfiguration")
		wPutMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing?lifecycle",
				`<LifecycleConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPutMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissing, "NoSuchBucket")
		wDelMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?lifecycle", "", nil),
		)
		requireStatus(t, wDelMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wDelMissing, "NoSuchBucket")
	})

	t.Run("encryption missing config and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?encryption", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "ServerSideEncryptionConfigurationNotFoundError")
		wPutMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing?encryption",
				`<ServerSideEncryptionConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPutMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissing, "NoSuchBucket")
		wDelMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?encryption", "", nil),
		)
		requireStatus(t, wDelMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wDelMissing, "NoSuchBucket")
	})

	t.Run("cors missing config and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?cors", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchCORSConfiguration")
		wPutMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing?cors",
				`<CORSConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPutMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissing, "NoSuchBucket")
		wDelMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?cors", "", nil),
		)
		requireStatus(t, wDelMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wDelMissing, "NoSuchBucket")
	})

	t.Run("website missing config and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/bucket-errors?website", "", nil),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchWebsiteConfiguration")
		wPutMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing?website",
				`<WebsiteConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPutMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissing, "NoSuchBucket")
		wDelMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?website", "", nil),
		)
		requireStatus(t, wDelMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wDelMissing, "NoSuchBucket")
	})

	t.Run("public access block missing config and missing bucket", func(t *testing.T) {
		wGet := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/bucket-errors?publicAccessBlock",
				"",
				nil,
			),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchPublicAccessBlockConfiguration")
		wPutMissing := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/missing?publicAccessBlock",
				`<PublicAccessBlockConfiguration/>`,
				nil,
			),
		)
		requireStatus(t, wPutMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wPutMissing, "NoSuchBucket")
		wDelMissing := doRequest(
			h,
			newRequest(http.MethodDelete, "http://example.test/missing?publicAccessBlock", "", nil),
		)
		requireStatus(t, wDelMissing, http.StatusNotFound)
		requireS3ErrorCode(t, wDelMissing, "NoSuchBucket")
	})
}

func TestObjectErrorBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj")
	mustPutObject(t, b, "obj", "k", "v")

	t.Run("get object acl errors", func(t *testing.T) {
		wBucket := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/missing/k?acl", "", nil),
		)
		requireStatus(t, wBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wBucket, "NoSuchBucket")
		wKey := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj/nope?acl", "", nil),
		)
		requireStatus(t, wKey, http.StatusNotFound)
		requireS3ErrorCode(t, wKey, "NoSuchKey")
		if err := b.SetBucketVersioning("obj", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		wVersion := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/obj/k?acl&versionId=missing", "", nil),
		)
		requireStatus(t, wVersion, http.StatusNotFound)
		requireS3ErrorCode(t, wVersion, "NoSuchVersion")
	})

	t.Run("object tagging version not found", func(t *testing.T) {
		payload := `<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`
		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj/k?tagging&versionId=missing",
				payload,
				nil,
			),
		)
		requireStatus(t, wPut, http.StatusNotFound)
		requireS3ErrorCode(t, wPut, "NoSuchVersion")
		wGet := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj/k?tagging&versionId=missing",
				"",
				nil,
			),
		)
		requireStatus(t, wGet, http.StatusNotFound)
		requireS3ErrorCode(t, wGet, "NoSuchVersion")
		wDel := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/obj/k?tagging&versionId=missing",
				"",
				nil,
			),
		)
		requireStatus(t, wDel, http.StatusNotFound)
		requireS3ErrorCode(t, wDel, "NoSuchVersion")
	})

	t.Run("get object attributes version not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/obj/k?attributes&versionId=missing",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})
}
