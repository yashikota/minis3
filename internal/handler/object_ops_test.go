package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestObjectDeleteObjectsHandler(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj-bucket")
	mustPutObject(t, b, "obj-bucket", "a.txt", "A")

	t.Run("malformed xml", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodPost, "http://example.test/obj-bucket?delete", "<bad", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("empty objects", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodPost, "http://example.test/obj-bucket?delete", `<Delete></Delete>`, nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("too many objects", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString(`<Delete>`)
		for i := 0; i < 1001; i++ {
			sb.WriteString(`<Object><Key>k</Key></Object>`)
		}
		sb.WriteString(`</Delete>`)
		w := doRequest(h, newRequest(http.MethodPost, "http://example.test/obj-bucket?delete", sb.String(), nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("bucket not found", func(t *testing.T) {
		body := `<Delete><Object><Key>a.txt</Key></Object></Delete>`
		w := doRequest(h, newRequest(http.MethodPost, "http://example.test/nope?delete", body, nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("success", func(t *testing.T) {
		body := `<Delete><Object><Key>a.txt</Key></Object></Delete>`
		w := doRequest(h, newRequest(http.MethodPost, "http://example.test/obj-bucket?delete", body, nil))
		requireStatus(t, w, http.StatusOK)
	})
}

func TestObjectCopyHandler(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src")
	mustCreateBucket(t, b, "dst")
	mustPutObject(t, b, "src", "key", "data")

	t.Run("invalid copy source encoding", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/new",
				"",
				map[string]string{"x-amz-copy-source": "%zz"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("invalid copy source format", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/new",
				"",
				map[string]string{"x-amz-copy-source": "/src"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("self copy without change", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src/key",
				"",
				map[string]string{"x-amz-copy-source": "/src/key"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidRequest")
	})

	t.Run("source key not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/new",
				"",
				map[string]string{"x-amz-copy-source": "/src/missing"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("copy success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/dst/copied",
				"",
				map[string]string{
					"x-amz-copy-source":       "/src/key",
					"x-amz-metadata-directive": "REPLACE",
					"Content-Type":             "text/plain",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
	})
}

func TestObjectACLAndTaggingHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "obj")
	mustPutObject(t, b, "obj", "k", "v")

	t.Run("put object acl malformed xml", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodPut, "http://example.test/obj/k?acl", "<bad", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedACLError")
	})

	t.Run("put object acl invalid canonical user", func(t *testing.T) {
		payload := `<AccessControlPolicy><Owner><ID>0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</ID></Owner><AccessControlList><Grant><Grantee xsi:type="CanonicalUser" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><ID>unknown</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`
		w := doRequest(h, newRequest(http.MethodPut, "http://example.test/obj/k?acl", payload, nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("put/get object acl success", func(t *testing.T) {
		wPut := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj/k?acl",
				"",
				map[string]string{"x-amz-acl": "public-read"},
			),
		)
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj/k?acl", "", nil))
		requireStatus(t, wGet, http.StatusOK)
	})

	t.Run("put object acl version not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/obj/k?acl&versionId=nope",
				"",
				map[string]string{"x-amz-acl": "private"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchVersion")
	})

	t.Run("tagging get not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj/missing?tagging", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("tagging put malformed xml", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodPut, "http://example.test/obj/k?tagging", "<bad", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("tagging put invalid tagset", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString(`<Tagging><TagSet>`)
		for i := 0; i < 11; i++ {
			sb.WriteString(fmt.Sprintf(`<Tag><Key>k%d</Key><Value>v</Value></Tag>`, i))
		}
		sb.WriteString(`</TagSet></Tagging>`)
		w := doRequest(h, newRequest(http.MethodPut, "http://example.test/obj/k?tagging", sb.String(), nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidTag")
	})

	t.Run("tagging put/get/delete success", func(t *testing.T) {
		payload := `<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`
		wPut := doRequest(h, newRequest(http.MethodPut, "http://example.test/obj/k?tagging", payload, nil))
		requireStatus(t, wPut, http.StatusOK)
		wGet := doRequest(h, newRequest(http.MethodGet, "http://example.test/obj/k?tagging", "", nil))
		requireStatus(t, wGet, http.StatusOK)
		wDel := doRequest(h, newRequest(http.MethodDelete, "http://example.test/obj/k?tagging", "", nil))
		requireStatus(t, wDel, http.StatusNoContent)
	})

	t.Run("direct error writers", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		h.writePutObjectACLError(w1, errors.New("boom"))
		requireStatus(t, w1, http.StatusInternalServerError)
		w2 := httptest.NewRecorder()
		h.writeObjectTaggingError(w2, errors.New("boom"))
		requireStatus(t, w2, http.StatusInternalServerError)
	})
}

func TestGetObjectAttributesHandler(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "attrs")
	mustPutObject(t, b, "attrs", "obj", "data")

	t.Run("missing attributes header", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/attrs/obj?attributes", "", nil))
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("bucket not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/nope/obj?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("key not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attrs/missing?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("success", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attrs/obj?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag,ObjectSize,StorageClass"},
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("delete marker", func(t *testing.T) {
		if err := b.SetBucketVersioning("attrs", backend.VersioningEnabled, backend.MFADeleteDisabled); err != nil {
			t.Fatalf("SetBucketVersioning failed: %v", err)
		}
		if _, err := b.DeleteObject("attrs", "obj", false); err != nil {
			t.Fatalf("DeleteObject failed: %v", err)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/attrs/obj?attributes",
				"",
				map[string]string{"x-amz-object-attributes": "ETag"},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})
}
