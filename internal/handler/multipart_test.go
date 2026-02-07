package handler

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func mustPublicWriteBucket(t *testing.T, b *backend.Backend, name, owner string) {
	t.Helper()
	mustCreateBucket(t, b, name)
	b.SetBucketOwner(name, owner)
	if err := b.PutBucketACL(name, backend.CannedACLToPolicy("public-read-write")); err != nil {
		t.Fatalf("PutBucketACL(%q) failed: %v", name, err)
	}
}

func createMultipartUpload(
	t *testing.T,
	h *Handler,
	bucket, key string,
	headers map[string]string,
) (uploadID string) {
	t.Helper()
	req := newRequest(
		http.MethodPost,
		"http://example.test/"+bucket+"/"+key+"?uploads",
		"",
		headers,
	)
	w := doRequest(h, req)
	requireStatus(t, w, http.StatusOK)
	var resp backend.InitiateMultipartUploadResult
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse create multipart response: %v body=%s", err, w.Body.String())
	}
	if resp.UploadId == "" {
		t.Fatalf("empty upload id in response: %s", w.Body.String())
	}
	return resp.UploadId
}

func TestMultipartHandlers(t *testing.T) {
	h, b := newTestHandler(t)
	mustPublicWriteBucket(t, b, "mp-bucket", "minis3-access-key")
	mustPublicWriteBucket(t, b, "src-bucket", "minis3-access-key")
	mustPutObject(t, b, "src-bucket", "src-key", "hello-copy")

	t.Run("create multipart access denied", func(t *testing.T) {
		mustCreateBucket(t, b, "private-bucket")
		b.SetBucketOwner("private-bucket", "minis3-access-key")
		w := doRequest(
			h,
			newRequest(http.MethodPost, "http://example.test/private-bucket/key?uploads", "", nil),
		)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("create multipart invalid sse header", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/mp-bucket/key?uploads",
				"",
				map[string]string{
					"Authorization":                authHeader("minis3-access-key"),
					"x-amz-server-side-encryption": "invalid",
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("create multipart bucket not found", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				"http://example.test/no-such/key?uploads",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("upload part invalid part number", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/mp-bucket/key?uploadId=u&partNumber=0",
				"x",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("upload part no such upload", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/mp-bucket/key?uploadId=missing&partNumber=1",
				"x",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("upload part sse-c mismatch", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"ssec",
			map[string]string{
				"Authorization": authHeader("minis3-access-key"),
				"x-amz-server-side-encryption-customer-algorithm": "AES256",
				"x-amz-server-side-encryption-customer-key":       "c2VjcmV0",
				"x-amz-server-side-encryption-customer-key-md5":   "Xr4ilOzQ4PCOq3aQ0qbuaQ==",
			},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/ssec?uploadId=%s&partNumber=1",
					uploadID,
				),
				"part",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("complete multipart malformed xml", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"badxml",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/badxml?uploadId=%s", uploadID),
				"<broken",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "MalformedXML")
	})

	t.Run("complete multipart invalid part", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"invalidpart",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/invalidpart?uploadId=%s", uploadID),
				`<CompleteMultipartUpload></CompleteMultipartUpload>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidPart")
	})

	t.Run("complete multipart invalid part order", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"partorder",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w1 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/partorder?uploadId=%s&partNumber=1",
					uploadID,
				),
				"123456",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w1, http.StatusOK)
		etag1 := w1.Header().Get("ETag")
		w2 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/partorder?uploadId=%s&partNumber=2",
					uploadID,
				),
				strings.Repeat("2", 5*1024*1024),
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w2, http.StatusOK)
		etag2 := w2.Header().Get("ETag")
		complete := `<CompleteMultipartUpload>` +
			`<Part><PartNumber>2</PartNumber><ETag>` + etag2 + `</ETag></Part>` +
			`<Part><PartNumber>1</PartNumber><ETag>` + etag1 + `</ETag></Part>` +
			`</CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/partorder?uploadId=%s", uploadID),
				complete,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidPartOrder")
	})

	t.Run("complete multipart entity too small", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"toosmall",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w1 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/toosmall?uploadId=%s&partNumber=1",
					uploadID,
				),
				"small",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w1, http.StatusOK)
		etag1 := w1.Header().Get("ETag")
		w2 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/toosmall?uploadId=%s&partNumber=2",
					uploadID,
				),
				"last",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w2, http.StatusOK)
		etag2 := w2.Header().Get("ETag")
		complete := `<CompleteMultipartUpload>` +
			`<Part><PartNumber>1</PartNumber><ETag>` + etag1 + `</ETag></Part>` +
			`<Part><PartNumber>2</PartNumber><ETag>` + etag2 + `</ETag></Part>` +
			`</CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/toosmall?uploadId=%s", uploadID),
				complete,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "EntityTooSmall")
	})

	t.Run("complete multipart duplicate part number uses last entry", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"dupepart",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w1 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-bucket/dupepart?uploadId=%s&partNumber=1", uploadID),
				"BBBBBBBB",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w1, http.StatusOK)
		etagFirst := w1.Header().Get("ETag")

		w2 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-bucket/dupepart?uploadId=%s&partNumber=1", uploadID),
				"AAAAAAAA",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w2, http.StatusOK)
		etagLast := w2.Header().Get("ETag")

		complete := `<CompleteMultipartUpload>` +
			`<Part><PartNumber>1</PartNumber><ETag>` + etagFirst + `</ETag></Part>` +
			`<Part><PartNumber>1</PartNumber><ETag>` + etagLast + `</ETag></Part>` +
			`</CompleteMultipartUpload>`
		wComplete := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/dupepart?uploadId=%s", uploadID),
				complete,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wComplete, http.StatusOK)

		obj, err := b.GetObject("mp-bucket", "dupepart")
		if err != nil {
			t.Fatalf("GetObject failed: %v", err)
		}
		if got := string(obj.Data); got != "AAAAAAAA" {
			t.Fatalf("object data = %q, want %q", got, "AAAAAAAA")
		}
	})

	t.Run("complete multipart success", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"ok",
			map[string]string{
				"Authorization":                authHeader("minis3-access-key"),
				"x-amz-server-side-encryption": "AES256",
			},
		)
		w1 := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf("http://example.test/mp-bucket/ok?uploadId=%s&partNumber=1", uploadID),
				"single-part",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w1, http.StatusOK)
		etag := w1.Header().Get("ETag")
		complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + etag + `</ETag></Part></CompleteMultipartUpload>`
		w := doRequest(
			h,
			newRequest(
				http.MethodPost,
				fmt.Sprintf("http://example.test/mp-bucket/ok?uploadId=%s", uploadID),
				complete,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusOK)
		if got := w.Header().Get("x-amz-server-side-encryption"); got != "AES256" {
			t.Fatalf("x-amz-server-side-encryption = %q, want AES256", got)
		}
	})

	t.Run("abort multipart no such upload", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/mp-bucket/key?uploadId=nope",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("abort multipart success", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"abortme",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				fmt.Sprintf("http://example.test/mp-bucket/abortme?uploadId=%s", uploadID),
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, w, http.StatusNoContent)
	})

	t.Run("list multipart uploads invalid max", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/mp-bucket?uploads&max-uploads=-1",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list multipart uploads bucket not found", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/nope?uploads", "", nil))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})

	t.Run("list multipart uploads success", func(t *testing.T) {
		_ = createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"p/a",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		_ = createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"p/b",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/mp-bucket?uploads&prefix=p/&delimiter=/&max-uploads=1",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("list parts invalid marker", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/mp-bucket/key?uploadId=u&part-number-marker=bad",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list parts invalid max", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/mp-bucket/key?uploadId=u&max-parts=-1",
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("list parts no such upload", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/mp-bucket/key?uploadId=nope", "", nil),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("list parts success", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"listparts",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		for i := 1; i <= 2; i++ {
			w := doRequest(
				h,
				newRequest(
					http.MethodPut,
					fmt.Sprintf(
						"http://example.test/mp-bucket/listparts?uploadId=%s&partNumber=%d",
						uploadID,
						i,
					),
					strings.Repeat("x", i),
					map[string]string{"Authorization": authHeader("minis3-access-key")},
				),
			)
			requireStatus(t, w, http.StatusOK)
		}
		w := doRequest(
			h,
			newRequest(
				http.MethodGet,
				fmt.Sprintf(
					"http://example.test/mp-bucket/listparts?uploadId=%s&max-parts=1",
					uploadID,
				),
				"",
				nil,
			),
		)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("upload part copy invalid part number", func(t *testing.T) {
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/mp-bucket/dst?uploadId=u&partNumber=0",
				"",
				map[string]string{"x-amz-copy-source": "/src-bucket/src-key"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("upload part copy invalid source header", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"copybad",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/copybad?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{"x-amz-copy-source": "noslash"},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("upload part copy invalid range", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"copyrange",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/copyrange?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":           authHeader("minis3-access-key"),
					"x-amz-copy-source":       "/src-bucket/src-key",
					"x-amz-copy-source-range": "bytes=bad",
				},
			),
		)
		requireStatus(t, w, http.StatusBadRequest)
		requireS3ErrorCode(t, w, "InvalidArgument")
	})

	t.Run("upload part copy source key not found", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"copymiss",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/copymiss?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-bucket/missing",
				},
			),
		)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchKey")
	})

	t.Run("upload part copy range unsatisfiable", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"copyrange2",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/copyrange2?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":           authHeader("minis3-access-key"),
					"x-amz-copy-source":       "/src-bucket/src-key",
					"x-amz-copy-source-range": "bytes=100-200",
				},
			),
		)
		requireStatus(t, w, http.StatusRequestedRangeNotSatisfiable)
		requireS3ErrorCode(t, w, "InvalidRange")
	})

	t.Run("upload part copy success", func(t *testing.T) {
		uploadID := createMultipartUpload(
			t,
			h,
			"mp-bucket",
			"copyok",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		w := doRequest(
			h,
			newRequest(
				http.MethodPut,
				fmt.Sprintf(
					"http://example.test/mp-bucket/copyok?uploadId=%s&partNumber=1",
					uploadID,
				),
				"",
				map[string]string{
					"Authorization":     authHeader("minis3-access-key"),
					"x-amz-copy-source": "/src-bucket/src-key",
				},
			),
		)
		requireStatus(t, w, http.StatusOK)
	})
}

func TestMultipartHelperFunctions(t *testing.T) {
	t.Run("decode and parse copy source", func(t *testing.T) {
		info, err := decodeAndParseCopySource("/bucket/key%20name?versionId=v1")
		if err != nil {
			t.Fatalf("decodeAndParseCopySource error: %v", err)
		}
		if info.bucket != "bucket" || info.key != "key name" || info.versionId != "v1" {
			t.Fatalf("unexpected info: %+v", info)
		}
	})

	t.Run("decode and parse copy source invalid", func(t *testing.T) {
		if _, err := decodeAndParseCopySource("bucket-only"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("decodeURI and unhex", func(t *testing.T) {
		got, err := decodeURI("/a%2Fb%20c%zz")
		if err != nil {
			t.Fatalf("decodeURI error: %v", err)
		}
		if got != "/a/b c%zz" {
			t.Fatalf("decodeURI = %q", got)
		}
		if unhex('A') != 10 || unhex('f') != 15 || unhex('z') != -1 {
			t.Fatalf("unexpected unhex values")
		}
	})

	t.Run("trim leading slash and indexByte", func(t *testing.T) {
		if trimLeadingSlash("/abc") != "abc" || trimLeadingSlash("abc") != "abc" {
			t.Fatal("trimLeadingSlash failed")
		}
		if indexByte("abc", 'b') != 1 || indexByte("abc", 'z') != -1 {
			t.Fatal("indexByte failed")
		}
	})

	t.Run("parse byte range", func(t *testing.T) {
		if s, e, err := parseByteRange("bytes=1-3"); err != nil || s != 1 || e != 3 {
			t.Fatalf("parseByteRange valid failed: %d %d %v", s, e, err)
		}
		for _, in := range []string{"bad", "bytes=1", "bytes=a-1", "bytes=1-a", "bytes=3-1"} {
			if _, _, err := parseByteRange(in); err == nil {
				t.Fatalf("expected error for %q", in)
			}
		}
	})
}
