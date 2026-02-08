package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestMultipartAdditionalBranchesWithHooks(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "mp-hook")

	restoreCreate := createMultipartUploadFn
	restoreUploadPart := uploadPartFn
	restoreComplete := completeMultipartUploadFn
	restoreGetObject := getObjectForMultipartCompletionFn
	restoreAbort := abortMultipartUploadFn
	restoreListUploads := listMultipartUploadsFn
	restoreListParts := listPartsFn
	restoreCopyPart := copyPartFn
	restoreDecodeURI := decodeURIFn
	t.Cleanup(func() {
		createMultipartUploadFn = restoreCreate
		uploadPartFn = restoreUploadPart
		completeMultipartUploadFn = restoreComplete
		getObjectForMultipartCompletionFn = restoreGetObject
		abortMultipartUploadFn = restoreAbort
		listMultipartUploadsFn = restoreListUploads
		listPartsFn = restoreListParts
		copyPartFn = restoreCopyPart
		decodeURIFn = restoreDecodeURI
	})

	t.Run("create multipart consumes legal-hold and storage-class headers", func(t *testing.T) {
		req := newRequest(
			http.MethodPost,
			"http://example.test/mp-hook/k?uploads",
			"",
			map[string]string{
				"x-amz-object-lock-legal-hold": "ON",
				"x-amz-storage-class":          "STANDARD_IA",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("create multipart unexpected backend error", func(t *testing.T) {
		createMultipartUploadFn = func(
			*Handler,
			string,
			string,
			backend.CreateMultipartUploadOptions,
		) (*backend.MultipartUpload, error) {
			return nil, errors.New("create boom")
		}
		req := newRequest(
			http.MethodPost,
			"http://example.test/mp-hook/create-err?uploads",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		createMultipartUploadFn = restoreCreate
	})

	t.Run("upload part invalid sse-c headers", func(t *testing.T) {
		up, err := b.CreateMultipartUpload(
			"mp-hook",
			"sse-invalid",
			backend.CreateMultipartUploadOptions{},
		)
		if err != nil {
			t.Fatalf("CreateMultipartUpload failed: %v", err)
		}
		req := newRequest(
			http.MethodPut,
			"http://example.test/mp-hook/sse-invalid?uploadId="+up.UploadId+"&partNumber=1",
			"part",
			map[string]string{"x-amz-server-side-encryption-customer-algorithm": "AES256"},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusBadRequest)
	})

	t.Run("upload part unexpected backend error", func(t *testing.T) {
		uploadPartFn = func(
			*Handler,
			string,
			string,
			string,
			int,
			[]byte,
		) (*backend.PartInfo, error) {
			return nil, errors.New("upload part boom")
		}
		req := newRequest(
			http.MethodPut,
			"http://example.test/mp-hook/up-err?uploadId=u&partNumber=1",
			"part",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		uploadPartFn = restoreUploadPart
	})

	t.Run("complete multipart idempotent no-such-upload fallback", func(t *testing.T) {
		completeMultipartUploadFn = func(
			*Handler,
			string,
			string,
			string,
			[]backend.CompletePart,
		) (*backend.Object, error) {
			return nil, backend.ErrNoSuchUpload
		}
		getObjectForMultipartCompletionFn = func(*Handler, string, string) (*backend.Object, error) {
			return &backend.Object{ETag: "\"etag-idempotent\""}, nil
		}
		body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`
		req := newRequest(
			http.MethodPost,
			"http://example.test/mp-hook/complete-idempotent?uploadId=gone",
			body,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		completeMultipartUploadFn = restoreComplete
		getObjectForMultipartCompletionFn = restoreGetObject
	})

	t.Run("complete multipart unexpected backend error", func(t *testing.T) {
		completeMultipartUploadFn = func(
			*Handler,
			string,
			string,
			string,
			[]backend.CompletePart,
		) (*backend.Object, error) {
			return nil, errors.New("complete boom")
		}
		body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`
		req := newRequest(
			http.MethodPost,
			"http://example.test/mp-hook/complete-err?uploadId=gone",
			body,
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		completeMultipartUploadFn = restoreComplete
	})

	t.Run("abort multipart unexpected backend error", func(t *testing.T) {
		abortMultipartUploadFn = func(*Handler, string, string, string) error {
			return errors.New("abort boom")
		}
		req := newRequest(
			http.MethodDelete,
			"http://example.test/mp-hook/abort-err?uploadId=u",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		abortMultipartUploadFn = restoreAbort
	})

	t.Run("list multipart uploads unexpected backend error", func(t *testing.T) {
		listMultipartUploadsFn = func(
			*Handler,
			string,
			backend.ListMultipartUploadsOptions,
		) (*backend.ListMultipartUploadsInternalResult, error) {
			return nil, errors.New("list uploads boom")
		}
		req := newRequest(http.MethodGet, "http://example.test/mp-hook?uploads", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		listMultipartUploadsFn = restoreListUploads
	})

	t.Run("list multipart uploads defaults owner and includes common prefixes", func(t *testing.T) {
		listMultipartUploadsFn = func(
			*Handler,
			string,
			backend.ListMultipartUploadsOptions,
		) (*backend.ListMultipartUploadsInternalResult, error) {
			return &backend.ListMultipartUploadsInternalResult{
				Uploads: []*backend.MultipartUpload{{
					Key:      "k",
					UploadId: "u",
				}},
				CommonPrefixes: []string{"prefix/"},
			}, nil
		}
		req := newRequest(http.MethodGet, "http://example.test/mp-hook?uploads", "", nil)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		listMultipartUploadsFn = restoreListUploads
	})

	t.Run("list parts parses part-number-marker", func(t *testing.T) {
		req := newRequest(
			http.MethodGet,
			"http://example.test/mp-hook/p?uploadId=nope&part-number-marker=2",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchUpload")
	})

	t.Run("list parts unexpected backend error", func(t *testing.T) {
		listPartsFn = func(
			*Handler,
			string,
			string,
			string,
			backend.ListPartsOptions,
		) (*backend.ListPartsInternalResult, *backend.MultipartUpload, error) {
			return nil, nil, errors.New("list parts boom")
		}
		req := newRequest(
			http.MethodGet,
			"http://example.test/mp-hook/p?uploadId=u",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		listPartsFn = restoreListParts
	})

	t.Run("list parts defaults owner and initiator", func(t *testing.T) {
		listPartsFn = func(
			*Handler,
			string,
			string,
			string,
			backend.ListPartsOptions,
		) (*backend.ListPartsInternalResult, *backend.MultipartUpload, error) {
			return &backend.ListPartsInternalResult{
					Parts: []*backend.PartInfo{{
						PartNumber: 1,
						ETag:       "\"etag\"",
						Size:       1,
					}},
				}, &backend.MultipartUpload{
					StorageClass: "STANDARD",
				}, nil
		}
		req := newRequest(
			http.MethodGet,
			"http://example.test/mp-hook/p?uploadId=u",
			"",
			nil,
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusOK)
		listPartsFn = restoreListParts
	})

	t.Run("copy part unexpected backend error", func(t *testing.T) {
		mustCreateBucket(t, b, "src-b")
		mustPutObject(t, b, "src-b", "src-k", "v")
		if err := b.PutObjectACL("src-b", "src-k", "", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		copyPartFn = func(
			*Handler,
			string,
			string,
			string,
			string,
			string,
			string,
			int,
			int64,
			int64,
		) (*backend.PartInfo, error) {
			return nil, errors.New("copy part boom")
		}
		req := newRequest(
			http.MethodPut,
			"http://example.test/mp-hook/dst?uploadId=u&partNumber=1",
			"",
			map[string]string{
				"Authorization":     authHeader("minis3-access-key"),
				"x-amz-copy-source": "/src-b/src-k",
			},
		)
		w := doRequest(h, req)
		requireStatus(t, w, http.StatusInternalServerError)
		requireS3ErrorCode(t, w, "InternalError")
		copyPartFn = restoreCopyPart
	})

	t.Run("decodeAndParseCopySource decode error branch", func(t *testing.T) {
		decodeURIFn = func(string) (string, error) {
			return "", errors.New("decode boom")
		}
		if _, err := decodeAndParseCopySource("/bucket/key"); err == nil {
			t.Fatal("decodeAndParseCopySource should fail when decode fails")
		}
		decodeURIFn = restoreDecodeURI
	})

	t.Run("parseByteRange invalid prefix", func(t *testing.T) {
		if _, _, err := parseByteRange("units=0-10"); err == nil {
			t.Fatal("parseByteRange should fail for invalid prefix")
		}
	})
}
