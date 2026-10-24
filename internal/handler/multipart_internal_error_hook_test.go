package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestMultipartAdditionalBranchesWithHooks(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateObjectLockBucket(t, b, "mp-hook")

	restoreCreate := h.hooks.createMultipartUpload
	restoreUploadPart := h.hooks.uploadPart
	restoreComplete := h.hooks.completeMultipartUpload
	restoreGetObject := h.hooks.getObjectForMultipartCompletion
	restoreCompleted := h.hooks.getCompletedUploadObject
	restoreAbort := h.hooks.abortMultipartUpload
	restoreListUploads := h.hooks.listMultipartUploads
	restoreListParts := h.hooks.listParts
	restoreCopyPart := h.hooks.copyPart
	restoreDecodeURI := h.hooks.decodeURI
	t.Cleanup(func() {
		h.hooks.createMultipartUpload = restoreCreate
		h.hooks.uploadPart = restoreUploadPart
		h.hooks.completeMultipartUpload = restoreComplete
		h.hooks.getObjectForMultipartCompletion = restoreGetObject
		h.hooks.getCompletedUploadObject = restoreCompleted
		h.hooks.abortMultipartUpload = restoreAbort
		h.hooks.listMultipartUploads = restoreListUploads
		h.hooks.listParts = restoreListParts
		h.hooks.copyPart = restoreCopyPart
		h.hooks.decodeURI = restoreDecodeURI
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
		h.hooks.createMultipartUpload = func(
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
		h.hooks.createMultipartUpload = restoreCreate
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
		h.hooks.uploadPart = func(
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
		h.hooks.uploadPart = restoreUploadPart
	})

	t.Run("complete multipart idempotent no-such-upload fallback", func(t *testing.T) {
		h.hooks.completeMultipartUpload = func(
			*Handler,
			string,
			string,
			string,
			[]backend.CompletePart,
		) (*backend.Object, error) {
			return nil, backend.ErrNoSuchUpload
		}
		h.hooks.getCompletedUploadObject = func(*Handler, string, string, string) (*backend.Object, bool) {
			return &backend.Object{ETag: "\"etag-idempotent\""}, true
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
		h.hooks.completeMultipartUpload = restoreComplete
		h.hooks.getCompletedUploadObject = restoreCompleted
	})

	t.Run("complete multipart unexpected backend error", func(t *testing.T) {
		h.hooks.completeMultipartUpload = func(
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
		h.hooks.completeMultipartUpload = restoreComplete
	})

	t.Run("abort multipart unexpected backend error", func(t *testing.T) {
		h.hooks.abortMultipartUpload = func(*Handler, string, string, string) error {
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
		h.hooks.abortMultipartUpload = restoreAbort
	})

	t.Run("list multipart uploads unexpected backend error", func(t *testing.T) {
		h.hooks.listMultipartUploads = func(
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
		h.hooks.listMultipartUploads = restoreListUploads
	})

	t.Run("list multipart uploads defaults owner and includes common prefixes", func(t *testing.T) {
		h.hooks.listMultipartUploads = func(
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
		h.hooks.listMultipartUploads = restoreListUploads
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
		h.hooks.listParts = func(
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
		h.hooks.listParts = restoreListParts
	})

	t.Run("list parts defaults owner and initiator", func(t *testing.T) {
		h.hooks.listParts = func(
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
		h.hooks.listParts = restoreListParts
	})

	t.Run("copy part unexpected backend error", func(t *testing.T) {
		mustCreateBucket(t, b, "src-b")
		mustPutObject(t, b, "src-b", "src-k", "v")
		if err := b.PutObjectACL(
			"src-b",
			"src-k",
			"",
			backend.CannedACLToPolicy("public-read"),
		); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		h.hooks.copyPart = func(
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
		h.hooks.copyPart = restoreCopyPart
	})

	t.Run("decodeAndParseCopySource decode error branch", func(t *testing.T) {
		h.hooks.decodeURI = func(string) (string, error) {
			return "", errors.New("decode boom")
		}
		if _, err := h.decodeAndParseCopySource("/bucket/key"); err == nil {
			t.Fatal("decodeAndParseCopySource should fail when decode fails")
		}
		h.hooks.decodeURI = restoreDecodeURI
	})

	t.Run("parseByteRange invalid prefix", func(t *testing.T) {
		if _, _, err := parseByteRange("units=0-10"); err == nil {
			t.Fatal("parseByteRange should fail for invalid prefix")
		}
	})
}

// TestCompleteMultipartUploadObjectLockMapping covers the CompleteMultipartUpload
// mapping of backend.ErrInvalidRequest (retention set on an upload whose bucket
// has no Object Lock configuration) to 400 InvalidRequest.
func TestCompleteMultipartUploadObjectLockMapping(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	restoreComplete := h.hooks.completeMultipartUpload
	t.Cleanup(func() {
		h.hooks.completeMultipartUpload = restoreComplete
	})
	h.hooks.completeMultipartUpload = func(
		*Handler,
		string,
		string,
		string,
		[]backend.CompletePart,
	) (*backend.Object, error) {
		return nil, backend.ErrInvalidRequest
	}

	body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"x"</ETag></Part></CompleteMultipartUpload>`
	w := doRequest(
		h,
		newRequest(
			http.MethodPost,
			"http://example.test/mp-hook/no-lock-complete?uploadId=u",
			body,
			nil,
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidRequest")
}
