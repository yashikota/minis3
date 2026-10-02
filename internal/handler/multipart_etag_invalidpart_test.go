package handler

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

// TestCompleteMultipartUploadNonHexETagIsInvalidPart is a regression test:
// a CompleteMultipartUpload referencing a non-hex ETag is a client error and
// must yield 400 InvalidPart, never 500 InternalError.
func TestCompleteMultipartUploadNonHexETagIsInvalidPart(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "mp-etag-err")
	b.SetBucketOwner("mp-etag-err", "minis3-access-key")

	uploadID := createMultipartUpload(
		t,
		h,
		"mp-etag-err",
		"obj",
		map[string]string{"Authorization": authHeader("minis3-access-key")},
	)
	w1 := doRequest(
		h,
		newRequest(
			http.MethodPut,
			fmt.Sprintf(
				"http://example.test/mp-etag-err/obj?uploadId=%s&partNumber=1",
				uploadID,
			),
			"part-data",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, w1, http.StatusOK)

	// Client sends a non-hex ETag that cannot match the stored part ETag.
	w := doRequest(
		h,
		newRequest(
			http.MethodPost,
			fmt.Sprintf("http://example.test/mp-etag-err/obj?uploadId=%s", uploadID),
			`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"zzz"</ETag></Part></CompleteMultipartUpload>`,
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidPart")
}

// TestCompleteMultipartUploadCorruptStoredETagIsInvalidPart verifies the
// handler mapping for the backend corrupted-ETag path: backend returns
// ErrInvalidPart (not a plain error), so the handler must respond with
// 400 InvalidPart instead of 500 InternalError.
func TestCompleteMultipartUploadCorruptStoredETagIsInvalidPart(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "mp-etag-corrupt")
	b.SetBucketOwner("mp-etag-corrupt", "minis3-access-key")

	restore := completeMultipartUploadFn
	t.Cleanup(func() { completeMultipartUploadFn = restore })
	completeMultipartUploadFn = func(
		*Handler,
		string,
		string,
		string,
		[]backend.CompletePart,
	) (*backend.Object, error) {
		return nil, backend.ErrInvalidPart
	}

	w := doRequest(
		h,
		newRequest(
			http.MethodPost,
			"http://example.test/mp-etag-corrupt/obj?uploadId=corrupt",
			`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"zzz"</ETag></Part></CompleteMultipartUpload>`,
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		),
	)
	requireStatus(t, w, http.StatusBadRequest)
	requireS3ErrorCode(t, w, "InvalidPart")
}
