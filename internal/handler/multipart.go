package handler

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/yashikota/minis3/internal/backend"
)

// handleCreateMultipartUpload handles CreateMultipartUpload requests.
func (h *Handler) handleCreateMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	opts := backend.CreateMultipartUploadOptions{
		ContentType: r.Header.Get("Content-Type"),
		Metadata:    extractMetadata(r),
	}

	upload, err := h.backend.CreateMultipartUpload(bucketName, key, opts)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	resp := backend.InitiateMultipartUploadResult{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:   bucketName,
		Key:      key,
		UploadId: upload.UploadId,
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleUploadPart handles UploadPart requests.
func (h *Handler) handleUploadPart(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	query := r.URL.Query()
	uploadId := query.Get("uploadId")
	partNumberStr := query.Get("partNumber")

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Part number must be an integer between 1 and 10000.",
		)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	defer func() { _ = r.Body.Close() }()

	part, err := h.backend.UploadPart(bucketName, key, uploadId, partNumber, data)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.Header().Set("ETag", part.ETag)
	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload handles CompleteMultipartUpload requests.
func (h *Handler) handleCompleteMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	uploadId := r.URL.Query().Get("uploadId")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body",
		)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var completeReq backend.CompleteMultipartUploadRequest
	if err := xml.Unmarshal(body, &completeReq); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed.",
		)
		return
	}

	obj, err := h.backend.CompleteMultipartUpload(bucketName, key, uploadId, completeReq.Parts)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else if errors.Is(err, backend.ErrInvalidPart) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidPart",
				"One or more of the specified parts could not be found.",
			)
		} else if errors.Is(err, backend.ErrInvalidPartOrder) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidPartOrder",
				"The list of parts was not in ascending order.",
			)
		} else if errors.Is(err, backend.ErrEntityTooSmall) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"EntityTooSmall",
				"Your proposed upload is smaller than the minimum allowed size.",
			)
		} else if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	// Build location URL
	location := "http://" + r.Host + "/" + bucketName + "/" + key

	resp := backend.CompleteMultipartUploadResult{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Location: location,
		Bucket:   bucketName,
		Key:      key,
		ETag:     obj.ETag,
	}

	// Add version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleAbortMultipartUpload handles AbortMultipartUpload requests.
func (h *Handler) handleAbortMultipartUpload(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	uploadId := r.URL.Query().Get("uploadId")

	err := h.backend.AbortMultipartUpload(bucketName, key, uploadId)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListMultipartUploads handles ListMultipartUploads requests.
func (h *Handler) handleListMultipartUploads(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	query := r.URL.Query()

	maxUploads := 1000
	if maxUploadsStr := query.Get("max-uploads"); maxUploadsStr != "" {
		parsed, err := strconv.Atoi(maxUploadsStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-uploads must be a non-negative integer.",
			)
			return
		}
		maxUploads = parsed
	}

	opts := backend.ListMultipartUploadsOptions{
		Prefix:         query.Get("prefix"),
		Delimiter:      query.Get("delimiter"),
		KeyMarker:      query.Get("key-marker"),
		UploadIdMarker: query.Get("upload-id-marker"),
		MaxUploads:     maxUploads,
	}

	result, err := h.backend.ListMultipartUploads(bucketName, opts)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	owner := backend.DefaultOwner()
	resp := backend.ListMultipartUploadsResult{
		Xmlns:              "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:             bucketName,
		KeyMarker:          opts.KeyMarker,
		UploadIdMarker:     opts.UploadIdMarker,
		NextKeyMarker:      result.NextKeyMarker,
		NextUploadIdMarker: result.NextUploadIdMarker,
		MaxUploads:         maxUploads,
		IsTruncated:        result.IsTruncated,
		Prefix:             opts.Prefix,
		Delimiter:          opts.Delimiter,
	}

	for _, upload := range result.Uploads {
		resp.Uploads = append(resp.Uploads, backend.UploadInfo{
			Key:          upload.Key,
			UploadId:     upload.UploadId,
			Initiator:    owner,
			Owner:        owner,
			StorageClass: "STANDARD",
			Initiated:    upload.Initiated,
		})
	}

	for _, cp := range result.CommonPrefixes {
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cp,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handleListParts handles ListParts requests.
func (h *Handler) handleListParts(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	query := r.URL.Query()
	uploadId := query.Get("uploadId")

	partNumberMarker := 0
	if markerStr := query.Get("part-number-marker"); markerStr != "" {
		parsed, err := strconv.Atoi(markerStr)
		if err != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"part-number-marker must be an integer.",
			)
			return
		}
		partNumberMarker = parsed
	}

	maxParts := 1000
	if maxPartsStr := query.Get("max-parts"); maxPartsStr != "" {
		parsed, err := strconv.Atoi(maxPartsStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-parts must be a non-negative integer.",
			)
			return
		}
		maxParts = parsed
	}

	opts := backend.ListPartsOptions{
		PartNumberMarker: partNumberMarker,
		MaxParts:         maxParts,
	}

	result, upload, err := h.backend.ListParts(bucketName, key, uploadId, opts)
	if err != nil {
		if errors.Is(err, backend.ErrNoSuchUpload) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchUpload",
				"The specified upload does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	owner := backend.DefaultOwner()
	resp := backend.ListPartsResult{
		Xmlns:                "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:               bucketName,
		Key:                  key,
		UploadId:             uploadId,
		Initiator:            owner,
		Owner:                owner,
		StorageClass:         "STANDARD",
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: result.NextPartNumberMarker,
		MaxParts:             maxParts,
		IsTruncated:          result.IsTruncated,
	}

	_ = upload // We have upload info if needed for future use

	for _, part := range result.Parts {
		resp.Parts = append(resp.Parts, backend.PartItem{
			PartNumber:   part.PartNumber,
			LastModified: part.LastModified,
			ETag:         part.ETag,
			Size:         part.Size,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}
