package handler

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleObject handles object-level operations.
func (h *Handler) handleObject(w http.ResponseWriter, r *http.Request, bucketName, key string) {
	switch r.Method {
	case http.MethodPut:
		copySource := r.Header.Get("x-amz-copy-source")
		if copySource != "" {
			h.handleCopyObject(w, r, bucketName, key, copySource)
			return
		}

		data, err := io.ReadAll(r.Body)
		if err != nil {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			return
		}
		defer func() { _ = r.Body.Close() }()

		contentType := r.Header.Get("Content-Type")
		obj, err := h.backend.PutObject(bucketName, key, data, contentType)
		if err != nil {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		obj, err := h.backend.GetObject(bucketName, key)
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchKey",
					"The specified key does not exist.",
				)
			}
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		_, _ = w.Write(obj.Data)

	case http.MethodDelete:
		err := h.backend.DeleteObject(bucketName, key)
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodHead:
		obj, err := h.backend.GetObject(bucketName, key)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		w.WriteHeader(http.StatusOK)

	default:
		backend.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	}
}

// handleDeleteObjects handles batch delete operations.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucketName string) {
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

	var deleteReq backend.DeleteRequest
	if err := xml.Unmarshal(body, &deleteReq); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema",
		)
		return
	}

	if len(deleteReq.Objects) == 0 {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema",
		)
		return
	}

	keys := make([]string, len(deleteReq.Objects))
	for i, obj := range deleteReq.Objects {
		keys[i] = obj.Key
	}

	results, err := h.backend.DeleteObjects(bucketName, keys)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.DeleteResult{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	for _, result := range results {
		if !deleteReq.Quiet {
			resp.Deleted = append(resp.Deleted, backend.DeletedObject{
				Key: result.Key,
			})
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusInternalServerError,
			"InternalError",
			"Failed to marshal XML response",
		)
		return
	}
	_, _ = w.Write(output)
}

// handleCopyObject handles copy object operations.
func (h *Handler) handleCopyObject(
	w http.ResponseWriter,
	_ *http.Request,
	dstBucket, dstKey, copySource string,
) {
	decodedCopySource, err := url.PathUnescape(copySource)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header: malformed URL encoding",
		)
		return
	}

	srcBucket, srcKey := extractBucketAndKey(decodedCopySource)
	if srcBucket == "" || srcKey == "" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidArgument",
			"Invalid x-amz-copy-source header",
		)
		return
	}

	obj, err := h.backend.CopyObject(srcBucket, srcKey, dstBucket, dstKey)
	if err != nil {
		if errors.Is(err, backend.ErrSourceBucketNotFound) ||
			errors.Is(err, backend.ErrDestinationBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrSourceObjectNotFound) {
			backend.WriteError(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	resp := backend.CopyObjectResult{
		ETag:         obj.ETag,
		LastModified: obj.LastModified.Format(time.RFC3339),
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
