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
	// Handle ACL operations
	if r.URL.Query().Has("acl") {
		switch r.Method {
		case http.MethodGet:
			h.handleGetObjectACL(w, r, bucketName, key)
		case http.MethodPut:
			h.handlePutObjectACL(w, r, bucketName, key)
		default:
			backend.WriteError(
				w,
				http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.",
			)
		}
		return
	}

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
		// Add version ID header if versioning is enabled
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		versionId := r.URL.Query().Get("versionId")
		var obj *backend.Object
		var err error

		if versionId != "" {
			obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			obj, err = h.backend.GetObject(bucketName, key)
		}

		if err != nil {
			if errors.Is(err, backend.ErrBucketNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else if errors.Is(err, backend.ErrVersionNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchVersion",
					"The specified version does not exist.",
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

		// Check if this is a DeleteMarker
		if obj.IsDeleteMarker {
			w.Header().Set("x-amz-delete-marker", "true")
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			// Return 404 NoSuchKey when latest version is a delete marker
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
			return
		}

		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
		_, _ = w.Write(obj.Data)

	case http.MethodDelete:
		versionId := r.URL.Query().Get("versionId")
		var result *backend.DeleteObjectVersionResult
		var err error

		if versionId != "" {
			result, err = h.backend.DeleteObjectVersion(bucketName, key, versionId)
		} else {
			result, err = h.backend.DeleteObject(bucketName, key)
		}

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
			if errors.Is(err, backend.ErrVersionNotFound) {
				backend.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchVersion",
					"The specified version does not exist.",
				)
				return
			}
		}

		// Set response headers based on result
		if result != nil {
			if result.VersionId != "" && result.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", result.VersionId)
			}
			if result.IsDeleteMarker {
				w.Header().Set("x-amz-delete-marker", "true")
			}
		}
		w.WriteHeader(http.StatusNoContent)

	case http.MethodHead:
		versionId := r.URL.Query().Get("versionId")
		var obj *backend.Object
		var err error

		if versionId != "" {
			obj, err = h.backend.GetObjectVersion(bucketName, key, versionId)
		} else {
			obj, err = h.backend.GetObject(bucketName, key)
		}

		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Check if this is a DeleteMarker
		if obj.IsDeleteMarker {
			w.Header().Set("x-amz-delete-marker", "true")
			if obj.VersionId != backend.NullVersionId {
				w.Header().Set("x-amz-version-id", obj.VersionId)
			}
			// Return 404 when latest version is a delete marker
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("ETag", obj.ETag)
		w.Header().Set("Content-Type", obj.ContentType)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", obj.Size))
		w.Header().Set("Last-Modified", obj.LastModified.Format(http.TimeFormat))
		w.Header().Set("x-amz-checksum-crc32", obj.ChecksumCRC32)
		if obj.VersionId != backend.NullVersionId {
			w.Header().Set("x-amz-version-id", obj.VersionId)
		}
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

	results, err := h.backend.DeleteObjects(bucketName, deleteReq.Objects)
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
		if result.Error != nil {
			resp.Errors = append(resp.Errors, backend.DeleteError{
				Key:     result.Key,
				Code:    "InternalError",
				Message: result.Error.Error(),
			})
		} else if !deleteReq.Quiet {
			deleted := backend.DeletedObject{
				Key: result.Key,
			}
			if result.VersionId != "" {
				deleted.VersionId = result.VersionId
			}
			if result.DeleteMarker {
				deleted.DeleteMarker = true
				if result.DeleteMarkerVersionId != "" {
					deleted.DeleteMarkerVersionId = result.DeleteMarkerVersionId
				}
			}
			resp.Deleted = append(resp.Deleted, deleted)
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

	// Add version ID header if versioning is enabled
	if obj.VersionId != backend.NullVersionId {
		w.Header().Set("x-amz-version-id", obj.VersionId)
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

// handleGetObjectACL handles GetObjectAcl requests.
func (h *Handler) handleGetObjectACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	acl, err := h.backend.GetObjectACL(bucketName, key, versionId)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrObjectNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchKey",
				"The specified key does not exist.",
			)
		} else if errors.Is(err, backend.ErrVersionNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchVersion",
				"The specified version does not exist.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(acl)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectACL handles PutObjectAcl requests.
func (h *Handler) handlePutObjectACL(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")

	// Check for canned ACL header first
	cannedACL := r.Header.Get("x-amz-acl")
	if cannedACL != "" {
		acl := backend.CannedACLToPolicy(cannedACL)
		if err := h.backend.PutObjectACL(bucketName, key, versionId, acl); err != nil {
			h.writePutObjectACLError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse ACL from request body
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}

	var acl backend.AccessControlPolicy
	if err := xml.Unmarshal(body, &acl); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedACLError",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	if err := h.backend.PutObjectACL(bucketName, key, versionId, &acl); err != nil {
		h.writePutObjectACLError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// writePutObjectACLError writes the appropriate error response for PutObjectACL.
func (h *Handler) writePutObjectACLError(w http.ResponseWriter, err error) {
	if errors.Is(err, backend.ErrBucketNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
	} else if errors.Is(err, backend.ErrObjectNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchKey",
			"The specified key does not exist.",
		)
	} else if errors.Is(err, backend.ErrVersionNotFound) {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchVersion",
			"The specified version does not exist.",
		)
	} else {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
	}
}
