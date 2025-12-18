package handler

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleBucket handles bucket-level operations.
func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Has("versions") {
			h.handleListObjectVersions(w, r, bucketName)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			h.handleListObjectsV2(w, r, bucketName)
			return
		}
		h.handleListObjectsV1(w, r, bucketName)
	case http.MethodPost:
		if r.URL.Query().Has("delete") {
			h.handleDeleteObjects(w, r, bucketName)
			return
		}
		backend.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	case http.MethodPut:
		// Parse CreateBucketConfiguration from request body if present
		if r.Body != nil && r.ContentLength > 0 {
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

			if len(body) > 0 {
				var config backend.CreateBucketConfiguration
				if err := xml.Unmarshal(body, &config); err != nil {
					backend.WriteError(
						w,
						http.StatusBadRequest,
						"MalformedXML",
						"The XML you provided was not well-formed or did not validate against our published schema.",
					)
					return
				}
				// LocationConstraint is accepted but ignored (single-region mock)
			}
		}

		err := h.backend.CreateBucket(bucketName)
		if err != nil {
			if errors.Is(err, backend.ErrBucketAlreadyOwnedByYou) {
				// S3 returns 409 BucketAlreadyOwnedByYou when the bucket exists and is owned by you
				backend.WriteError(
					w,
					http.StatusConflict,
					"BucketAlreadyOwnedByYou",
					"Your previous request to create the named bucket succeeded and you already own it.",
				)
			} else if errors.Is(err, backend.ErrBucketAlreadyExists) {
				backend.WriteError(w, http.StatusConflict, "BucketAlreadyExists", err.Error())
			} else if errors.Is(err, backend.ErrInvalidBucketName) {
				backend.WriteError(w, http.StatusBadRequest, "InvalidBucketName", err.Error())
			} else {
				backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}
		w.Header().Set("Location", "/"+bucketName)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		err := h.backend.DeleteBucket(bucketName)
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotEmpty) {
				backend.WriteError(w, http.StatusConflict, "BucketNotEmpty", err.Error())
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
		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead:
		_, ok := h.backend.GetBucket(bucketName)
		if !ok {
			// S3 returns x-amz-bucket-region header even on 404
			w.Header().Set("x-amz-bucket-region", "us-east-1")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// HeadBucket response headers per S3 API spec
		w.Header().Set("x-amz-bucket-region", "us-east-1")
		w.Header().Set("x-amz-access-point-alias", "false")
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

// handleListObjectsV2 handles ListObjectsV2 requests.
func (h *Handler) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucketName string) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	result, err := h.backend.ListObjectsV2(bucketName, prefix, delimiter, maxKeys)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListBucketV2Result{
		Xmlns:       "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:        bucketName,
		Prefix:      prefix,
		Delimiter:   delimiter,
		MaxKeys:     maxKeys,
		KeyCount:    result.KeyCount,
		IsTruncated: result.IsTruncated,
	}

	for _, obj := range result.Objects {
		resp.Contents = append(resp.Contents, backend.ObjectInfo{
			Key:          obj.Key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
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

// handleListObjectsV1 handles ListObjects (v1) requests.
func (h *Handler) handleListObjectsV1(w http.ResponseWriter, r *http.Request, bucketName string) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	marker := query.Get("marker")
	encodingType := query.Get("encoding-type")

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	result, err := h.backend.ListObjectsV1(bucketName, prefix, delimiter, marker, maxKeys)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListBucketV1Result{
		Xmlns:       "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:        bucketName,
		Prefix:      prefix,
		Marker:      marker,
		Delimiter:   delimiter,
		MaxKeys:     maxKeys,
		IsTruncated: result.IsTruncated,
		NextMarker:  result.NextMarker,
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	for _, obj := range result.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = url.PathEscape(obj.Key)
		}
		resp.Contents = append(resp.Contents, backend.ObjectInfo{
			Key:          key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = url.PathEscape(cp)
		}
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cpValue,
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

// handleListObjectVersions handles ListObjectVersions requests.
// Since minis3 doesn't support versioning, it returns all objects as the latest version
// with a "null" version ID.
func (h *Handler) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucketName string) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	keyMarker := query.Get("key-marker")
	versionIdMarker := query.Get("version-id-marker")
	encodingType := query.Get("encoding-type")

	maxKeys := 1000
	if maxKeysStr := query.Get("max-keys"); maxKeysStr != "" {
		parsed, err := strconv.Atoi(maxKeysStr)
		if err != nil || parsed < 0 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-keys must be a non-negative integer.",
			)
			return
		}
		maxKeys = parsed
	}

	// Reuse ListObjectsV1 logic for now
	result, err := h.backend.ListObjectsV1(bucketName, prefix, delimiter, keyMarker, maxKeys)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.ListVersionsResult{
		Xmlns:           "http://s3.amazonaws.com/doc/2006-03-01/",
		IsTruncated:     result.IsTruncated,
		KeyMarker:       keyMarker,
		VersionIdMarker: versionIdMarker,
		Name:            bucketName,
		Prefix:          prefix,
		Delimiter:       delimiter,
		MaxKeys:         maxKeys,
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	if result.IsTruncated && result.NextMarker != "" {
		resp.NextKeyMarker = result.NextMarker
	}

	for _, obj := range result.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = url.PathEscape(obj.Key)
		}
		resp.Versions = append(resp.Versions, backend.VersionInfo{
			Key:          key,
			VersionId:    "null",
			IsLatest:     true,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = url.PathEscape(cp)
		}
		resp.CommonPrefixes = append(resp.CommonPrefixes, backend.CommonPrefix{
			Prefix: cpValue,
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
