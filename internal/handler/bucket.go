package handler

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/yashikota/minis3/internal/api"
	"github.com/yashikota/minis3/internal/backend"
)

// handleBucket handles bucket-level operations.
func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			h.handleListObjectsV2(w, r, bucketName)
			return
		}
		api.WriteError(
			w,
			http.StatusNotImplemented,
			"NotImplemented",
			"ListObjects v1 is not implemented. Use list-type=2 for ListObjectsV2.",
		)
	case http.MethodPost:
		if r.URL.Query().Has("delete") {
			h.handleDeleteObjects(w, r, bucketName)
			return
		}
		api.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
	case http.MethodPut:
		err := h.backend.CreateBucket(bucketName)
		if err != nil {
			if errors.Is(err, backend.ErrBucketAlreadyExists) {
				api.WriteError(w, http.StatusConflict, "BucketAlreadyExists", err.Error())
			} else {
				api.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}
		w.Header().Set("Location", "/"+bucketName)
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		err := h.backend.DeleteBucket(bucketName)
		if err != nil {
			if errors.Is(err, backend.ErrBucketNotEmpty) {
				api.WriteError(w, http.StatusConflict, "BucketNotEmpty", err.Error())
			} else if errors.Is(err, backend.ErrBucketNotFound) {
				api.WriteError(
					w,
					http.StatusNotFound,
					"NoSuchBucket",
					"The specified bucket does not exist.",
				)
			} else {
				api.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead:
		_, ok := h.backend.GetBucket(bucketName)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		api.WriteError(
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
		if parsed, err := strconv.Atoi(maxKeysStr); err == nil && parsed >= 0 {
			maxKeys = parsed
		}
	}

	result, err := h.backend.ListObjectsV2(bucketName, prefix, delimiter, maxKeys)
	if err != nil {
		api.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := api.ListBucketResult{
		Xmlns:       "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:        bucketName,
		Prefix:      prefix,
		Delimiter:   delimiter,
		MaxKeys:     maxKeys,
		KeyCount:    result.KeyCount,
		IsTruncated: result.IsTruncated,
	}

	for _, obj := range result.Objects {
		resp.Contents = append(resp.Contents, api.ObjectInfo{
			Key:          obj.Key,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, cp := range result.CommonPrefixes {
		resp.CommonPrefixes = append(resp.CommonPrefixes, api.CommonPrefix{
			Prefix: cp,
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xml.Marshal(resp)
	if err != nil {
		api.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}
