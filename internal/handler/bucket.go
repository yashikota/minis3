package handler

import (
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleBucket handles bucket-level operations.
func (h *Handler) handleBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Has("versioning") {
			h.handleGetBucketVersioning(w, r, bucketName)
			return
		}
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
		if r.URL.Query().Has("versioning") {
			h.handlePutBucketVersioning(w, r, bucketName)
			return
		}
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

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	for _, obj := range result.Objects {
		key := obj.Key
		if encodingType == "url" {
			key = url.QueryEscape(obj.Key)
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
			cpValue = url.QueryEscape(cp)
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
			key = url.QueryEscape(obj.Key)
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
			cpValue = url.QueryEscape(cp)
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
func (h *Handler) handleListObjectVersions(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	result, err := h.backend.ListObjectVersions(
		bucketName,
		prefix,
		delimiter,
		keyMarker,
		versionIdMarker,
		maxKeys,
	)
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
		Xmlns:               "http://s3.amazonaws.com/doc/2006-03-01/",
		IsTruncated:         result.IsTruncated,
		KeyMarker:           keyMarker,
		VersionIdMarker:     versionIdMarker,
		NextKeyMarker:       result.NextKeyMarker,
		NextVersionIdMarker: result.NextVersionIdMarker,
		Name:                bucketName,
		Prefix:              prefix,
		Delimiter:           delimiter,
		MaxKeys:             maxKeys,
	}

	if encodingType == "url" {
		resp.EncodingType = "url"
	}

	for _, obj := range result.Versions {
		key := obj.Key
		if encodingType == "url" {
			key = url.QueryEscape(obj.Key)
		}
		resp.Versions = append(resp.Versions, backend.VersionInfo{
			Key:          key,
			VersionId:    obj.VersionId,
			IsLatest:     obj.IsLatest,
			LastModified: obj.LastModified.Format(time.RFC3339),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, obj := range result.DeleteMarkers {
		key := obj.Key
		if encodingType == "url" {
			key = url.QueryEscape(obj.Key)
		}
		resp.DeleteMarkers = append(resp.DeleteMarkers, backend.DeleteMarker{
			Key:          key,
			VersionId:    obj.VersionId,
			IsLatest:     obj.IsLatest,
			LastModified: obj.LastModified.Format(time.RFC3339),
		})
	}

	for _, cp := range result.CommonPrefixes {
		cpValue := cp
		if encodingType == "url" {
			cpValue = url.QueryEscape(cp)
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

// handleGetBucketVersioning handles GetBucketVersioning requests.
func (h *Handler) handleGetBucketVersioning(
	w http.ResponseWriter,
	_ *http.Request,
	bucketName string,
) {
	status, mfaDelete, err := h.backend.GetBucketVersioning(bucketName)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusNotFound,
			"NoSuchBucket",
			"The specified bucket does not exist.",
		)
		return
	}

	resp := backend.VersioningConfiguration{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	// Only include Status if versioning has been configured
	if status != backend.VersioningUnset {
		resp.Status = status.String()
	}

	// Only include MfaDelete if it's enabled
	if mfaDelete == backend.MFADeleteEnabled {
		resp.MFADelete = mfaDelete.String()
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

// handlePutBucketVersioning handles PutBucketVersioning requests.
func (h *Handler) handlePutBucketVersioning(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
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

	var config backend.VersioningConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	// Validate Status field
	if config.Status != "" && config.Status != "Enabled" && config.Status != "Suspended" {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema.",
		)
		return
	}

	status := backend.ParseVersioningStatus(config.Status)
	mfaDelete := backend.ParseMFADeleteStatus(config.MFADelete)

	// Check x-amz-mfa header if MFA Delete is being enabled
	if mfaDelete == backend.MFADeleteEnabled {
		mfaHeader := r.Header.Get("x-amz-mfa")
		if err := validateMFAHeader(mfaHeader); err != nil {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				err.Error(),
			)
			return
		}
	}

	err = h.backend.SetBucketVersioning(bucketName, status, mfaDelete)
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

	w.WriteHeader(http.StatusOK)
}

// validateMFAHeader validates the x-amz-mfa header format.
// Format: "{SerialNumber} {TokenCode}" where:
// - SerialNumber is either an ARN (arn:aws:iam::...:mfa/...) or a hardware device serial number
// - TokenCode is a 6-digit number from the MFA device
// Example: "arn:aws:iam::123456789012:mfa/user 123456" or "20899872 301749"
func validateMFAHeader(header string) error {
	if header == "" {
		return errors.New("x-amz-mfa header is required for MFA Delete operations")
	}

	// Split by space - format is "SerialNumber TokenCode"
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return errors.New("x-amz-mfa header must be in format 'SerialNumber TokenCode'")
	}

	serialNumber := strings.TrimSpace(parts[0])
	tokenCode := strings.TrimSpace(parts[1])

	// Validate SerialNumber is not empty
	if serialNumber == "" {
		return errors.New("MFA serial number cannot be empty")
	}

	// Validate SerialNumber format:
	// - Virtual MFA: arn:aws:iam::ACCOUNT_ID:mfa/DEVICE_NAME
	// - Hardware MFA: numeric serial number
	if strings.HasPrefix(serialNumber, "arn:") {
		// Validate ARN format
		if !strings.Contains(serialNumber, ":mfa/") {
			return errors.New("MFA serial number ARN must contain ':mfa/'")
		}
	}
	// Hardware serial numbers are just numeric strings - no specific validation needed

	// Validate TokenCode is exactly 6 digits
	if len(tokenCode) != 6 {
		return errors.New("MFA token code must be exactly 6 digits")
	}
	for _, c := range tokenCode {
		if c < '0' || c > '9' {
			return errors.New("MFA token code must contain only digits")
		}
	}

	return nil
}
