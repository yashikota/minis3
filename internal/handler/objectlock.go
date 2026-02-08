package handler

import (
	"encoding/xml"
	"errors"
	"net/http"

	"github.com/yashikota/minis3/internal/backend"
)

var (
	getObjectLockConfigurationFn = func(
		h *Handler,
		bucketName string,
	) (*backend.ObjectLockConfiguration, error) {
		return h.backend.GetObjectLockConfiguration(bucketName)
	}
	putObjectLockConfigurationFn = func(
		h *Handler,
		bucketName string,
		config *backend.ObjectLockConfiguration,
	) error {
		return h.backend.PutObjectLockConfiguration(bucketName, config)
	}
	getObjectRetentionFn = func(
		h *Handler,
		bucketName, key, versionID string,
	) (*backend.ObjectLockRetention, error) {
		return h.backend.GetObjectRetention(bucketName, key, versionID)
	}
	putObjectRetentionFn = func(
		h *Handler,
		bucketName, key, versionID string,
		retention *backend.ObjectLockRetention,
		bypassGovernance bool,
	) error {
		return h.backend.PutObjectRetention(bucketName, key, versionID, retention, bypassGovernance)
	}
	getObjectLegalHoldFn = func(
		h *Handler,
		bucketName, key, versionID string,
	) (*backend.ObjectLockLegalHold, error) {
		return h.backend.GetObjectLegalHold(bucketName, key, versionID)
	}
	putObjectLegalHoldFn = func(
		h *Handler,
		bucketName, key, versionID string,
		legalHold *backend.ObjectLockLegalHold,
	) error {
		return h.backend.PutObjectLegalHold(bucketName, key, versionID, legalHold)
	}
)

// handleGetObjectLockConfiguration handles GetObjectLockConfiguration requests.
func (h *Handler) handleGetObjectLockConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	config, err := getObjectLockConfigurationFn(h, bucketName)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"ObjectLockConfigurationNotFoundError",
				"Object Lock configuration does not exist for this bucket.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	config.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(config)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectLockConfiguration handles PutObjectLockConfiguration requests.
func (h *Handler) handlePutObjectLockConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	bucketName string,
) {
	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var config backend.ObjectLockConfiguration
	if err := xml.Unmarshal(body, &config); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed.",
		)
		return
	}

	err = putObjectLockConfigurationFn(h, bucketName, &config)
	if err != nil {
		if errors.Is(err, backend.ErrBucketNotFound) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchBucket",
				"The specified bucket does not exist.",
			)
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusConflict,
				"InvalidBucketState",
				"Object Lock configuration cannot be enabled on existing buckets.",
			)
		} else if errors.Is(err, backend.ErrInvalidRetentionPeriod) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRetentionPeriod",
				"The retention period must be a positive integer value.",
			)
		} else if errors.Is(err, backend.ErrInvalidObjectLockConfig) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetObjectRetention handles GetObjectRetention requests.
func (h *Handler) handleGetObjectRetention(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	retention, err := getObjectRetentionFn(h, bucketName, key, versionId)
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
		} else if errors.Is(err, backend.ErrNoSuchObjectLockConfig) {
			backend.WriteError(
				w,
				http.StatusNotFound,
				"NoSuchObjectLockConfiguration",
				"The specified object does not have an Object Lock configuration.",
			)
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	retention.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(retention)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectRetention handles PutObjectRetention requests.
func (h *Handler) handlePutObjectRetention(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	bypassGovernance := r.Header.Get("x-amz-bypass-governance-retention") == "true"

	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var retention backend.ObjectLockRetention
	if err := xml.Unmarshal(body, &retention); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed.",
		)
		return
	}

	err = putObjectRetentionFn(
		h,
		bucketName,
		key,
		versionId,
		&retention,
		bypassGovernance,
	)
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
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration.",
			)
		} else if errors.Is(err, backend.ErrObjectLocked) {
			backend.WriteError(
				w,
				http.StatusForbidden,
				"AccessDenied",
				"Object is locked.",
			)
		} else if errors.Is(err, backend.ErrInvalidObjectLockConfig) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetObjectLegalHold handles GetObjectLegalHold requests.
func (h *Handler) handleGetObjectLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")
	legalHold, err := getObjectLegalHoldFn(h, bucketName, key, versionId)
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
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	legalHold.Xmlns = backend.S3Xmlns
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(legalHold)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// handlePutObjectLegalHold handles PutObjectLegalHold requests.
func (h *Handler) handlePutObjectLegalHold(
	w http.ResponseWriter,
	r *http.Request,
	bucketName, key string,
) {
	versionId := r.URL.Query().Get("versionId")

	body, err := readAllFn(r.Body)
	if err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"InvalidRequest",
			"Failed to read request body.",
		)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var legalHold backend.ObjectLockLegalHold
	if err := xml.Unmarshal(body, &legalHold); err != nil {
		backend.WriteError(
			w,
			http.StatusBadRequest,
			"MalformedXML",
			"The XML you provided was not well-formed.",
		)
		return
	}

	err = putObjectLegalHoldFn(h, bucketName, key, versionId, &legalHold)
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
		} else if errors.Is(err, backend.ErrObjectLockNotEnabled) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidRequest",
				"Bucket is missing Object Lock Configuration.",
			)
		} else if errors.Is(err, backend.ErrInvalidObjectLockConfig) {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"MalformedXML",
				"The XML you provided was not well-formed or did not validate against our published schema.",
			)
		} else {
			backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusOK)
}
