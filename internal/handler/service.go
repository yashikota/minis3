package handler

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleService handles service-level operations (ListBuckets).
func (h *Handler) handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		backend.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
		return
	}

	query := r.URL.Query()

	// Parse query parameters per S3 ListBuckets API
	opts := backend.ListBucketsOptions{
		Prefix:            query.Get("prefix"),
		ContinuationToken: query.Get("continuation-token"),
	}

	// Parse max-buckets (valid range: 0-10000, 0 returns empty result with truncation)
	if maxBucketsStr := query.Get("max-buckets"); maxBucketsStr != "" {
		maxBuckets, err := strconv.Atoi(maxBucketsStr)
		if err != nil || maxBuckets < 0 || maxBuckets > 10000 {
			backend.WriteError(
				w,
				http.StatusBadRequest,
				"InvalidArgument",
				"max-buckets must be an integer between 0 and 10000.",
			)
			return
		}
		opts.MaxBuckets = maxBuckets
	}

	result := h.backend.ListBucketsWithOptions(opts)
	resp := backend.ListAllMyBucketsResult{
		Owner:  &backend.Owner{ID: "minis3", DisplayName: "minis3"},
		Prefix: opts.Prefix,
	}
	if query.Has("usage") {
		resp.Summary = &backend.UsageSummary{
			QuotaMaxBytes:             "-1",
			QuotaMaxBuckets:           "1000",
			QuotaMaxObjCount:          "-1",
			QuotaMaxBytesPerBucket:    "-1",
			QuotaMaxObjCountPerBucket: "-1",
		}
	}

	for _, b := range result.Buckets {
		resp.Buckets = append(resp.Buckets, backend.BucketInfo{
			Name:         b.Name,
			CreationDate: b.CreationDate.Format(time.RFC3339),
		})
	}

	if result.IsTruncated {
		resp.ContinuationToken = result.ContinuationToken
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
