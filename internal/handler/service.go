package handler

import (
	"encoding/xml"
	"net/http"
	"time"

	"github.com/yashikota/minis3/internal/api"
)

// handleService handles service-level operations (ListBuckets).
func (h *Handler) handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.WriteError(
			w,
			http.StatusMethodNotAllowed,
			"MethodNotAllowed",
			"The specified method is not allowed against this resource.",
		)
		return
	}

	list := h.backend.ListBuckets()
	resp := api.ListAllMyBucketsResult{
		Owner: &api.Owner{ID: "minis3", DisplayName: "minis3"},
	}
	for _, b := range list {
		resp.Buckets = append(resp.Buckets, api.BucketInfo{
			Name:         b.Name,
			CreationDate: b.CreationDate.Format(time.RFC3339),
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
