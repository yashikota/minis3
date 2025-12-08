package handler

import (
	"encoding/xml"
	"net/http"
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

	list := h.backend.ListBuckets()
	resp := backend.ListAllMyBucketsResult{
		Owner: &backend.Owner{ID: "minis3", DisplayName: "minis3"},
	}
	for _, b := range list {
		resp.Buckets = append(resp.Buckets, backend.BucketInfo{
			Name:         b.Name,
			CreationDate: b.CreationDate.Format(time.RFC3339),
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
