package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func FuzzAclFromGrantHeaders(f *testing.F) {
	f.Add("id=\"canonical-id-1\"", "", "", "", "")
	f.Add("uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"", "", "", "", "")
	f.Add("emailAddress=\"user@example.com\"", "", "", "", "")
	f.Add("id=\"id1\", id=\"id2\"", "", "", "", "")
	f.Add("", "id=\"canonical-id\"", "", "", "")
	f.Add("invalid-format", "", "", "", "")
	f.Add("=empty-key", "", "", "", "")
	f.Add("id=\"\"", "", "", "", "")
	f.Add("unknown=value", "", "", "", "")
	f.Add("", "", "", "", "")

	f.Fuzz(
		func(t *testing.T, grantRead, grantWrite, grantReadACP, grantWriteACP, grantFull string) {
			req := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
			if grantRead != "" {
				req.Header.Set("x-amz-grant-read", grantRead)
			}
			if grantWrite != "" {
				req.Header.Set("x-amz-grant-write", grantWrite)
			}
			if grantReadACP != "" {
				req.Header.Set("x-amz-grant-read-acp", grantReadACP)
			}
			if grantWriteACP != "" {
				req.Header.Set("x-amz-grant-write-acp", grantWriteACP)
			}
			if grantFull != "" {
				req.Header.Set("x-amz-grant-full-control", grantFull)
			}
			owner := &backend.Owner{ID: "owner-id", DisplayName: "owner"}
			_, _ = aclFromGrantHeaders(req, owner)
		},
	)
}
