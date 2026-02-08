package handler

import (
	"encoding/xml"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

// handleService handles service-level operations (ListBuckets).
func (h *Handler) handleService(w http.ResponseWriter, r *http.Request) {
	if action := iamAction(r); action != "" {
		h.handleIAMAction(w, r, action)
		return
	}

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

	accessKey := extractAccessKey(r)
	type bucketView struct {
		name   string
		bucket *backend.Bucket
	}
	allBuckets := h.backend.ListBuckets()
	views := make([]bucketView, 0, len(allBuckets))
	for _, b := range allBuckets {
		if accessKey != "" && b.OwnerAccessKey != accessKey {
			continue
		}
		displayName := displayBucketName(b.Name)
		if opts.Prefix != "" && !strings.HasPrefix(displayName, opts.Prefix) {
			continue
		}
		views = append(views, bucketView{name: displayName, bucket: b})
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].name < views[j].name
	})
	startIdx := 0
	if opts.ContinuationToken != "" {
		startIdx = sort.Search(len(views), func(i int) bool {
			return views[i].name > opts.ContinuationToken
		})
	}
	maxBuckets := opts.MaxBuckets
	if maxBuckets <= 0 {
		maxBuckets = 1000
	}
	endIdx := startIdx + maxBuckets
	if endIdx > len(views) {
		endIdx = len(views)
	}
	isTruncated := endIdx < len(views)

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

	for _, view := range views[startIdx:endIdx] {
		resp.Buckets = append(resp.Buckets, backend.BucketInfo{
			Name:         view.name,
			CreationDate: view.bucket.CreationDate.Format(time.RFC3339),
		})
	}

	if isTruncated && endIdx > startIdx {
		resp.ContinuationToken = views[endIdx-1].name
	}

	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

func iamAction(r *http.Request) string {
	if action := strings.TrimSpace(r.URL.Query().Get("Action")); action != "" {
		return action
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if action := strings.TrimSpace(r.Form.Get("Action")); action != "" {
			return action
		}
	}
	return ""
}

func (h *Handler) handleIAMAction(w http.ResponseWriter, r *http.Request, action string) {
	switch action {
	case "GetUser":
		h.handleIAMGetUser(w, r)
	case "ListUsers":
		h.handleIAMListUsers(w, r)
	case "CreateUser":
		h.handleIAMCreateUser(w, r)
	case "DeleteUser":
		h.handleIAMDeleteUser(w, r)
	case "PutUserPolicy":
		h.handleIAMPutUserPolicy(w, r)
	case "DeleteUserPolicy":
		h.handleIAMDeleteUserPolicy(w, r)
	case "ListGroups":
		h.handleIAMListGroups(w, r)
	default:
		backend.WriteError(w, http.StatusBadRequest, "Unknown", "Unknown")
	}
}

type iamGetUserResponse struct {
	XMLName          xml.Name            `xml:"GetUserResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	GetUserResult    iamGetUserResult    `xml:"GetUserResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamGetUserResult struct {
	User iamUser `xml:"User"`
}

type iamUser struct {
	Path       string `xml:"Path"`
	UserName   string `xml:"UserName"`
	UserID     string `xml:"UserId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

type iamResponseMetadata struct {
	RequestID string `xml:"RequestId"`
}

func (h *Handler) handleIAMGetUser(w http.ResponseWriter, r *http.Request) {
	accessKey := extractAccessKey(r)
	owner := ownerForAccessKeyFn(accessKey)
	if owner == nil {
		owner = backend.DefaultOwner()
	}
	accountID := owner.ID
	userName := owner.DisplayName
	if userName == "" {
		userName = "user"
	}
	arn := "arn:aws:iam::" + accountID + ":user/" + userName
	switch {
	case accessKey == "root-access-key" || userName == "root":
		accountID = "123456789012"
		arn = "arn:aws:iam::" + accountID + ":root"
	case accessKey == "altroot-access-key" || userName == "altroot":
		accountID = "210987654321"
		arn = "arn:aws:iam::" + accountID + ":root"
	}
	resp := iamGetUserResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		GetUserResult: iamGetUserResult{
			User: iamUser{
				Path:       "/",
				UserName:   userName,
				UserID:     accountID,
				Arn:        arn,
				CreateDate: time.Now().UTC().Format(time.RFC3339),
			},
		},
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM ListUsers response types
type iamListUsersResponse struct {
	XMLName          xml.Name            `xml:"ListUsersResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ListUsersResult  iamListUsersResult  `xml:"ListUsersResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamListUsersResult struct {
	Users       []iamUser `xml:"Users>member"`
	IsTruncated bool      `xml:"IsTruncated"`
	Marker      string    `xml:"Marker,omitempty"`
}

func (h *Handler) handleIAMListUsers(w http.ResponseWriter, _ *http.Request) {
	resp := iamListUsersResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		ListUsersResult: iamListUsersResult{
			Users:       []iamUser{},
			IsTruncated: false,
		},
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM CreateUser response types
type iamCreateUserResponse struct {
	XMLName          xml.Name            `xml:"CreateUserResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	CreateUserResult iamCreateUserResult `xml:"CreateUserResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamCreateUserResult struct {
	User iamUser `xml:"User"`
}

func (h *Handler) handleIAMCreateUser(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userName := r.Form.Get("UserName")
	if userName == "" {
		userName = "newuser"
	}
	path := r.Form.Get("Path")
	if path == "" {
		path = "/"
	}

	accountID := "123456789012"
	arn := "arn:aws:iam::" + accountID + ":user" + path + userName

	resp := iamCreateUserResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		CreateUserResult: iamCreateUserResult{
			User: iamUser{
				Path:       path,
				UserName:   userName,
				UserID:     "AIDAEXAMPLEID" + userName,
				Arn:        arn,
				CreateDate: time.Now().UTC().Format(time.RFC3339),
			},
		},
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM DeleteUser response types
type iamDeleteUserResponse struct {
	XMLName          xml.Name            `xml:"DeleteUserResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

func (h *Handler) handleIAMDeleteUser(w http.ResponseWriter, _ *http.Request) {
	resp := iamDeleteUserResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM PutUserPolicy response types
type iamPutUserPolicyResponse struct {
	XMLName          xml.Name            `xml:"PutUserPolicyResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

func (h *Handler) handleIAMPutUserPolicy(w http.ResponseWriter, _ *http.Request) {
	resp := iamPutUserPolicyResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM DeleteUserPolicy response types
type iamDeleteUserPolicyResponse struct {
	XMLName          xml.Name            `xml:"DeleteUserPolicyResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

func (h *Handler) handleIAMDeleteUserPolicy(w http.ResponseWriter, _ *http.Request) {
	resp := iamDeleteUserPolicyResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

// IAM ListGroups response types
type iamListGroupsResponse struct {
	XMLName          xml.Name            `xml:"ListGroupsResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ListGroupsResult iamListGroupsResult `xml:"ListGroupsResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamListGroupsResult struct {
	Groups      []iamGroup `xml:"Groups>member"`
	IsTruncated bool       `xml:"IsTruncated"`
	Marker      string     `xml:"Marker,omitempty"`
}

type iamGroup struct {
	Path       string `xml:"Path"`
	GroupName  string `xml:"GroupName"`
	GroupID    string `xml:"GroupId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

func (h *Handler) handleIAMListGroups(w http.ResponseWriter, _ *http.Request) {
	resp := iamListGroupsResponse{
		Xmlns: "https://iam.amazonaws.com/doc/2010-05-08/",
		ListGroupsResult: iamListGroupsResult{
			Groups:      []iamGroup{},
			IsTruncated: false,
		},
		ResponseMetadata: iamResponseMetadata{
			RequestID: generateRequestId(),
		},
	}
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(resp)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}
