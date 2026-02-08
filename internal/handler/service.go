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
	case "CreateUser":
		h.handleIAMCreateUser(w, r)
	case "CreateAccessKey":
		h.handleIAMCreateAccessKey(w, r)
	case "DeleteAccessKey":
		h.handleIAMDeleteAccessKey(w, r)
	case "DeleteUser":
		h.handleIAMDeleteUser(w, r)
	case "ListUsers":
		h.handleIAMListUsers(w, r)
	case "ListAccessKeys":
		h.handleIAMListAccessKeys(w, r)
	case "ListUserPolicies":
		h.handleIAMListUserPolicies(w, r)
	case "ListAttachedUserPolicies":
		h.handleIAMListAttachedUserPolicies(w, r)
	case "ListGroups":
		h.handleIAMListGroups(w, r)
	case "ListRoles":
		h.handleIAMListRoles(w, r)
	case "ListOpenIDConnectProviders":
		h.handleIAMListOpenIDConnectProviders(w, r)
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
		Xmlns: iamXmlns,
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
	h.writeIAMResponse(w, resp)
}

const iamXmlns = "https://iam.amazonaws.com/doc/2010-05-08/"

func (h *Handler) writeIAMResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "text/xml")
	_, _ = w.Write([]byte(xml.Header))
	output, err := xmlMarshalFn(v)
	if err != nil {
		backend.WriteError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	_, _ = w.Write(output)
}

func iamFormValue(r *http.Request, key string) string {
	_ = r.ParseForm()
	if v := r.Form.Get(key); v != "" {
		return v
	}
	return r.URL.Query().Get(key)
}

// --- CreateUser ---

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
	userName := iamFormValue(r, "UserName")
	path := iamFormValue(r, "Path")
	if path == "" {
		path = "/"
	}

	user, err := h.backend.CreateIAMUser(userName, path)
	if err != nil {
		backend.WriteError(w, http.StatusConflict, "EntityAlreadyExists",
			"User with name "+userName+" already exists.")
		return
	}

	resp := iamCreateUserResponse{
		Xmlns: iamXmlns,
		CreateUserResult: iamCreateUserResult{
			User: iamUser{
				Path:       user.Path,
				UserName:   user.UserName,
				UserID:     user.UserID,
				Arn:        user.Arn,
				CreateDate: user.CreateDate.Format(time.RFC3339),
			},
		},
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	w.WriteHeader(http.StatusCreated)
	h.writeIAMResponse(w, resp)
}

// --- CreateAccessKey ---

type iamCreateAccessKeyResponse struct {
	XMLName               xml.Name                 `xml:"CreateAccessKeyResponse"`
	Xmlns                 string                   `xml:"xmlns,attr,omitempty"`
	CreateAccessKeyResult iamCreateAccessKeyResult `xml:"CreateAccessKeyResult"`
	ResponseMetadata      iamResponseMetadata      `xml:"ResponseMetadata"`
}

type iamCreateAccessKeyResult struct {
	AccessKey iamAccessKeyDetail `xml:"AccessKey"`
}

type iamAccessKeyDetail struct {
	UserName        string `xml:"UserName"`
	AccessKeyId     string `xml:"AccessKeyId"`
	Status          string `xml:"Status"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	CreateDate      string `xml:"CreateDate"`
}

func (h *Handler) handleIAMCreateAccessKey(w http.ResponseWriter, r *http.Request) {
	userName := iamFormValue(r, "UserName")

	key, err := h.backend.CreateIAMAccessKey(userName)
	if err != nil {
		backend.WriteError(w, http.StatusNotFound, "NoSuchEntity",
			"The user with name "+userName+" cannot be found.")
		return
	}

	resp := iamCreateAccessKeyResponse{
		Xmlns: iamXmlns,
		CreateAccessKeyResult: iamCreateAccessKeyResult{
			AccessKey: iamAccessKeyDetail{
				UserName:        key.UserName,
				AccessKeyId:     key.AccessKeyId,
				Status:          key.Status,
				SecretAccessKey: key.SecretAccessKey,
				CreateDate:      key.CreateDate.Format(time.RFC3339),
			},
		},
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	w.WriteHeader(http.StatusCreated)
	h.writeIAMResponse(w, resp)
}

// --- DeleteAccessKey ---

type iamDeleteAccessKeyResponse struct {
	XMLName          xml.Name            `xml:"DeleteAccessKeyResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

func (h *Handler) handleIAMDeleteAccessKey(w http.ResponseWriter, r *http.Request) {
	userName := iamFormValue(r, "UserName")
	accessKeyID := iamFormValue(r, "AccessKeyId")

	_ = h.backend.DeleteIAMAccessKey(userName, accessKeyID)

	resp := iamDeleteAccessKeyResponse{
		Xmlns:            iamXmlns,
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

// --- DeleteUser ---

type iamDeleteUserResponse struct {
	XMLName          xml.Name            `xml:"DeleteUserResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

func (h *Handler) handleIAMDeleteUser(w http.ResponseWriter, r *http.Request) {
	userName := iamFormValue(r, "UserName")

	_ = h.backend.DeleteIAMUser(userName)

	resp := iamDeleteUserResponse{
		Xmlns:            iamXmlns,
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

// --- ListUsers ---

type iamListUsersResponse struct {
	XMLName          xml.Name            `xml:"ListUsersResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ListUsersResult  iamListUsersResult  `xml:"ListUsersResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamListUsersResult struct {
	Users       []iamUserMember `xml:"Users>member,omitempty"`
	IsTruncated bool            `xml:"IsTruncated"`
}

type iamUserMember struct {
	Path       string `xml:"Path"`
	UserName   string `xml:"UserName"`
	UserID     string `xml:"UserId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

func (h *Handler) handleIAMListUsers(w http.ResponseWriter, r *http.Request) {
	pathPrefix := iamFormValue(r, "PathPrefix")
	users := h.backend.ListIAMUsers(pathPrefix)

	result := iamListUsersResult{IsTruncated: false}
	for _, u := range users {
		result.Users = append(result.Users, iamUserMember{
			Path:       u.Path,
			UserName:   u.UserName,
			UserID:     u.UserID,
			Arn:        u.Arn,
			CreateDate: u.CreateDate.Format(time.RFC3339),
		})
	}

	resp := iamListUsersResponse{
		Xmlns:            iamXmlns,
		ListUsersResult:  result,
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

// --- ListAccessKeys ---

type iamListAccessKeysResponse struct {
	XMLName              xml.Name                `xml:"ListAccessKeysResponse"`
	Xmlns                string                  `xml:"xmlns,attr,omitempty"`
	ListAccessKeysResult iamListAccessKeysResult `xml:"ListAccessKeysResult"`
	ResponseMetadata     iamResponseMetadata     `xml:"ResponseMetadata"`
}

type iamListAccessKeysResult struct {
	AccessKeyMetadata []iamAccessKeyMetadata `xml:"AccessKeyMetadata>member,omitempty"`
	IsTruncated       bool                   `xml:"IsTruncated"`
}

type iamAccessKeyMetadata struct {
	UserName    string `xml:"UserName"`
	AccessKeyId string `xml:"AccessKeyId"`
	Status      string `xml:"Status"`
	CreateDate  string `xml:"CreateDate"`
}

func (h *Handler) handleIAMListAccessKeys(w http.ResponseWriter, r *http.Request) {
	userName := iamFormValue(r, "UserName")
	keys := h.backend.ListIAMAccessKeys(userName)

	result := iamListAccessKeysResult{IsTruncated: false}
	for _, k := range keys {
		result.AccessKeyMetadata = append(result.AccessKeyMetadata, iamAccessKeyMetadata{
			UserName:    k.UserName,
			AccessKeyId: k.AccessKeyId,
			Status:      k.Status,
			CreateDate:  k.CreateDate.Format(time.RFC3339),
		})
	}

	resp := iamListAccessKeysResponse{
		Xmlns:                iamXmlns,
		ListAccessKeysResult: result,
		ResponseMetadata:     iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

// --- Stub IAM list actions (return empty lists) ---

type iamListUserPoliciesResponse struct {
	XMLName                xml.Name                  `xml:"ListUserPoliciesResponse"`
	Xmlns                  string                    `xml:"xmlns,attr,omitempty"`
	ListUserPoliciesResult iamListUserPoliciesResult `xml:"ListUserPoliciesResult"`
	ResponseMetadata       iamResponseMetadata       `xml:"ResponseMetadata"`
}

type iamListUserPoliciesResult struct {
	PolicyNames []string `xml:"PolicyNames>member,omitempty"`
	IsTruncated bool     `xml:"IsTruncated"`
}

func (h *Handler) handleIAMListUserPolicies(w http.ResponseWriter, r *http.Request) {
	resp := iamListUserPoliciesResponse{
		Xmlns:                  iamXmlns,
		ListUserPoliciesResult: iamListUserPoliciesResult{IsTruncated: false},
		ResponseMetadata:       iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

type iamListAttachedUserPoliciesResponse struct {
	XMLName                        xml.Name                          `xml:"ListAttachedUserPoliciesResponse"`
	Xmlns                          string                            `xml:"xmlns,attr,omitempty"`
	ListAttachedUserPoliciesResult iamListAttachedUserPoliciesResult `xml:"ListAttachedUserPoliciesResult"`
	ResponseMetadata               iamResponseMetadata               `xml:"ResponseMetadata"`
}

type iamListAttachedUserPoliciesResult struct {
	AttachedPolicies []string `xml:"AttachedPolicies>member,omitempty"`
	IsTruncated      bool     `xml:"IsTruncated"`
}

func (h *Handler) handleIAMListAttachedUserPolicies(w http.ResponseWriter, r *http.Request) {
	resp := iamListAttachedUserPoliciesResponse{
		Xmlns:                          iamXmlns,
		ListAttachedUserPoliciesResult: iamListAttachedUserPoliciesResult{IsTruncated: false},
		ResponseMetadata:               iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

type iamListGroupsResponse struct {
	XMLName          xml.Name            `xml:"ListGroupsResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ListGroupsResult iamListGroupsResult `xml:"ListGroupsResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamListGroupsResult struct {
	Groups      []string `xml:"Groups>member,omitempty"`
	IsTruncated bool     `xml:"IsTruncated"`
}

func (h *Handler) handleIAMListGroups(w http.ResponseWriter, r *http.Request) {
	resp := iamListGroupsResponse{
		Xmlns:            iamXmlns,
		ListGroupsResult: iamListGroupsResult{IsTruncated: false},
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

type iamListRolesResponse struct {
	XMLName          xml.Name            `xml:"ListRolesResponse"`
	Xmlns            string              `xml:"xmlns,attr,omitempty"`
	ListRolesResult  iamListRolesResult  `xml:"ListRolesResult"`
	ResponseMetadata iamResponseMetadata `xml:"ResponseMetadata"`
}

type iamListRolesResult struct {
	Roles       []string `xml:"Roles>member,omitempty"`
	IsTruncated bool     `xml:"IsTruncated"`
}

func (h *Handler) handleIAMListRoles(w http.ResponseWriter, r *http.Request) {
	resp := iamListRolesResponse{
		Xmlns:            iamXmlns,
		ListRolesResult:  iamListRolesResult{IsTruncated: false},
		ResponseMetadata: iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}

type iamListOpenIDConnectProvidersResponse struct {
	XMLName                          xml.Name                            `xml:"ListOpenIDConnectProvidersResponse"`
	Xmlns                            string                              `xml:"xmlns,attr,omitempty"`
	ListOpenIDConnectProvidersResult iamListOpenIDConnectProvidersResult `xml:"ListOpenIDConnectProvidersResult"`
	ResponseMetadata                 iamResponseMetadata                 `xml:"ResponseMetadata"`
}

type iamListOpenIDConnectProvidersResult struct {
	OpenIDConnectProviderList []string `xml:"OpenIDConnectProviderList>member,omitempty"`
}

func (h *Handler) handleIAMListOpenIDConnectProviders(w http.ResponseWriter, r *http.Request) {
	resp := iamListOpenIDConnectProvidersResponse{
		Xmlns:                            iamXmlns,
		ListOpenIDConnectProvidersResult: iamListOpenIDConnectProvidersResult{},
		ResponseMetadata:                 iamResponseMetadata{RequestID: generateRequestId()},
	}
	h.writeIAMResponse(w, resp)
}
