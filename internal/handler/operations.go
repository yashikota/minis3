package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yashikota/minis3/internal/backend"
)

// operationAuth says where an S3 operation is authorized.
type operationAuth int

const (
	// authNone: the request is not authorized against a bucket (CreateBucket,
	// unsupported subresources, method errors).
	authNone operationAuth = iota
	// authRouter: handleRequest authorizes the operation's IAM action before
	// dispatching it (with the object's existing tags for object operations).
	authRouter
	// authHandler: the handler authorizes the operation itself because the
	// decision needs request data the router does not have (tags in the
	// request, a copy source, per-key results, form credentials).
	authHandler
)

// s3Operation is one S3 API operation and the IAM action that authorizes it.
type s3Operation struct {
	Name string
	// Action is the IAM action checked against the bucket policy and ACLs.
	Action string
	// VersionAction replaces Action when the request names a version
	// (?versionId=...), e.g. s3:GetObjectVersion for GetObject.
	VersionAction string
	Auth          operationAuth
}

// action returns the IAM action for this request.
func (op s3Operation) action(query url.Values) string {
	if op.VersionAction != "" && query.Get("versionId") != "" {
		return op.VersionAction
	}
	return op.Action
}

func routerOp(name, action string) s3Operation {
	return s3Operation{Name: name, Action: action, Auth: authRouter}
}

func routerVersionedOp(name, action, versionAction string) s3Operation {
	return s3Operation{Name: name, Action: action, VersionAction: versionAction, Auth: authRouter}
}

func handlerOp(name, action, versionAction string) s3Operation {
	return s3Operation{Name: name, Action: action, VersionAction: versionAction, Auth: authHandler}
}

var unauthorizedOp = s3Operation{Auth: authNone}

// subresourceOperation maps a bucket subresource (query parameter) to the
// operation it selects.
type subresourceOperation struct {
	subresource string
	op          s3Operation
}

// bucketSubresourceOperations lists, per method and in dispatch order, the
// bucket subresources handleBucket recognises. The IAM actions follow the
// "Permissions" section of each operation in the Amazon S3 API Reference;
// several Delete operations are authorized by the matching Put action.
var bucketSubresourceOperations = map[string][]subresourceOperation{
	http.MethodGet: {
		{
			"ownershipControls",
			routerOp("GetBucketOwnershipControls", "s3:GetBucketOwnershipControls"),
		},
		{"requestPayment", routerOp("GetBucketRequestPayment", "s3:GetBucketRequestPayment")},
		{"logging", routerOp("GetBucketLogging", "s3:GetBucketLogging")},
		{"versioning", routerOp("GetBucketVersioning", "s3:GetBucketVersioning")},
		{"versions", routerOp("ListObjectVersions", "s3:ListBucketVersions")},
		{"location", routerOp("GetBucketLocation", "s3:GetBucketLocation")},
		{"tagging", routerOp("GetBucketTagging", "s3:GetBucketTagging")},
		{"policy", routerOp("GetBucketPolicy", "s3:GetBucketPolicy")},
		{"policyStatus", routerOp("GetBucketPolicyStatus", "s3:GetBucketPolicyStatus")},
		{"uploads", routerOp("ListMultipartUploads", "s3:ListBucketMultipartUploads")},
		{
			"object-lock",
			routerOp("GetObjectLockConfiguration", "s3:GetBucketObjectLockConfiguration"),
		},
		{
			"lifecycle",
			routerOp("GetBucketLifecycleConfiguration", "s3:GetLifecycleConfiguration"),
		},
		{"encryption", routerOp("GetBucketEncryption", "s3:GetEncryptionConfiguration")},
		{"cors", routerOp("GetBucketCors", "s3:GetBucketCORS")},
		{"website", routerOp("GetBucketWebsite", "s3:GetBucketWebsite")},
		{"publicAccessBlock", routerOp("GetPublicAccessBlock", "s3:GetBucketPublicAccessBlock")},
	},
	http.MethodPost: {
		// Test extension: force-flush pending server access logs.
		{"logging", routerOp("PostBucketLogging", "s3:PutBucketLogging")},
		// Each key is authorized separately (s3:DeleteObject or
		// s3:DeleteObjectVersion) and reported in the result.
		{"delete", handlerOp("DeleteObjects", "s3:DeleteObject", "")},
	},
	http.MethodPut: {
		{
			"ownershipControls",
			routerOp("PutBucketOwnershipControls", "s3:PutBucketOwnershipControls"),
		},
		{"requestPayment", routerOp("PutBucketRequestPayment", "s3:PutBucketRequestPayment")},
		{"logging", routerOp("PutBucketLogging", "s3:PutBucketLogging")},
		{"versioning", routerOp("PutBucketVersioning", "s3:PutBucketVersioning")},
		{"tagging", routerOp("PutBucketTagging", "s3:PutBucketTagging")},
		{"policy", routerOp("PutBucketPolicy", "s3:PutBucketPolicy")},
		{
			"object-lock",
			routerOp("PutObjectLockConfiguration", "s3:PutBucketObjectLockConfiguration"),
		},
		{
			"lifecycle",
			routerOp("PutBucketLifecycleConfiguration", "s3:PutLifecycleConfiguration"),
		},
		{"encryption", routerOp("PutBucketEncryption", "s3:PutEncryptionConfiguration")},
		{"cors", routerOp("PutBucketCors", "s3:PutBucketCORS")},
		{"website", routerOp("PutBucketWebsite", "s3:PutBucketWebsite")},
		{"publicAccessBlock", routerOp("PutPublicAccessBlock", "s3:PutBucketPublicAccessBlock")},
	},
	http.MethodDelete: {
		{
			"ownershipControls",
			routerOp("DeleteBucketOwnershipControls", "s3:PutBucketOwnershipControls"),
		},
		{"logging", routerOp("DeleteBucketLogging", "s3:PutBucketLogging")},
		{"tagging", routerOp("DeleteBucketTagging", "s3:PutBucketTagging")},
		{"policy", routerOp("DeleteBucketPolicy", "s3:DeleteBucketPolicy")},
		{"lifecycle", routerOp("DeleteBucketLifecycle", "s3:PutLifecycleConfiguration")},
		{"encryption", routerOp("DeleteBucketEncryption", "s3:PutEncryptionConfiguration")},
		{"cors", routerOp("DeleteBucketCors", "s3:PutBucketCORS")},
		{"website", routerOp("DeleteBucketWebsite", "s3:DeleteBucketWebsite")},
		{
			"publicAccessBlock",
			routerOp("DeletePublicAccessBlock", "s3:PutBucketPublicAccessBlock"),
		},
	},
}

// resolveS3Operation returns the operation handleBucket or handleObject
// dispatches r to. It mirrors their dispatch order; TestOperationTable
// checks the two agree for every route.
func resolveS3Operation(r *http.Request, key string) s3Operation {
	if key == "" {
		return resolveBucketOperation(r.Method, r.URL.Query())
	}
	return resolveObjectOperation(r, key)
}

func resolveBucketOperation(method string, query url.Values) s3Operation {
	if query.Has("acl") {
		switch method {
		case http.MethodGet:
			return routerOp("GetBucketAcl", "s3:GetBucketAcl")
		case http.MethodPut:
			return routerOp("PutBucketAcl", "s3:PutBucketAcl")
		default:
			return unauthorizedOp
		}
	}
	for _, entry := range bucketSubresourceOperations[method] {
		if query.Has(entry.subresource) {
			return entry.op
		}
	}
	if isUnsupportedSubresource(query) {
		return unauthorizedOp
	}
	switch method {
	case http.MethodGet:
		if query.Get("list-type") == "2" {
			return routerOp("ListObjectsV2", "s3:ListBucket")
		}
		return routerOp("ListObjects", "s3:ListBucket")
	case http.MethodHead:
		return routerOp("HeadBucket", "s3:ListBucket")
	case http.MethodPost:
		// The form's credentials, not the request's, identify the caller.
		return handlerOp("PostObject", "s3:PutObject", "")
	case http.MethodDelete:
		return routerOp("DeleteBucket", "s3:DeleteBucket")
	default:
		// CreateBucket is open to every authenticated caller; the bucket
		// does not exist yet, so there is no policy to evaluate.
		return unauthorizedOp
	}
}

func resolveObjectOperation(r *http.Request, key string) s3Operation {
	if containsUnreadableURIKeyRune(key) {
		return unauthorizedOp
	}
	query := r.URL.Query()
	method := r.Method
	if query.Has("torrent") && method == http.MethodGet {
		return unauthorizedOp
	}
	if method == http.MethodPost && (query.Has("select") || query.Has("select-type")) {
		return unauthorizedOp
	}
	if query.Has("tagging") {
		switch method {
		case http.MethodGet:
			return routerVersionedOp(
				"GetObjectTagging",
				"s3:GetObjectTagging",
				"s3:GetObjectVersionTagging",
			)
		case http.MethodPut:
			// Policies may test the requested tags in the body.
			return handlerOp(
				"PutObjectTagging",
				"s3:PutObjectTagging",
				"s3:PutObjectVersionTagging",
			)
		case http.MethodDelete:
			return routerVersionedOp(
				"DeleteObjectTagging",
				"s3:DeleteObjectTagging",
				"s3:DeleteObjectVersionTagging",
			)
		default:
			return unauthorizedOp
		}
	}
	if query.Has("attributes") && method == http.MethodGet {
		return routerVersionedOp(
			"GetObjectAttributes",
			"s3:GetObjectAttributes",
			"s3:GetObjectVersionAttributes",
		)
	}
	if query.Has("acl") {
		switch method {
		case http.MethodGet:
			return routerVersionedOp("GetObjectAcl", "s3:GetObjectAcl", "s3:GetObjectVersionAcl")
		case http.MethodPut:
			return routerVersionedOp("PutObjectAcl", "s3:PutObjectAcl", "s3:PutObjectVersionAcl")
		default:
			return unauthorizedOp
		}
	}
	if query.Has("retention") {
		switch method {
		case http.MethodGet:
			return routerOp("GetObjectRetention", "s3:GetObjectRetention")
		case http.MethodPut:
			return routerOp("PutObjectRetention", "s3:PutObjectRetention")
		default:
			return unauthorizedOp
		}
	}
	if query.Has("legal-hold") {
		switch method {
		case http.MethodGet:
			return routerOp("GetObjectLegalHold", "s3:GetObjectLegalHold")
		case http.MethodPut:
			return routerOp("PutObjectLegalHold", "s3:PutObjectLegalHold")
		default:
			return unauthorizedOp
		}
	}
	if query.Has("uploadId") {
		switch method {
		case http.MethodPut:
			if query.Has("partNumber") {
				// UploadPartCopy also needs s3:GetObject on the copy
				// source, which the handler checks.
				if r.Header.Get("x-amz-copy-source") != "" {
					return routerOp("UploadPartCopy", "s3:PutObject")
				}
				return routerOp("UploadPart", "s3:PutObject")
			}
		case http.MethodPost:
			return routerOp("CompleteMultipartUpload", "s3:PutObject")
		case http.MethodDelete:
			return routerOp("AbortMultipartUpload", "s3:AbortMultipartUpload")
		case http.MethodGet:
			if query.Get("uploadId") != "" {
				return routerOp("ListParts", "s3:ListMultipartUploadParts")
			}
		}
	}
	if method == http.MethodPost && query.Has("uploads") {
		return routerOp("CreateMultipartUpload", "s3:PutObject")
	}
	if method == http.MethodPost && query.Has("restore") {
		return routerOp("RestoreObject", "s3:RestoreObject")
	}
	switch method {
	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			// Needs s3:GetObject on the source and s3:PutObject here.
			return handlerOp("CopyObject", "s3:PutObject", "")
		}
		// Policies may test the requested tags (x-amz-tagging).
		return handlerOp("PutObject", "s3:PutObject", "")
	case http.MethodGet:
		return routerVersionedOp("GetObject", "s3:GetObject", "s3:GetObjectVersion")
	case http.MethodHead:
		return routerVersionedOp("HeadObject", "s3:GetObject", "s3:GetObjectVersion")
	case http.MethodDelete:
		return routerVersionedOp("DeleteObject", "s3:DeleteObject", "s3:DeleteObjectVersion")
	default:
		return unauthorizedOp
	}
}

// authorizeCopySource checks read access to a copy source: s3:GetObject, or
// s3:GetObjectVersion when a source version is named, with the source's tags.
func (h *Handler) authorizeCopySource(r *http.Request, bucketName, key, versionID string) bool {
	action := "s3:GetObject"
	if versionID != "" {
		action = "s3:GetObjectVersion"
	}
	return h.checkAccessWithContext(r, bucketName, action, key, backend.PolicyEvalContext{
		ExistingObjectTags: h.existingObjectTagsForPolicy(bucketName, key, versionID),
	})
}

// bypassGovernanceAllowed reports whether the request asks to bypass
// GOVERNANCE retention (x-amz-bypass-governance-retention: true) and the
// caller holds s3:BypassGovernanceRetention. Without the permission the
// header is ignored, so retention still protects the object.
func (h *Handler) bypassGovernanceAllowed(r *http.Request, bucketName, key string) bool {
	if !strings.EqualFold(r.Header.Get("x-amz-bypass-governance-retention"), "true") {
		return false
	}
	return h.checkAccess(r, bucketName, "s3:BypassGovernanceRetention", key)
}
