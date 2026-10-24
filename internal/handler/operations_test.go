package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

const (
	authzBucket   = "authz-bucket"
	authzOwnerKey = "minis3-access-key"
	authzAltKey   = "minis3-alt-access-key"
)

// operationRoute is one request shape the router dispatches. Placeholders
// in target and headers: {vid} is the version ID of authz-bucket/obj and
// {upload} an upload ID for authz-bucket/obj.
type operationRoute struct {
	method  string
	target  string
	headers map[string]string
	body    string
	op      string
	// extra lists further actions the request needs (a copy source).
	extra []string
	// anonymous sends the request without credentials (POST Object forms).
	anonymous bool
	// ownerOnly: a policy cannot grant the operation to other users.
	ownerOnly bool
}

var operationRoutes = []operationRoute{
	// Bucket subresources.
	{method: "GET", target: "/?acl", op: "GetBucketAcl"},
	{
		method:  "PUT",
		target:  "/?acl",
		headers: map[string]string{"x-amz-acl": "private"},
		op:      "PutBucketAcl",
	},
	{method: "DELETE", target: "/?acl", op: ""},
	{method: "GET", target: "/?ownershipControls", op: "GetBucketOwnershipControls"},
	{method: "PUT", target: "/?ownershipControls", op: "PutBucketOwnershipControls"},
	{method: "DELETE", target: "/?ownershipControls", op: "DeleteBucketOwnershipControls"},
	{method: "GET", target: "/?requestPayment", op: "GetBucketRequestPayment"},
	{method: "PUT", target: "/?requestPayment", op: "PutBucketRequestPayment"},
	{method: "GET", target: "/?logging", op: "GetBucketLogging"},
	{method: "PUT", target: "/?logging", op: "PutBucketLogging", ownerOnly: true},
	{method: "POST", target: "/?logging", op: "PostBucketLogging"},
	{method: "DELETE", target: "/?logging", op: "DeleteBucketLogging"},
	{method: "GET", target: "/?versioning", op: "GetBucketVersioning"},
	{method: "PUT", target: "/?versioning", op: "PutBucketVersioning"},
	{method: "GET", target: "/?versions", op: "ListObjectVersions"},
	{method: "GET", target: "/?location", op: "GetBucketLocation"},
	{method: "GET", target: "/?tagging", op: "GetBucketTagging"},
	{method: "PUT", target: "/?tagging", op: "PutBucketTagging"},
	{method: "DELETE", target: "/?tagging", op: "DeleteBucketTagging"},
	{method: "GET", target: "/?policy", op: "GetBucketPolicy"},
	{method: "PUT", target: "/?policy", op: "PutBucketPolicy"},
	{method: "DELETE", target: "/?policy", op: "DeleteBucketPolicy"},
	{method: "GET", target: "/?policyStatus", op: "GetBucketPolicyStatus"},
	{method: "GET", target: "/?uploads", op: "ListMultipartUploads"},
	{method: "GET", target: "/?object-lock", op: "GetObjectLockConfiguration"},
	{method: "PUT", target: "/?object-lock", op: "PutObjectLockConfiguration"},
	{method: "GET", target: "/?lifecycle", op: "GetBucketLifecycleConfiguration"},
	{method: "PUT", target: "/?lifecycle", op: "PutBucketLifecycleConfiguration"},
	{method: "DELETE", target: "/?lifecycle", op: "DeleteBucketLifecycle"},
	{method: "GET", target: "/?encryption", op: "GetBucketEncryption"},
	{method: "PUT", target: "/?encryption", op: "PutBucketEncryption"},
	{method: "DELETE", target: "/?encryption", op: "DeleteBucketEncryption"},
	{method: "GET", target: "/?cors", op: "GetBucketCors"},
	{method: "PUT", target: "/?cors", op: "PutBucketCors"},
	{method: "DELETE", target: "/?cors", op: "DeleteBucketCors"},
	{method: "GET", target: "/?website", op: "GetBucketWebsite"},
	{method: "PUT", target: "/?website", op: "PutBucketWebsite"},
	{method: "DELETE", target: "/?website", op: "DeleteBucketWebsite"},
	{method: "GET", target: "/?publicAccessBlock", op: "GetPublicAccessBlock"},
	{method: "PUT", target: "/?publicAccessBlock", op: "PutPublicAccessBlock"},
	{method: "DELETE", target: "/?publicAccessBlock", op: "DeletePublicAccessBlock"},
	{method: "GET", target: "/?notification", op: ""},
	{method: "PUT", target: "/?replication", op: ""},
	{method: "DELETE", target: "/?analytics", op: ""},
	{method: "POST", target: "/?select", op: ""},
	// Bucket operations.
	{method: "GET", target: "/", op: "ListObjects"},
	{method: "GET", target: "/?list-type=2", op: "ListObjectsV2"},
	{method: "HEAD", target: "/", op: "HeadBucket"},
	{method: "PUT", target: "/", op: ""},
	{method: "DELETE", target: "/", op: "DeleteBucket"},
	{method: "PATCH", target: "/", op: ""},
	{
		method: "POST",
		target: "/?delete",
		body:   `<Delete><Object><Key>obj</Key></Object></Delete>`,
		op:     "DeleteObjects",
	},
	{
		method: "POST",
		target: "/?delete",
		body:   `<Delete><Object><Key>obj</Key><VersionId>{vid}</VersionId></Object></Delete>`,
		op:     "DeleteObjects",
	},
	{method: "POST", target: "/", op: "PostObject", anonymous: true},
	// Object subresources.
	{method: "GET", target: "/obj?tagging", op: "GetObjectTagging"},
	{method: "GET", target: "/obj?tagging&versionId={vid}", op: "GetObjectTagging"},
	{
		method: "PUT",
		target: "/obj?tagging",
		body:   `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`,
		op:     "PutObjectTagging",
	},
	{
		method: "PUT",
		target: "/obj?tagging&versionId={vid}",
		body:   `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`,
		op:     "PutObjectTagging",
	},
	{method: "DELETE", target: "/obj?tagging", op: "DeleteObjectTagging"},
	{method: "DELETE", target: "/obj?tagging&versionId={vid}", op: "DeleteObjectTagging"},
	{method: "POST", target: "/obj?tagging", op: ""},
	{
		method:  "GET",
		target:  "/obj?attributes",
		headers: map[string]string{"x-amz-object-attributes": "ETag"},
		op:      "GetObjectAttributes",
	},
	{
		method:  "GET",
		target:  "/obj?attributes&versionId={vid}",
		headers: map[string]string{"x-amz-object-attributes": "ETag"},
		op:      "GetObjectAttributes",
	},
	{method: "GET", target: "/obj?acl", op: "GetObjectAcl"},
	{method: "GET", target: "/obj?acl&versionId={vid}", op: "GetObjectAcl"},
	{
		method:  "PUT",
		target:  "/obj?acl",
		headers: map[string]string{"x-amz-acl": "private"},
		op:      "PutObjectAcl",
	},
	{
		method:  "PUT",
		target:  "/obj?acl&versionId={vid}",
		headers: map[string]string{"x-amz-acl": "private"},
		op:      "PutObjectAcl",
	},
	{method: "DELETE", target: "/obj?acl", op: ""},
	{method: "GET", target: "/obj?retention", op: "GetObjectRetention"},
	{method: "PUT", target: "/obj?retention", op: "PutObjectRetention"},
	{method: "DELETE", target: "/obj?retention", op: ""},
	{method: "GET", target: "/obj?legal-hold", op: "GetObjectLegalHold"},
	{method: "PUT", target: "/obj?legal-hold", op: "PutObjectLegalHold"},
	{method: "DELETE", target: "/obj?legal-hold", op: ""},
	{method: "GET", target: "/obj?torrent", op: ""},
	{method: "POST", target: "/obj?select&select-type=2", op: ""},
	// Multipart uploads.
	{method: "POST", target: "/obj?uploads", op: "CreateMultipartUpload"},
	{method: "PUT", target: "/obj?uploadId={upload}&partNumber=1", body: "part", op: "UploadPart"},
	{
		method:  "PUT",
		target:  "/obj?uploadId={upload}&partNumber=1",
		headers: map[string]string{"x-amz-copy-source": "/" + authzBucket + "/obj"},
		op:      "UploadPartCopy",
		extra:   []string{"s3:GetObject"},
	},
	{
		method:  "PUT",
		target:  "/obj?uploadId={upload}&partNumber=1",
		headers: map[string]string{"x-amz-copy-source": "/" + authzBucket + "/obj?versionId={vid}"},
		op:      "UploadPartCopy",
		extra:   []string{"s3:GetObjectVersion"},
	},
	{
		method: "POST",
		target: "/obj?uploadId={upload}",
		body:   `<CompleteMultipartUpload></CompleteMultipartUpload>`,
		op:     "CompleteMultipartUpload",
	},
	{method: "DELETE", target: "/obj?uploadId={upload}", op: "AbortMultipartUpload"},
	{method: "GET", target: "/obj?uploadId={upload}", op: "ListParts"},
	{
		method: "POST",
		target: "/obj?restore",
		body:   `<RestoreRequest><Days>1</Days></RestoreRequest>`,
		op:     "RestoreObject",
	},
	// Object operations.
	{method: "PUT", target: "/new-obj", body: "data", op: "PutObject"},
	{
		method:  "PUT",
		target:  "/copy-obj",
		headers: map[string]string{"x-amz-copy-source": "/" + authzBucket + "/obj"},
		op:      "CopyObject",
		extra:   []string{"s3:GetObject"},
	},
	{
		method:  "PUT",
		target:  "/copy-obj",
		headers: map[string]string{"x-amz-copy-source": "/" + authzBucket + "/obj?versionId={vid}"},
		op:      "CopyObject",
		extra:   []string{"s3:GetObjectVersion"},
	},
	{method: "GET", target: "/obj", op: "GetObject"},
	{method: "GET", target: "/obj?versionId={vid}", op: "GetObject"},
	{method: "HEAD", target: "/obj", op: "HeadObject"},
	{method: "HEAD", target: "/obj?versionId={vid}", op: "HeadObject"},
	{method: "DELETE", target: "/obj", op: "DeleteObject"},
	{method: "DELETE", target: "/obj?versionId={vid}", op: "DeleteObject"},
	{method: "PATCH", target: "/obj", op: ""},
	{method: "GET", target: "/bad%01key", op: ""},
}

// wantOperationActions is the IAM action of each operation, and of its
// versioned form (?versionId=), from the "Permissions" section of the Amazon
// S3 API Reference. It is kept apart from the router's table so a wrong
// entry there fails TestOperationTable and the matrix.
var wantOperationActions = map[string][2]string{
	"GetBucketAcl":                    {"s3:GetBucketAcl"},
	"PutBucketAcl":                    {"s3:PutBucketAcl"},
	"GetBucketOwnershipControls":      {"s3:GetBucketOwnershipControls"},
	"PutBucketOwnershipControls":      {"s3:PutBucketOwnershipControls"},
	"DeleteBucketOwnershipControls":   {"s3:PutBucketOwnershipControls"},
	"GetBucketRequestPayment":         {"s3:GetBucketRequestPayment"},
	"PutBucketRequestPayment":         {"s3:PutBucketRequestPayment"},
	"GetBucketLogging":                {"s3:GetBucketLogging"},
	"PutBucketLogging":                {"s3:PutBucketLogging"},
	"PostBucketLogging":               {"s3:PutBucketLogging"},
	"DeleteBucketLogging":             {"s3:PutBucketLogging"},
	"GetBucketVersioning":             {"s3:GetBucketVersioning"},
	"PutBucketVersioning":             {"s3:PutBucketVersioning"},
	"ListObjectVersions":              {"s3:ListBucketVersions"},
	"GetBucketLocation":               {"s3:GetBucketLocation"},
	"GetBucketTagging":                {"s3:GetBucketTagging"},
	"PutBucketTagging":                {"s3:PutBucketTagging"},
	"DeleteBucketTagging":             {"s3:PutBucketTagging"},
	"GetBucketPolicy":                 {"s3:GetBucketPolicy"},
	"PutBucketPolicy":                 {"s3:PutBucketPolicy"},
	"DeleteBucketPolicy":              {"s3:DeleteBucketPolicy"},
	"GetBucketPolicyStatus":           {"s3:GetBucketPolicyStatus"},
	"ListMultipartUploads":            {"s3:ListBucketMultipartUploads"},
	"GetObjectLockConfiguration":      {"s3:GetBucketObjectLockConfiguration"},
	"PutObjectLockConfiguration":      {"s3:PutBucketObjectLockConfiguration"},
	"GetBucketLifecycleConfiguration": {"s3:GetLifecycleConfiguration"},
	"PutBucketLifecycleConfiguration": {"s3:PutLifecycleConfiguration"},
	"DeleteBucketLifecycle":           {"s3:PutLifecycleConfiguration"},
	"GetBucketEncryption":             {"s3:GetEncryptionConfiguration"},
	"PutBucketEncryption":             {"s3:PutEncryptionConfiguration"},
	"DeleteBucketEncryption":          {"s3:PutEncryptionConfiguration"},
	"GetBucketCors":                   {"s3:GetBucketCORS"},
	"PutBucketCors":                   {"s3:PutBucketCORS"},
	"DeleteBucketCors":                {"s3:PutBucketCORS"},
	"GetBucketWebsite":                {"s3:GetBucketWebsite"},
	"PutBucketWebsite":                {"s3:PutBucketWebsite"},
	"DeleteBucketWebsite":             {"s3:DeleteBucketWebsite"},
	"GetPublicAccessBlock":            {"s3:GetBucketPublicAccessBlock"},
	"PutPublicAccessBlock":            {"s3:PutBucketPublicAccessBlock"},
	"DeletePublicAccessBlock":         {"s3:PutBucketPublicAccessBlock"},
	"ListObjects":                     {"s3:ListBucket"},
	"ListObjectsV2":                   {"s3:ListBucket"},
	"HeadBucket":                      {"s3:ListBucket"},
	"DeleteBucket":                    {"s3:DeleteBucket"},
	"DeleteObjects":                   {"s3:DeleteObject", "s3:DeleteObjectVersion"},
	"PostObject":                      {"s3:PutObject"},
	"GetObjectTagging":                {"s3:GetObjectTagging", "s3:GetObjectVersionTagging"},
	"PutObjectTagging":                {"s3:PutObjectTagging", "s3:PutObjectVersionTagging"},
	"DeleteObjectTagging":             {"s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging"},
	"GetObjectAttributes":             {"s3:GetObjectAttributes", "s3:GetObjectVersionAttributes"},
	"GetObjectAcl":                    {"s3:GetObjectAcl", "s3:GetObjectVersionAcl"},
	"PutObjectAcl":                    {"s3:PutObjectAcl", "s3:PutObjectVersionAcl"},
	"GetObjectRetention":              {"s3:GetObjectRetention"},
	"PutObjectRetention":              {"s3:PutObjectRetention"},
	"GetObjectLegalHold":              {"s3:GetObjectLegalHold"},
	"PutObjectLegalHold":              {"s3:PutObjectLegalHold"},
	"CreateMultipartUpload":           {"s3:PutObject"},
	"UploadPart":                      {"s3:PutObject"},
	"UploadPartCopy":                  {"s3:PutObject"},
	"CompleteMultipartUpload":         {"s3:PutObject"},
	"AbortMultipartUpload":            {"s3:AbortMultipartUpload"},
	"ListParts":                       {"s3:ListMultipartUploadParts"},
	"RestoreObject":                   {"s3:RestoreObject"},
	"PutObject":                       {"s3:PutObject"},
	"CopyObject":                      {"s3:PutObject"},
	"GetObject":                       {"s3:GetObject", "s3:GetObjectVersion"},
	"HeadObject":                      {"s3:GetObject", "s3:GetObjectVersion"},
	"DeleteObject":                    {"s3:DeleteObject", "s3:DeleteObjectVersion"},
}

// wantAction returns the expected IAM action for a route.
func (route operationRoute) wantAction() string {
	want := wantOperationActions[route.op]
	if want[1] != "" && strings.Contains(route.target+route.body, "{vid}") &&
		!strings.Contains(route.headers["x-amz-copy-source"], "{vid}") {
		return want[1]
	}
	return want[0]
}

// authzFixture is a private, versioned bucket owned by minis3-access-key
// holding one object version and one multipart upload.
type authzFixture struct {
	h         *Handler
	b         *backend.Backend
	versionID string
	uploadID  string
}

func newAuthzFixture(t *testing.T) authzFixture {
	t.Helper()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, authzBucket)
	b.SetBucketOwner(authzBucket, authzOwnerKey)
	if err := b.SetBucketVersioning(
		authzBucket,
		backend.VersioningEnabled,
		backend.MFADeleteDisabled,
	); err != nil {
		t.Fatalf("SetBucketVersioning: %v", err)
	}
	obj, err := b.PutObject(authzBucket, "obj", []byte("data"), backend.PutObjectOptions{})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	upload, err := b.CreateMultipartUpload(
		authzBucket,
		"obj",
		backend.CreateMultipartUploadOptions{},
	)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	return authzFixture{h: h, b: b, versionID: obj.VersionId, uploadID: upload.UploadId}
}

func (f authzFixture) expand(s string) string {
	return strings.NewReplacer("{vid}", f.versionID, "{upload}", f.uploadID).Replace(s)
}

func (f authzFixture) request(t *testing.T, route operationRoute, accessKey string) *http.Request {
	t.Helper()
	target := "http://example.test/" + authzBucket + f.expand(route.target)
	var req *http.Request
	if route.op == "PostObject" {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("key", "form-obj")
		fw, _ := mw.CreateFormFile("file", "f.txt")
		_, _ = fw.Write([]byte("form"))
		_ = mw.Close()
		req = httptest.NewRequest(route.method, target, &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
	} else {
		req = httptest.NewRequest(route.method, target, strings.NewReader(route.body))
	}
	for k, v := range route.headers {
		req.Header.Set(k, f.expand(v))
	}
	if accessKey != "" {
		req.Header.Set("Authorization", authHeader(accessKey))
	}
	return req
}

func (f authzFixture) setPolicy(t *testing.T, policy string) {
	t.Helper()
	if err := f.b.PutBucketPolicy(authzBucket, policy, false); err != nil {
		t.Fatalf("PutBucketPolicy(%s): %v", policy, err)
	}
}

func policyJSON(effect, actionElement string, actions []string, principal string) string {
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[{"Effect":%q,"Principal":%s,%q:[%s],"Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`,
		effect,
		principal,
		actionElement,
		strings.Join(quoted, ","),
		authzBucket,
		authzBucket,
	)
}

// denied reports whether the response refused the request: 403
// AccessDenied, or for
// DeleteObjects an AccessDenied entry in the result.
func denied(t *testing.T, route operationRoute, w *httptest.ResponseRecorder) bool {
	t.Helper()
	if w.Code == http.StatusForbidden {
		// HEAD responses carry no body.
		if w.Body.Len() == 0 {
			return true
		}
		var er s3ErrorResponse
		if err := xml.Unmarshal(w.Body.Bytes(), &er); err != nil {
			t.Fatalf("403 body: %v body=%s", err, w.Body.String())
		}
		return er.Code == "AccessDenied"
	}
	if route.op == "DeleteObjects" && w.Code == http.StatusOK {
		var result backend.DeleteResult
		if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("DeleteObjects result: %v body=%s", err, w.Body.String())
		}
		for _, e := range result.Errors {
			if e.Code == "AccessDenied" {
				return true
			}
		}
	}
	return false
}

func TestOperationTable(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, route := range operationRoutes {
		f := authzFixture{versionID: "v", uploadID: "u"}
		req := f.request(t, route, authzOwnerKey)
		_, key := extractBucketAndKey(req.URL.Path)
		op := resolveS3Operation(req, key)
		if op.Name != route.op {
			t.Errorf("%s %s resolves to %q, want %q", route.method, route.target, op.Name, route.op)
		}
		if (op.Auth == authNone) != (route.op == "") {
			t.Errorf(
				"%s %s: auth mode %v for operation %q",
				route.method,
				route.target,
				op.Auth,
				op.Name,
			)
		}
		for _, action := range []string{op.Action, op.VersionAction} {
			if action != "" && !backend.IsKnownS3PolicyAction(action) {
				t.Errorf("%s uses unknown IAM action %q", op.Name, action)
			}
		}
		if route.op != "" && route.op != "DeleteObjects" {
			if got, want := op.action(req.URL.Query()), route.wantAction(); got != want {
				t.Errorf("%s %s authorizes %q, want %q", route.method, route.target, got, want)
			}
		}
		seen[op.Name] = true
	}
	// Every operation in the bucket subresource table has a route.
	for _, entries := range bucketSubresourceOperations {
		for _, entry := range entries {
			if !seen[entry.op.Name] {
				t.Errorf("no route covers %s", entry.op.Name)
			}
		}
	}
}

// TestOperationAuthorizationMatrix sends every route as a non-owner and as
// the owner under four bucket policies and checks that exactly the
// operation's IAM actions decide the outcome:
//
//   - no policy: a non-owner without ACL grants is denied;
//   - Allow of the operation's actions: the non-owner gets past authorization;
//   - Allow of everything but one of them (NotAction): denied;
//   - Deny of the operation's action: the owner is denied too, except for
//     the bucket policy operations the owner may always manage.
func TestOperationAuthorizationMatrix(t *testing.T) {
	t.Parallel()
	for _, route := range operationRoutes {
		if route.op == "" {
			continue
		}
		name := route.method + " " + route.target
		if len(route.headers) > 0 && route.headers["x-amz-copy-source"] != "" {
			name += " copy " + route.headers["x-amz-copy-source"]
		}
		t.Run(name, func(t *testing.T) {
			action := route.wantAction()
			actions := append([]string{action}, route.extra...)
			caller := authzAltKey
			principal := `{"AWS":"` + authzAltKey + `"}`
			if route.anonymous {
				caller = ""
				principal = `"*"`
			}

			f := newAuthzFixture(t)
			if w := doRequest(f.h, f.request(t, route, caller)); !denied(t, route, w) {
				t.Fatalf(
					"without a policy: status %d, want AccessDenied, body=%s",
					w.Code,
					w.Body.String(),
				)
			}

			f = newAuthzFixture(t)
			f.setPolicy(t, policyJSON("Allow", "Action", actions, principal))
			if w := doRequest(
				f.h,
				f.request(t, route, caller),
			); denied(
				t,
				route,
				w,
			) != route.ownerOnly {
				t.Fatalf("Allow %v: status %d, denied=%v, want %v, body=%s",
					actions, w.Code, !route.ownerOnly, route.ownerOnly, w.Body.String())
			}

			for _, missing := range actions {
				f = newAuthzFixture(t)
				f.setPolicy(t, policyJSON("Allow", "NotAction", []string{missing}, principal))
				if w := doRequest(f.h, f.request(t, route, caller)); !denied(t, route, w) {
					t.Fatalf("Allow all but %s: status %d, want AccessDenied, body=%s",
						missing, w.Code, w.Body.String())
				}
			}

			if route.anonymous {
				return
			}
			f = newAuthzFixture(t)
			f.setPolicy(t, policyJSON("Deny", "Action", []string{action}, `"*"`))
			w := doRequest(f.h, f.request(t, route, authzOwnerKey))
			if want := !isBucketPolicyAction(action); denied(t, route, w) != want {
				t.Fatalf("Deny %s for the owner: status %d, denied=%v want %v, body=%s",
					action, w.Code, !want, want, w.Body.String())
			}
		})
	}
}

func TestBypassGovernanceRetentionNeedsPermission(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T, actions ...string) (*Handler, string) {
		t.Helper()
		h, b := newTestHandler(t)
		mustCreateObjectLockBucket(t, b, authzBucket)
		b.SetBucketOwner(authzBucket, authzOwnerKey)
		until := time.Now().Add(24 * time.Hour)
		obj, err := b.PutObject(authzBucket, "locked", []byte("x"), backend.PutObjectOptions{
			RetentionMode:   backend.RetentionModeGovernance,
			RetainUntilDate: &until,
		})
		if err != nil {
			t.Fatalf("PutObject: %v", err)
		}
		if len(actions) > 0 {
			policy := policyJSON("Allow", "Action", actions, `{"AWS":"`+authzAltKey+`"}`)
			if err := b.PutBucketPolicy(authzBucket, policy, false); err != nil {
				t.Fatalf("PutBucketPolicy: %v", err)
			}
		}
		return h, obj.VersionId
	}
	del := func(h *Handler, versionID, accessKey string) *httptest.ResponseRecorder {
		return doRequest(h, newRequest(
			http.MethodDelete,
			"http://example.test/"+authzBucket+"/locked?versionId="+versionID,
			"",
			map[string]string{
				"Authorization":                     authHeader(accessKey),
				"x-amz-bypass-governance-retention": "true",
			},
		))
	}

	t.Run("without s3:BypassGovernanceRetention the header is ignored", func(t *testing.T) {
		h, vid := setup(t, "s3:DeleteObjectVersion")
		w := del(h, vid, authzAltKey)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})
	t.Run("with s3:BypassGovernanceRetention the version is deleted", func(t *testing.T) {
		h, vid := setup(t, "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention")
		requireStatus(t, del(h, vid, authzAltKey), http.StatusNoContent)
	})
	t.Run("the bucket owner may bypass", func(t *testing.T) {
		h, vid := setup(t)
		requireStatus(t, del(h, vid, authzOwnerKey), http.StatusNoContent)
	})
	t.Run("DeleteObjects applies the same rule", func(t *testing.T) {
		for _, tc := range []struct {
			actions []string
			want    string
		}{
			{[]string{"s3:DeleteObjectVersion"}, "AccessDenied"},
			{[]string{"s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"}, ""},
		} {
			h, vid := setup(t, tc.actions...)
			w := doRequest(h, newRequest(
				http.MethodPost,
				"http://example.test/"+authzBucket+"?delete",
				`<Delete><Object><Key>locked</Key><VersionId>`+vid+`</VersionId></Object></Delete>`,
				map[string]string{
					"Authorization":                     authHeader(authzAltKey),
					"x-amz-bypass-governance-retention": "true",
				},
			))
			requireStatus(t, w, http.StatusOK)
			var result backend.DeleteResult
			if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatalf("decode: %v", err)
			}
			got := ""
			if len(result.Errors) > 0 {
				got = result.Errors[0].Code
			}
			if got != tc.want || (tc.want == "" && len(result.Deleted) != 1) {
				t.Fatalf("actions %v: result %+v, want error %q", tc.actions, result, tc.want)
			}
		}
	})
	t.Run("PutObjectRetention applies the same rule", func(t *testing.T) {
		shorten := func(h *Handler, vid string) *httptest.ResponseRecorder {
			soon := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
			return doRequest(h, newRequest(
				http.MethodPut,
				"http://example.test/"+authzBucket+"/locked?retention&versionId="+vid,
				`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>`+soon+`</RetainUntilDate></Retention>`,
				map[string]string{
					"Authorization":                     authHeader(authzAltKey),
					"x-amz-bypass-governance-retention": "true",
				},
			))
		}
		h, vid := setup(t, "s3:PutObjectRetention")
		if w := shorten(h, vid); w.Code != http.StatusForbidden {
			t.Fatalf(
				"shortening without bypass permission: status %d, body=%s",
				w.Code,
				w.Body.String(),
			)
		}
		h, vid = setup(t, "s3:PutObjectRetention", "s3:BypassGovernanceRetention")
		requireStatus(t, shorten(h, vid), http.StatusOK)
	})
}

func TestDeleteObjectsAuthorizesEachKey(t *testing.T) {
	t.Parallel()
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, authzBucket)
	b.SetBucketOwner(authzBucket, authzOwnerKey)
	mustPutObject(t, b, authzBucket, "allowed/1", "a")
	mustPutObject(t, b, authzBucket, "denied/1", "b")
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
		authzAltKey + `"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::` + authzBucket + `/allowed/*"}]}`
	if err := b.PutBucketPolicy(authzBucket, policy, false); err != nil {
		t.Fatalf("PutBucketPolicy: %v", err)
	}
	w := doRequest(h, newRequest(
		http.MethodPost,
		"http://example.test/"+authzBucket+"?delete",
		`<Delete><Object><Key>allowed/1</Key></Object><Object><Key>denied/1</Key></Object></Delete>`,
		map[string]string{"Authorization": authHeader(authzAltKey)},
	))
	requireStatus(t, w, http.StatusOK)
	var result backend.DeleteResult
	if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Deleted) != 1 || result.Deleted[0].Key != "allowed/1" {
		t.Fatalf("Deleted = %+v, want only allowed/1", result.Deleted)
	}
	if len(result.Errors) != 1 || result.Errors[0].Key != "denied/1" ||
		result.Errors[0].Code != "AccessDenied" {
		t.Fatalf("Errors = %+v, want AccessDenied for denied/1", result.Errors)
	}
	if _, err := b.GetObject(authzBucket, "denied/1"); err != nil {
		t.Fatalf("denied/1 was deleted: %v", err)
	}
}

func TestPostObjectAuthorizesTheFormSigner(t *testing.T) {
	t.Parallel()
	post := func(t *testing.T, h *Handler, accessKey string) *httptest.ResponseRecorder {
		t.Helper()
		fields := map[string]string{"key": "form-obj"}
		if accessKey != "" {
			policy := encodePolicy(t, map[string]any{
				"expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"conditions": []any{
					map[string]string{"bucket": authzBucket},
					[]string{"starts-with", "$key", ""},
				},
			})
			mac := hmac.New(sha1.New, []byte(DefaultCredentials()[accessKey]))
			_, _ = mac.Write([]byte(policy))
			fields["AWSAccessKeyId"] = accessKey
			fields["policy"] = policy
			fields["signature"] = base64.StdEncoding.EncodeToString(mac.Sum(nil))
		}
		return doRequest(h, makeMultipartReqWithFilename(
			t, "http://example.test/"+authzBucket, fields, "file", "f.txt", "body",
		))
	}
	newBucket := func(t *testing.T) (*Handler, *backend.Backend) {
		h, b := newTestHandler(t)
		mustCreateBucket(t, b, authzBucket)
		b.SetBucketOwner(authzBucket, authzOwnerKey)
		return h, b
	}

	h, _ := newBucket(t)
	if w := post(t, h, authzOwnerKey); w.Code >= 300 {
		t.Fatalf("owner-signed form: status %d, body=%s", w.Code, w.Body.String())
	}
	for _, caller := range []string{"", authzAltKey} {
		h, _ := newBucket(t)
		w := post(t, h, caller)
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	}

	// A policy naming the form's signer grants the upload.
	h, b := newBucket(t)
	policy := policyJSON("Allow", "Action", []string{"s3:PutObject"}, `{"AWS":"`+authzAltKey+`"}`)
	if err := b.PutBucketPolicy(authzBucket, policy, false); err != nil {
		t.Fatalf("PutBucketPolicy: %v", err)
	}
	if w := post(t, h, authzAltKey); w.Code >= 300 {
		t.Fatalf("alt-signed form with policy: status %d, body=%s", w.Code, w.Body.String())
	}
	obj, err := b.GetObject(authzBucket, "form-obj")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if want := backend.OwnerForAccessKey(authzAltKey).ID; obj.Owner == nil || obj.Owner.ID != want {
		t.Fatalf("object owner = %+v, want the form signer %s", obj.Owner, want)
	}
}
