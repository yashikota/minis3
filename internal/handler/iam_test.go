package handler

import (
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
)

func TestIAMCreateUserAndAccessKey(t *testing.T) {
	h, _ := newTestHandler(t)

	rootHeaders := map[string]string{"Authorization": authHeader("root-access-key")}

	// CreateUser via POST form
	wCreate := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateUser&UserName=testiam&Path=/s3-tests/",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, wCreate, http.StatusCreated)
	if !strings.Contains(wCreate.Body.String(), "<UserName>testiam</UserName>") {
		t.Fatalf("CreateUser response missing UserName: %s", wCreate.Body.String())
	}

	// CreateAccessKey
	wKey := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateAccessKey&UserName=testiam",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, wKey, http.StatusCreated)
	body := wKey.Body.String()
	if !strings.Contains(body, "<AccessKeyId>") {
		t.Fatalf("CreateAccessKey response missing AccessKeyId: %s", body)
	}
	if !strings.Contains(body, "<SecretAccessKey>") {
		t.Fatalf("CreateAccessKey response missing SecretAccessKey: %s", body)
	}

	// Extract the access key from response
	type accessKeyResp struct {
		XMLName xml.Name `xml:"CreateAccessKeyResponse"`
		Result  struct {
			AccessKey struct {
				AccessKeyId     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	var akr accessKeyResp
	if err := xml.Unmarshal(wKey.Body.Bytes(), &akr); err != nil {
		t.Fatalf("failed to parse CreateAccessKey response: %v", err)
	}

	// The newly created access key should be usable for auth
	// (we verify the credential lookup works)
	secret, ok := credentialLookupFn(akr.Result.AccessKey.AccessKeyId)
	if !ok {
		t.Fatal("newly created access key should be found in credential lookup")
	}
	if secret != akr.Result.AccessKey.SecretAccessKey {
		t.Fatal("secret key mismatch")
	}

	// ListUsers
	wList := doRequest(h, newRequest(
		http.MethodGet, "http://example.test/?Action=ListUsers&PathPrefix=/s3-tests/",
		"", rootHeaders,
	))
	requireStatus(t, wList, http.StatusOK)
	if !strings.Contains(wList.Body.String(), "<UserName>testiam</UserName>") {
		t.Fatalf("ListUsers should contain testiam: %s", wList.Body.String())
	}

	// ListAccessKeys
	wListKeys := doRequest(h, newRequest(
		http.MethodGet, "http://example.test/?Action=ListAccessKeys&UserName=testiam",
		"", rootHeaders,
	))
	requireStatus(t, wListKeys, http.StatusOK)
	if !strings.Contains(wListKeys.Body.String(), akr.Result.AccessKey.AccessKeyId) {
		t.Fatalf("ListAccessKeys should contain the key: %s", wListKeys.Body.String())
	}

	// DeleteAccessKey
	wDelKey := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=DeleteAccessKey&UserName=testiam&AccessKeyId="+akr.Result.AccessKey.AccessKeyId,
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, wDelKey, http.StatusOK)

	// DeleteUser
	wDelUser := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=DeleteUser&UserName=testiam",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, wDelUser, http.StatusOK)
}

func TestIAMStubActions(t *testing.T) {
	h, _ := newTestHandler(t)

	rootHeaders := map[string]string{"Authorization": authHeader("root-access-key")}

	stubs := []struct {
		action   string
		contains string
	}{
		{"ListUserPolicies", "ListUserPoliciesResponse"},
		{"ListAttachedUserPolicies", "ListAttachedUserPoliciesResponse"},
		{"ListGroups", "ListGroupsResponse"},
		{"ListRoles", "ListRolesResponse"},
		{"ListOpenIDConnectProviders", "ListOpenIDConnectProvidersResponse"},
	}

	for _, s := range stubs {
		t.Run(s.action, func(t *testing.T) {
			w := doRequest(h, newRequest(
				http.MethodGet,
				"http://example.test/?Action="+s.action,
				"", rootHeaders,
			))
			requireStatus(t, w, http.StatusOK)
			if !strings.Contains(w.Body.String(), s.contains) {
				t.Fatalf("expected %s in body: %s", s.contains, w.Body.String())
			}
		})
	}
}

func TestIAMCreateUserConflict(t *testing.T) {
	h, _ := newTestHandler(t)

	// Create user first time
	doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateUser&UserName=dup",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))

	// Second time should conflict
	w := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateUser&UserName=dup",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, w, http.StatusConflict)
}

func TestIAMCreateAccessKeyUserNotFound(t *testing.T) {
	h, _ := newTestHandler(t)

	w := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateAccessKey&UserName=nonexistent",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))
	requireStatus(t, w, http.StatusNotFound)
}

func TestBucketPolicyDenySelfE2E(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "deny-self-bucket")
	b.SetBucketOwner("deny-self-bucket", "root-access-key")

	ownerHeaders := map[string]string{"Authorization": authHeader("root-access-key")}
	altHeaders := map[string]string{"Authorization": authHeader("minis3-alt-access-key")}

	denyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:PutBucketPolicy","s3:GetBucketPolicy","s3:DeleteBucketPolicy"],"Resource":["arn:aws:s3:::deny-self-bucket","arn:aws:s3:::deny-self-bucket/*"]}]}`

	// Put policy without ConfirmRemoveSelfBucketAccess
	wPut := doRequest(h, newRequest(
		http.MethodPut,
		"http://example.test/deny-self-bucket?policy",
		denyPolicy,
		ownerHeaders,
	))
	requireStatus(t, wPut, http.StatusNoContent)

	t.Run("non-owner denied", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodGet, "http://example.test/deny-self-bucket?policy", "", altHeaders,
		))
		requireStatus(t, w, http.StatusForbidden)
		requireS3ErrorCode(t, w, "AccessDenied")
	})

	t.Run("owner allowed (no confirm header)", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodGet, "http://example.test/deny-self-bucket?policy", "", ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)
	})

	t.Run("owner can delete policy", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodDelete, "http://example.test/deny-self-bucket?policy", "", ownerHeaders,
		))
		requireStatus(t, w, http.StatusNoContent)
	})

	t.Run("owner can re-put policy", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodPut,
			"http://example.test/deny-self-bucket?policy",
			denyPolicy,
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusNoContent)
	})

	// Now put with ConfirmRemoveSelfBucketAccess header
	t.Run("with ConfirmRemoveSelfBucketAccess", func(t *testing.T) {
		wConfirm := doRequest(h, newRequest(
			http.MethodPut,
			"http://example.test/deny-self-bucket?policy",
			denyPolicy,
			map[string]string{
				"Authorization": authHeader("root-access-key"),
				"x-amz-confirm-remove-self-bucket-access": "true",
			},
		))
		requireStatus(t, wConfirm, http.StatusNoContent)

		// Owner should now be denied too
		wGet := doRequest(h, newRequest(
			http.MethodGet, "http://example.test/deny-self-bucket?policy", "", ownerHeaders,
		))
		requireStatus(t, wGet, http.StatusForbidden)
		requireS3ErrorCode(t, wGet, "AccessDenied")

		wDel := doRequest(h, newRequest(
			http.MethodDelete, "http://example.test/deny-self-bucket?policy", "", ownerHeaders,
		))
		requireStatus(t, wDel, http.StatusForbidden)
		requireS3ErrorCode(t, wDel, "AccessDenied")

		wPut := doRequest(h, newRequest(
			http.MethodPut,
			"http://example.test/deny-self-bucket?policy",
			denyPolicy,
			ownerHeaders,
		))
		requireStatus(t, wPut, http.StatusForbidden)
		requireS3ErrorCode(t, wPut, "AccessDenied")
	})
}

func TestBucketPolicyDenySelfWithIAMUser(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "iam-deny-bucket")
	b.SetBucketOwner("iam-deny-bucket", "root-access-key")

	ownerHeaders := map[string]string{"Authorization": authHeader("root-access-key")}

	// Create IAM user via handler
	doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateUser&UserName=iamtestuser&Path=/s3-tests/",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))

	wKey := doRequest(h, newRequest(
		http.MethodPost, "http://example.test/",
		"Action=CreateAccessKey&UserName=iamtestuser",
		map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": authHeader("root-access-key"),
		},
	))

	type akResp struct {
		XMLName xml.Name `xml:"CreateAccessKeyResponse"`
		Result  struct {
			AccessKey struct {
				AccessKeyId string `xml:"AccessKeyId"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	var akr akResp
	_ = xml.Unmarshal(wKey.Body.Bytes(), &akr)

	iamUserHeaders := map[string]string{
		"Authorization": "AWS " + akr.Result.AccessKey.AccessKeyId + ":sig",
	}

	denyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:PutBucketPolicy","s3:GetBucketPolicy","s3:DeleteBucketPolicy"],"Resource":["arn:aws:s3:::iam-deny-bucket","arn:aws:s3:::iam-deny-bucket/*"]}]}`

	// Set deny policy without confirm header
	wPut := doRequest(h, newRequest(
		http.MethodPut,
		"http://example.test/iam-deny-bucket?policy",
		denyPolicy,
		ownerHeaders,
	))
	requireStatus(t, wPut, http.StatusNoContent)

	// IAM user (not owner) should be denied
	wIAMGet := doRequest(h, newRequest(
		http.MethodGet, "http://example.test/iam-deny-bucket?policy", "", iamUserHeaders,
	))
	requireStatus(t, wIAMGet, http.StatusForbidden)

	// Owner should still have access
	wOwnerGet := doRequest(h, newRequest(
		http.MethodGet, "http://example.test/iam-deny-bucket?policy", "", ownerHeaders,
	))
	requireStatus(t, wOwnerGet, http.StatusOK)
}

func TestIsBucketPolicyAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"s3:GetBucketPolicy", true},
		{"s3:PutBucketPolicy", true},
		{"s3:DeleteBucketPolicy", true},
		{"s3:GetObject", false},
		{"s3:PutObject", false},
		{"s3:ListBucket", false},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			if got := isBucketPolicyAction(tc.action); got != tc.want {
				t.Fatalf("isBucketPolicyAction(%q) = %v, want %v", tc.action, got, tc.want)
			}
		})
	}
}
