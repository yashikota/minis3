package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yashikota/minis3/internal/backend"
)

func mustPutBucketPolicy(t *testing.T, b *backend.Backend, bucketName, policy string) {
	t.Helper()
	if err := b.PutBucketPolicy(bucketName, policy, false); err != nil {
		t.Fatalf("PutBucketPolicy(%q) failed: %v", bucketName, err)
	}
}

func allowLoggingPolicy(sourceBucket, targetBucket, targetPrefix, sourceAccount string) string {
	return fmt.Sprintf(
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"%s","Condition":{"ArnLike":{"aws:SourceArn":"%s"},"StringEquals":{"aws:SourceAccount":"%s"}}}]}`,
		qualifiedBucketObjectARN(targetBucket, targetPrefix),
		qualifiedBucketARN(sourceBucket, ""),
		sourceAccount,
	)
}

func TestBucketLoggingOwnershipAndRequestPaymentBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-log")
	mustCreateBucket(t, b, "dst-log")
	b.SetBucketOwner("src-log", "minis3-access-key")
	b.SetBucketOwner("dst-log", "minis3-access-key")
	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner for minis3-access-key must exist")
		return
	}
	mustPutBucketPolicy(
		t,
		b,
		"dst-log",
		allowLoggingPolicy("src-log", "dst-log", "logs/", owner.ID),
	)

	t.Run("ownership controls handlers", func(t *testing.T) {
		wDenied := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/src-log?ownershipControls", "", nil),
		)
		requireStatus(t, wDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wDenied, "AccessDenied")

		wNoBucket := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-bucket?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wNoBucket, "NoSuchBucket")

		wNotFound := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/src-log?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wNotFound, http.StatusNotFound)
		requireS3ErrorCode(t, wNotFound, "OwnershipControlsNotFoundError")

		wReadErr := newRequest(
			http.MethodPut,
			"http://example.test/src-log?ownershipControls",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		wReadErr.Body = io.NopCloser(failingReader{})
		wPutReadErr := doRequest(h, wReadErr)
		requireStatus(t, wPutReadErr, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutReadErr, "InvalidRequest")

		wMalformed := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?ownershipControls",
				`<OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wMalformed, "MalformedXML")

		wInvalid := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?ownershipControls",
				`<OwnershipControls><Rule><ObjectOwnership>INVALID</ObjectOwnership></Rule></OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wInvalid, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalid, "InvalidRequest")

		wPutOK := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?ownershipControls",
				`<OwnershipControls><Rule><ObjectOwnership>BucketOwnerPreferred</ObjectOwnership></Rule></OwnershipControls>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/src-log?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetOK, http.StatusOK)

		wDelNoBucket := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/no-bucket?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDelNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wDelNoBucket, "NoSuchBucket")

		wDelOK := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/src-log?ownershipControls",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDelOK, http.StatusNoContent)
	})

	t.Run("request payment handlers", func(t *testing.T) {
		wGetDenied := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/src-log?requestPayment", "", nil),
		)
		requireStatus(t, wGetDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wGetDenied, "AccessDenied")

		wGetNoBucket := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-bucket?requestPayment",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		wGetDefault := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/src-log?requestPayment",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetDefault, http.StatusOK)

		reqReadErr := newRequest(
			http.MethodPut,
			"http://example.test/src-log?requestPayment",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		reqReadErr.Body = io.NopCloser(failingReader{})
		wPutReadErr := doRequest(h, reqReadErr)
		requireStatus(t, wPutReadErr, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutReadErr, "InvalidRequest")

		wPutMalformed := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?requestPayment",
				`<RequestPaymentConfiguration>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutMalformed, "MalformedXML")

		wPutInvalid := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?requestPayment",
				`<RequestPaymentConfiguration><Payer>Invalid</Payer></RequestPaymentConfiguration>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutInvalid, http.StatusBadRequest)
		requireS3ErrorCode(t, wPutInvalid, "MalformedXML")

		wPutNoBucket := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/no-bucket?requestPayment",
				`<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wPutNoBucket, "NoSuchBucket")

		wPutOK := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?requestPayment",
				`<RequestPaymentConfiguration><Payer>Requester</Payer></RequestPaymentConfiguration>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutOK, http.StatusOK)
	})

	t.Run("bucket logging handlers", func(t *testing.T) {
		wGetDenied := doRequest(
			h,
			newRequest(http.MethodGet, "http://example.test/src-log?logging", "", nil),
		)
		requireStatus(t, wGetDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wGetDenied, "AccessDenied")

		wGetNoBucket := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/no-bucket?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wGetNoBucket, "NoSuchBucket")

		b.SetBucketOwner("src-log", "root-access-key")
		wOwnerDenied := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus/>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wOwnerDenied, http.StatusForbidden)
		requireS3ErrorCode(t, wOwnerDenied, "AccessDenied")
		b.SetBucketOwner("src-log", "minis3-access-key")

		reqReadErr := newRequest(
			http.MethodPut,
			"http://example.test/src-log?logging",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		reqReadErr.Body = io.NopCloser(failingReader{})
		wReadErr := doRequest(h, reqReadErr)
		requireStatus(t, wReadErr, http.StatusBadRequest)
		requireS3ErrorCode(t, wReadErr, "InvalidRequest")

		wMalformed := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wMalformed, http.StatusBadRequest)
		requireS3ErrorCode(t, wMalformed, "MalformedXML")

		wInvalidTarget := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>:</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wInvalidTarget, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalidTarget, "InvalidArgument")

		wInvalidPartition := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>dst-log</TargetBucket><TargetPrefix>logs/</TargetPrefix><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>InvalidSource</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wInvalidPartition, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalidPartition, "MalformedXML")

		wMissingTarget := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>missing-target</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wMissingTarget, http.StatusNotFound)
		requireS3ErrorCode(t, wMissingTarget, "NoSuchKey")

		// No policy on target -> AccessDenied from bucketLoggingTargetAllowed.
		if err := b.PutBucketPolicy("dst-log", `{"Version":"2012-10-17","Statement":[]}`, false); err != nil {
			t.Fatalf("PutBucketPolicy reset failed: %v", err)
		}
		wDeniedPolicy := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>dst-log</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeniedPolicy, http.StatusForbidden)
		requireS3ErrorCode(t, wDeniedPolicy, "AccessDenied")

		// Allowed by policy but backend rejects requester-pays target.
		mustPutBucketPolicy(
			t,
			b,
			"dst-log",
			allowLoggingPolicy("src-log", "dst-log", "logs/", owner.ID),
		)
		if err := b.PutBucketRequestPayment(
			"dst-log",
			&backend.RequestPaymentConfiguration{Payer: backend.RequestPayerRequester},
		); err != nil {
			t.Fatalf("PutBucketRequestPayment failed: %v", err)
		}
		wInvalidRequest := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>dst-log</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wInvalidRequest, http.StatusBadRequest)
		requireS3ErrorCode(t, wInvalidRequest, "InvalidArgument")

		if err := b.PutBucketRequestPayment(
			"dst-log",
			&backend.RequestPaymentConfiguration{Payer: backend.RequestPayerBucketOwner},
		); err != nil {
			t.Fatalf("PutBucketRequestPayment reset failed: %v", err)
		}
		mustPutBucketPolicy(
			t,
			b,
			"dst-log",
			allowLoggingPolicy("src-log", "dst-log", "logs/", owner.ID),
		)
		wPutOK := doRequest(
			h,
			newRequest(
				http.MethodPut,
				"http://example.test/src-log?logging",
				`<BucketLoggingStatus><LoggingEnabled><TargetBucket>dst-log</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wPutOK, http.StatusOK)

		wGetOK := doRequest(
			h,
			newRequest(
				http.MethodGet,
				"http://example.test/src-log?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wGetOK, http.StatusOK)
		if got := wGetOK.Header().Get("Last-Modified"); got == "" {
			t.Fatal("Last-Modified should be set when logging config was modified")
		}

		wDeleteNoBucket := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/no-bucket?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeleteNoBucket, http.StatusNotFound)
		requireS3ErrorCode(t, wDeleteNoBucket, "NoSuchBucket")

		wDeleteOK := doRequest(
			h,
			newRequest(
				http.MethodDelete,
				"http://example.test/src-log?logging",
				"",
				map[string]string{"Authorization": authHeader("minis3-access-key")},
			),
		)
		requireStatus(t, wDeleteOK, http.StatusNoContent)
	})
}

func TestBucketLoggingHelperFunctions(t *testing.T) {
	if got := policyValueToStrings("x"); len(got) != 1 || got[0] != "x" {
		t.Fatalf("policyValueToStrings(string) = %#v", got)
	}
	if got := policyValueToStrings([]any{"x", 1, "y"}); len(got) != 2 || got[0] != "x" ||
		got[1] != "y" {
		t.Fatalf("policyValueToStrings([]any) = %#v", got)
	}
	if got := policyValueToStrings(123); got != nil {
		t.Fatalf("policyValueToStrings(default) = %#v, want nil", got)
	}

	if !wildcardMatch("*", "abc") {
		t.Fatal("wildcard * should match")
	}
	if !wildcardMatch("a*c", "abbbc") {
		t.Fatal("wildcard a*c should match abbbc")
	}
	if wildcardMatch("a*d", "abbbc") {
		t.Fatal("wildcard a*d should not match abbbc")
	}
	if !wildcardMatch("exact", "exact") {
		t.Fatal("exact match should match")
	}

	if !principalHasLoggingService("*") {
		t.Fatal("string * principal should allow logging service")
	}
	if !principalHasLoggingService(map[string]any{"Service": "logging.s3.amazonaws.com"}) {
		t.Fatal("service principal string should allow")
	}
	if !principalHasLoggingService(
		map[string]any{"Service": []any{"x", "logging.s3.amazonaws.com"}},
	) {
		t.Fatal("service principal list should allow")
	}
	if principalHasLoggingService(map[string]any{"Service": "other"}) {
		t.Fatal("non-logging service principal should not allow")
	}

	tenant, bucket := splitQualifiedBucketName("tenant:bucket")
	if tenant != "tenant" || bucket != "bucket" {
		t.Fatalf("splitQualifiedBucketName = (%q,%q), want (tenant,bucket)", tenant, bucket)
	}
	tenant, bucket = splitQualifiedBucketName("bucket")
	if tenant != "" || bucket != "bucket" {
		t.Fatalf("splitQualifiedBucketName unqualified = (%q,%q), want (,bucket)", tenant, bucket)
	}

	if got := qualifiedBucketARN("bucket", ""); got != "arn:aws:s3:::bucket" {
		t.Fatalf("qualifiedBucketARN(bucket) = %q", got)
	}
	if got := qualifiedBucketARN("tenant:bucket", "obj"); got != "arn:aws:s3::tenant:bucket/obj" {
		t.Fatalf("qualifiedBucketARN(tenant:bucket,obj) = %q", got)
	}
	if got := qualifiedBucketObjectARN("bucket", "logs/"); got != "arn:aws:s3:::bucket/logs/" {
		t.Fatalf("qualifiedBucketObjectARN(bucket,logs/) = %q", got)
	}
	if got := qualifiedBucketObjectARN("tenant:bucket", "logs/"); got != "arn:aws:s3::tenant:bucket/logs/" {
		t.Fatalf("qualifiedBucketObjectARN(tenant:bucket,logs/) = %q", got)
	}

	h, _ := newTestHandler(t)
	if got := h.resolveLoggingTargetBucketName("tenant-access-key", "target"); got != "tenant:target" {
		t.Fatalf("resolveLoggingTargetBucketName tenant = %q, want tenant:target", got)
	}
	if got := h.resolveLoggingTargetBucketName("tenant-access-key", "other:target"); got != "other:target" {
		t.Fatalf("resolveLoggingTargetBucketName qualified = %q", got)
	}
	if got := h.resolveLoggingTargetBucketName("minis3-access-key", ":target"); got != "target" {
		t.Fatalf("resolveLoggingTargetBucketName empty-tenant = %q, want target", got)
	}
	if got := h.resolveLoggingTargetBucketName("tenant-access-key", "tenant:"); got != "" {
		t.Fatalf("resolveLoggingTargetBucketName empty bucket = %q, want empty", got)
	}
}

func TestBucketLoggingTargetAllowedBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-policy")
	mustCreateBucket(t, b, "dst-policy")
	b.SetBucketOwner("src-policy", "minis3-access-key")
	b.SetBucketOwner("dst-policy", "minis3-access-key")
	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
		return
	}

	t.Run("source or target missing", func(t *testing.T) {
		if ok, code := h.bucketLoggingTargetAllowed("missing", "dst-policy", "logs/"); ok ||
			code != "NoSuchBucket" {
			t.Fatalf("missing source result = (%v,%q), want (false,NoSuchBucket)", ok, code)
		}
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "missing", "logs/"); ok ||
			code != "NoSuchKey" {
			t.Fatalf("missing target result = (%v,%q), want (false,NoSuchKey)", ok, code)
		}
	})

	t.Run("policy shape and condition branches", func(t *testing.T) {
		if dst, ok := b.GetBucket("dst-policy"); ok {
			dst.Policy = ""
		}
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("empty policy result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		if dst, ok := b.GetBucket("dst-policy"); ok {
			dst.Policy = "{bad json"
		}
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("invalid json result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(t, b, "dst-policy", `{"Version":"2012-10-17"}`)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("missing statement result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(t, b, "dst-policy", `{"Statement":"invalid"}`)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("invalid statement type result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			`{"Statement":[{"Effect":"Deny","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"*"}]}`,
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("deny effect result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"not-logging"},"Action":"s3:PutObject","Resource":"*"}]}`,
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("wrong principal result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:GetObject","Resource":"*"}]}`,
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("wrong action result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::another/*"}]}`,
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("resource mismatch result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			fmt.Sprintf(
				`{"Statement":{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"*","Resource":"%s","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::wrong"},"StringLike":{"aws:SourceAccount":"%s"}}}}`,
				qualifiedBucketObjectARN("dst-policy", "logs/"),
				owner.ID,
			),
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("arnlike mismatch result = (%v,%q), want (false,AccessDenied)", ok, code)
		}

		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			fmt.Sprintf(
				`{"Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"%s","Condition":{"ArnLike":{"aws:SourceArn":"%s"},"StringEquals":{"aws:SourceAccount":"wrong"}}}]}`,
				qualifiedBucketObjectARN("dst-policy", "logs/"),
				qualifiedBucketARN("src-policy", ""),
			),
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); ok ||
			code != "AccessDenied" {
			t.Fatalf("account mismatch result = (%v,%q), want (false,AccessDenied)", ok, code)
		}
	})

	t.Run("success", func(t *testing.T) {
		mustPutBucketPolicy(
			t,
			b,
			"dst-policy",
			allowLoggingPolicy("src-policy", "dst-policy", "logs/", owner.ID),
		)
		if ok, code := h.bucketLoggingTargetAllowed("src-policy", "dst-policy", "logs/"); !ok ||
			code != "" {
			t.Fatalf("success result = (%v,%q), want (true,\"\")", ok, code)
		}
	})
}

func TestServerAccessLoggingHelperBranches(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-access-log")
	mustCreateBucket(t, b, "dst-access-log")
	b.SetBucketOwner("src-access-log", "minis3-access-key")
	b.SetBucketOwner("dst-access-log", "minis3-access-key")
	owner := backend.OwnerForAccessKey("minis3-access-key")
	if owner == nil {
		t.Fatal("owner must not be nil")
		return
	}
	mustPutBucketPolicy(
		t,
		b,
		"dst-access-log",
		allowLoggingPolicy("src-access-log", "dst-access-log", "logs/", owner.ID),
	)
	if err := b.PutBucketLogging("src-access-log", &backend.BucketLoggingStatus{
		LoggingEnabled: &backend.LoggingEnabled{
			TargetBucket: "dst-access-log",
			TargetPrefix: "logs/",
		},
	}); err != nil {
		t.Fatalf("PutBucketLogging failed: %v", err)
	}

	t.Run("basic helper functions", func(t *testing.T) {
		if got := tenantFromAccessKey("tenant-access-key"); got != "tenant" {
			t.Fatalf("tenantFromAccessKey = %q, want tenant", got)
		}
		if got := tenantFromAccessKey("missing"); got != "" {
			t.Fatalf("tenantFromAccessKey unknown = %q, want empty", got)
		}
		if got := normalizeBucketNameForRequestAccessKey("bucket", "tenant-access-key"); got != "tenant:bucket" {
			t.Fatalf("normalizeBucketNameForRequestAccessKey = %q, want tenant:bucket", got)
		}
		if got := normalizeBucketNameForRequestAccessKey("tenant:bucket", "tenant-access-key"); got != "tenant:bucket" {
			t.Fatalf("normalize qualified bucket = %q", got)
		}
		if got := displayBucketName("tenant:bucket"); got != "bucket" {
			t.Fatalf("displayBucketName qualified = %q, want bucket", got)
		}
		if got := displayBucketName("bucket"); got != "bucket" {
			t.Fatalf("displayBucketName unqualified = %q, want bucket", got)
		}
		if got := defaultLogField("", "-"); got != "-" {
			t.Fatalf("defaultLogField empty = %q, want -", got)
		}
		if got := defaultLogField("x", "-"); got != "x" {
			t.Fatalf("defaultLogField non-empty = %q, want x", got)
		}
	})

	t.Run("mapRequestToLoggingOperation and auth/action helpers", func(t *testing.T) {
		cases := []struct {
			method string
			url    string
			key    string
		}{
			{http.MethodPut, "http://example.test/b?logging", ""},
			{http.MethodGet, "http://example.test/b?logging", ""},
			{http.MethodPost, "http://example.test/b?delete", ""},
			{http.MethodPut, "http://example.test/b", ""},
			{http.MethodGet, "http://example.test/b", ""},
			{http.MethodPatch, "http://example.test/b", ""},
			{http.MethodPut, "http://example.test/b/k?uploadId=u", "k"},
			{http.MethodPost, "http://example.test/b/k?uploadId=u", "k"},
			{http.MethodPost, "http://example.test/b/k?uploads", "k"},
			{http.MethodPost, "http://example.test/b/k?delete", "k"},
			{http.MethodPut, "http://example.test/b/k", "k"},
			{http.MethodGet, "http://example.test/b/k", "k"},
			{http.MethodHead, "http://example.test/b/k", "k"},
			{http.MethodDelete, "http://example.test/b/k", "k"},
			{http.MethodPatch, "http://example.test/b/k", "k"},
		}
		for _, tc := range cases {
			req := newRequest(tc.method, tc.url, "", nil)
			if tc.key != "" && tc.method == http.MethodPut &&
				!strings.Contains(tc.url, "uploadId") {
				req.Header.Set("x-amz-copy-source", "/src/k")
			}
			_ = mapRequestToLoggingOperation(req, tc.key)
			_ = loggingActionFromRequest(req, tc.key)
		}

		reqQuery := newRequest(http.MethodGet, "http://example.test/b/k?X-Amz-Signature=x", "", nil)
		if got := loggingAuthType(reqQuery); got != "QueryString" {
			t.Fatalf("loggingAuthType(query) = %q, want QueryString", got)
		}
		reqHeader := newRequest(http.MethodGet, "http://example.test/b/k", "", map[string]string{
			"Authorization": authHeader("minis3-access-key"),
		})
		if got := loggingAuthType(reqHeader); got != "AuthHeader" {
			t.Fatalf("loggingAuthType(header) = %q, want AuthHeader", got)
		}
		reqNone := newRequest(http.MethodGet, "http://example.test/b/k", "", nil)
		if got := loggingAuthType(reqNone); got != "-" {
			t.Fatalf("loggingAuthType(none) = %q, want -", got)
		}
	})

	t.Run("emit and flush logs", func(t *testing.T) {
		reqNoBucket := newRequest(http.MethodGet, "http://example.test/", "", nil)
		h.emitServerAccessLog(reqNoBucket, http.StatusOK, 10, "", "")

		req := newRequest(
			http.MethodGet,
			"http://example.test/src-access-log/k",
			"",
			map[string]string{
				"Authorization": authHeader("minis3-access-key"),
				"Referer":       "https://ref.example.test",
				"User-Agent":    "ua",
			},
		)
		req.RemoteAddr = "127.0.0.1:1234"
		h.emitServerAccessLog(req, http.StatusOK, 123, "req-id", "host-id")

		reqDelete := newRequest(
			http.MethodPost,
			"http://example.test/src-access-log?delete",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		reqDelete.RemoteAddr = "127.0.0.1:9999"
		reqDelete = reqDelete.WithContext(
			context.WithValue(reqDelete.Context(), deleteLogKeysContextKey, []string{"a", "b"}),
		)
		h.emitServerAccessLog(reqDelete, http.StatusForbidden, 0, "", "")

		h.loggingMu.Lock()
		for _, batch := range h.pendingLogBatches {
			batch.FirstEventAt = time.Now().UTC().Add(-10 * time.Second)
		}
		h.loggingMu.Unlock()

		if err := h.flushServerAccessLogsIfDue("other-source"); err != nil {
			t.Fatalf("flushServerAccessLogsIfDue(other-source) failed: %v", err)
		}
		if err := h.flushServerAccessLogsIfDue("src-access-log"); err != nil {
			t.Fatalf("flushServerAccessLogsIfDue(src-access-log) failed: %v", err)
		}

		list, err := b.ListObjectsV2("dst-access-log", "logs/", "", "", "", 1000)
		if err != nil {
			t.Fatalf("ListObjectsV2 failed: %v", err)
		}
		if len(list.Objects) == 0 {
			t.Fatal("expected at least one access-log object in target bucket")
		}
	})

	t.Run("flushServerAccessLogBatch branches", func(t *testing.T) {
		if _, err := h.flushServerAccessLogBatch(nil, time.Now().UTC()); err != nil {
			t.Fatalf("flush nil batch failed: %v", err)
		}
		if _, err := h.flushServerAccessLogBatch(&serverAccessLogBatch{}, time.Now().UTC()); err != nil {
			t.Fatalf("flush empty batch failed: %v", err)
		}

		// Empty-source entries are ignored.
		_, err := h.flushServerAccessLogBatch(&serverAccessLogBatch{
			TargetBucket: "dst-access-log",
			TargetPrefix: "logs/",
			Entries: []serverAccessLogEntry{{
				SourceBucket: "",
				Line:         "line",
			}},
		}, time.Now().UTC())
		if err != nil {
			t.Fatalf("unexpected error for empty-source entry: %v", err)
		}

		// Access denied when target policy does not allow logging service writes.
		mustCreateBucket(t, b, "src-denied")
		b.SetBucketOwner("src-denied", "minis3-access-key")
		mustCreateBucket(t, b, "dst-denied")
		b.SetBucketOwner("dst-denied", "minis3-access-key")
		mustPutBucketPolicy(t, b, "dst-denied", `{"Statement":[]}`)
		_, err = h.flushServerAccessLogBatch(&serverAccessLogBatch{
			TargetBucket: "dst-denied",
			TargetPrefix: "logs/",
			Entries: []serverAccessLogEntry{{
				SourceBucket: "src-denied",
				Line:         "line",
			}},
		}, time.Now().UTC())
		if err == nil {
			t.Fatal("expected access-denied error for disallowed target policy")
		}
	})

	t.Run("loggingACLRequired branches", func(t *testing.T) {
		mustCreateBucket(t, b, "acl-required")
		b.SetBucketOwner("acl-required", "minis3-access-key")
		mustPutObject(t, b, "acl-required", "k", "v")

		// action empty
		reqDelete := newRequest(http.MethodDelete, "http://example.test/acl-required/k", "", nil)
		if got := h.loggingACLRequired(reqDelete, "acl-required", "k"); got != "-" {
			t.Fatalf("loggingACLRequired delete = %q, want -", got)
		}

		// missing bucket
		reqGet := newRequest(http.MethodGet, "http://example.test/missing/k", "", nil)
		if got := h.loggingACLRequired(reqGet, "missing", "k"); got != "-" {
			t.Fatalf("loggingACLRequired missing bucket = %q, want -", got)
		}

		// owner shortcut
		reqOwner := newRequest(
			http.MethodGet,
			"http://example.test/acl-required/k",
			"",
			map[string]string{"Authorization": authHeader("minis3-access-key")},
		)
		if got := h.loggingACLRequired(reqOwner, "acl-required", "k"); got != "-" {
			t.Fatalf("loggingACLRequired owner = %q, want -", got)
		}

		// ACL-required yes via bucket/object ACL read grant.
		if err := b.PutBucketACL("acl-required", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutBucketACL failed: %v", err)
		}
		if err := b.PutObjectACL("acl-required", "k", "", backend.CannedACLToPolicy("public-read")); err != nil {
			t.Fatalf("PutObjectACL failed: %v", err)
		}
		reqAnonList := newRequest(http.MethodGet, "http://example.test/acl-required", "", nil)
		if got := h.loggingACLRequired(reqAnonList, "acl-required", ""); got != "Yes" {
			t.Fatalf("loggingACLRequired list = %q, want Yes", got)
		}
		reqAnonGet := newRequest(http.MethodGet, "http://example.test/acl-required/k", "", nil)
		if got := h.loggingACLRequired(reqAnonGet, "acl-required", "k"); got != "Yes" {
			t.Fatalf("loggingACLRequired get = %q, want Yes", got)
		}
	})
}
