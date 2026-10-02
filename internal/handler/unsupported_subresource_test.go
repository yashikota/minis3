package handler

import (
	"net/http"
	"testing"
)

func TestUnsupportedBucketSubresourcesReturn501(t *testing.T) {
	unsupportedQueries := []string{
		"notification",
		"replication",
		"analytics",
		"inventory",
		"metrics",
		"accelerate",
		"intelligent-tiering",
		"select",
		"select-type",
	}

	methods := []string{
		http.MethodGet,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPost,
	}

	for _, method := range methods {
		for _, q := range unsupportedQueries {
			t.Run(method+" bucket?"+q, func(t *testing.T) {
				h, b := newTestHandler(t)
				mustCreateBucket(t, b, "notimpl-bucket")
				w := doRequest(h, newRequest(method, "http://example.test/notimpl-bucket?"+q, "", nil))
				requireStatus(t, w, http.StatusNotImplemented)
				requireS3ErrorCode(t, w, "NotImplemented")
			})
		}
	}
}

func TestUnsupportedBucketSubresourcesWithValueReturn501(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "notimpl-bucket")
	cases := []struct {
		name   string
		method string
		target string
	}{
		{"GET analytics id", http.MethodGet, "http://example.test/notimpl-bucket?analytics&id=1"},
		{"GET inventory id", http.MethodGet, "http://example.test/notimpl-bucket?inventory&id=1"},
		{"GET metrics id", http.MethodGet, "http://example.test/notimpl-bucket?metrics&id=1"},
		{"GET intelligent-tiering id", http.MethodGet, "http://example.test/notimpl-bucket?intelligent-tiering&id=1"},
		{"POST select-type value", http.MethodPost, "http://example.test/notimpl-bucket?select-type=2"},
		{"PUT notification empty", http.MethodPut, "http://example.test/notimpl-bucket?notification="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doRequest(h, newRequest(tc.method, tc.target, "", nil))
			requireStatus(t, w, http.StatusNotImplemented)
			requireS3ErrorCode(t, w, "NotImplemented")
		})
	}
}

func TestUnsupportedObjectSubresourcesReturn501(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
	}{
		{"POST object select", http.MethodPost, "http://example.test/notimpl-bucket/k?select"},
		{"POST object select-type", http.MethodPost, "http://example.test/notimpl-bucket/k?select&select-type=2"},
		{"GET object torrent", http.MethodGet, "http://example.test/notimpl-bucket/k?torrent"},
		{"GET object torrent with key", http.MethodGet, "http://example.test/notimpl-bucket/k?torrent=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, b := newTestHandler(t)
			mustCreateBucket(t, b, "notimpl-bucket")
			mustPutObject(t, b, "notimpl-bucket", "k", "v")
			w := doRequest(h, newRequest(tc.method, tc.target, "", nil))
			requireStatus(t, w, http.StatusNotImplemented)
			requireS3ErrorCode(t, w, "NotImplemented")
		})
	}
}

func TestSupportedBucketOperationsUnaffectedByNotImplementedGuard(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "notimpl-bucket")
	mustPutObject(t, b, "notimpl-bucket", "k", "v")

	t.Run("ListObjectsV1", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/notimpl-bucket", "", nil))
		requireStatus(t, w, http.StatusOK)
	})
	t.Run("ListObjectsV2", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/notimpl-bucket?list-type=2", "", nil))
		requireStatus(t, w, http.StatusOK)
	})
	t.Run("ListObjectsV1 with prefix", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/notimpl-bucket?prefix=k&max-keys=10", "", nil))
		requireStatus(t, w, http.StatusOK)
	})
	t.Run("GetObject still works", func(t *testing.T) {
		w := doRequest(h, newRequest(http.MethodGet, "http://example.test/notimpl-bucket/k", "", nil))
		requireStatus(t, w, http.StatusOK)
	})
}
