package minis3

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMinis3(t *testing.T) {
	s := New()
	server := httptest.NewServer(s.handler())
	defer server.Close()

	client := server.Client()

	// 1. List Buckets (Empty)
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("ListBuckets failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "ListAllMyBucketsResult") {
		t.Errorf("Expected ListAllMyBucketsResult XML, got: %s", string(body))
	}

	// 2. Create Bucket
	req, _ := http.NewRequest("PUT", server.URL+"/testbucket", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 3. Put Object
	content := "Hello S3"
	req, _ = http.NewRequest("PUT", server.URL+"/testbucket/hello.txt", strings.NewReader(content))
	req.Header.Set("Content-Type", "text/plain")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 4. Get Object
	resp, err = client.Get(server.URL + "/testbucket/hello.txt")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != content {
		t.Errorf("Expected content %q, got %q", content, string(data))
	}

	// 5. Delete Object
	req, _ = http.NewRequest("DELETE", server.URL+"/testbucket/hello.txt", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected 204 No Content, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// 6. Delete Bucket
	req, _ = http.NewRequest("DELETE", server.URL+"/testbucket", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DeleteBucket failed: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected 204 No Content, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
