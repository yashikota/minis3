package minis3

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "ListAllMyBucketsResult") {
		t.Errorf("Expected ListAllMyBucketsResult XML, got: %s", string(body))
	}

	// 2. Create Bucket
	req, _ := http.NewRequest("PUT", server.URL+"/testbucket", nil)
	req.Header.Set("x-amz-acl", "public-read-write")
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
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

func TestDeleteObjects(t *testing.T) {
	s := New()
	server := httptest.NewServer(s.handler())
	defer server.Close()

	client := server.Client()

	// Create bucket
	req, _ := http.NewRequest("PUT", server.URL+"/testbucket", nil)
	req.Header.Set("x-amz-acl", "public-read-write")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	_ = resp.Body.Close()

	// Put multiple objects
	for _, key := range []string{"file1.txt", "file2.txt", "file3.txt"} {
		req, _ = http.NewRequest("PUT", server.URL+"/testbucket/"+key, strings.NewReader("content"))
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("PutObject failed: %v", err)
		}
		_ = resp.Body.Close()
	}

	// Delete multiple objects
	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object><Key>file1.txt</Key></Object>
	<Object><Key>file2.txt</Key></Object>
	<Object><Key>nonexistent.txt</Key></Object>
</Delete>`

	req, _ = http.NewRequest("POST", server.URL+"/testbucket?delete", strings.NewReader(deleteXML))
	req.Header.Set("Content-Type", "application/xml")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()

	// Verify response contains DeleteResult
	if !strings.Contains(string(body), "DeleteResult") {
		t.Errorf("Expected DeleteResult XML, got: %s", string(body))
	}
	// Verify deleted keys are in response
	if !strings.Contains(string(body), "file1.txt") {
		t.Errorf("Expected file1.txt in response, got: %s", string(body))
	}
	if !strings.Contains(string(body), "file2.txt") {
		t.Errorf("Expected file2.txt in response, got: %s", string(body))
	}
	// S3 treats non-existent objects as successfully deleted
	if !strings.Contains(string(body), "nonexistent.txt") {
		t.Errorf("Expected nonexistent.txt in response, got: %s", string(body))
	}

	// Verify file3.txt still exists
	resp, err = client.Get(server.URL + "/testbucket/file3.txt")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected file3.txt to still exist, got status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Verify file1.txt is deleted
	resp, err = client.Get(server.URL + "/testbucket/file1.txt")
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected file1.txt to be deleted, got status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDeleteObjectsQuietMode(t *testing.T) {
	s := New()
	server := httptest.NewServer(s.handler())
	defer server.Close()

	client := server.Client()

	// Create bucket
	req, _ := http.NewRequest("PUT", server.URL+"/testbucket", nil)
	req.Header.Set("x-amz-acl", "public-read-write")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	_ = resp.Body.Close()

	// Put object
	req, _ = http.NewRequest("PUT", server.URL+"/testbucket/file.txt", strings.NewReader("content"))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}
	_ = resp.Body.Close()

	// Delete with quiet mode
	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Quiet>true</Quiet>
	<Object><Key>file.txt</Key></Object>
</Delete>`

	req, _ = http.NewRequest("POST", server.URL+"/testbucket?delete", strings.NewReader(deleteXML))
	req.Header.Set("Content-Type", "application/xml")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()

	// In quiet mode, successful deletions should NOT be in response
	if strings.Contains(string(body), "<Deleted>") {
		t.Errorf("Expected no Deleted elements in quiet mode, got: %s", string(body))
	}
}

func TestDeleteObjectsNoSuchBucket(t *testing.T) {
	s := New()
	server := httptest.NewServer(s.handler())
	defer server.Close()

	client := server.Client()

	deleteXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object><Key>file.txt</Key></Object>
</Delete>`

	req, _ := http.NewRequest(
		"POST",
		server.URL+"/nonexistent?delete",
		strings.NewReader(deleteXML),
	)
	req.Header.Set("Content-Type", "application/xml")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected 404 Not Found, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()

	if !strings.Contains(string(body), "NoSuchBucket") {
		t.Errorf("Expected NoSuchBucket error, got: %s", string(body))
	}
}

func TestDeleteObjectsMalformedXML(t *testing.T) {
	s := New()
	server := httptest.NewServer(s.handler())
	defer server.Close()

	client := server.Client()

	// Create bucket
	req, _ := http.NewRequest("PUT", server.URL+"/testbucket", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("CreateBucket failed: %v", err)
	}
	_ = resp.Body.Close()

	// Send malformed XML
	malformedXML := `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
	<Object><Key>file.txt</Key>
</Delete>`

	req, _ = http.NewRequest(
		"POST",
		server.URL+"/testbucket?delete",
		strings.NewReader(malformedXML),
	)
	req.Header.Set("Content-Type", "application/xml")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DeleteObjects failed: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	_ = resp.Body.Close()

	if !strings.Contains(string(body), "MalformedXML") {
		t.Errorf("Expected MalformedXML error, got: %s", string(body))
	}
}

func TestMinis3RunAndAccessors(t *testing.T) {
	s, err := Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	addr := s.Addr()
	if addr == "" {
		t.Fatal("expected non-empty addr")
	}
	if s.Host() != addr {
		t.Fatalf("Host()=%q, Addr()=%q", s.Host(), addr)
	}

	resp, err := http.Get("http://" + s.Host() + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_ = resp.Body.Close()
}

func TestMinis3RunAddrAndStartAddr(t *testing.T) {
	s, err := RunAddr("127.0.0.1:0")
	if err != nil {
		t.Fatalf("RunAddr failed: %v", err)
	}
	defer func() { _ = s.Close() }()

	addr := s.Addr()
	if addr == "" {
		t.Fatal("expected non-empty addr")
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("Addr()=%q, want 127.0.0.1:*", addr)
	}

	resp, err := http.Get("http://" + s.Host() + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_ = resp.Body.Close()
}

func TestMinis3CloseAndAddrBeforeStart(t *testing.T) {
	s := New()
	if got := s.Addr(); got != "" {
		t.Fatalf("Addr() before start = %q, want empty", got)
	}
	if got := s.Host(); got != "" {
		t.Fatalf("Host() before start = %q, want empty", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() before start failed: %v", err)
	}
}

func TestMinis3StartListenError(t *testing.T) {
	origListenFn := listenFn
	listenFn = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("boom")
	}
	defer func() { listenFn = origListenFn }()

	s := New()
	err := s.Start()
	if err == nil {
		t.Fatal("expected Start() to fail")
	}
	if !strings.Contains(err.Error(), "failed to listen: boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMinis3StartAddrListenError(t *testing.T) {
	origListenFn := listenFn
	listenFn = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("boom-addr")
	}
	defer func() { listenFn = origListenFn }()

	s := New()
	err := s.StartAddr("127.0.0.1:9191")
	if err == nil {
		t.Fatal("expected StartAddr() to fail")
	}
	if !strings.Contains(err.Error(), "failed to listen: boom-addr") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunReturnsStartError(t *testing.T) {
	origListenFn := listenFn
	listenFn = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("run-boom")
	}
	defer func() { listenFn = origListenFn }()

	s, err := Run()
	if err == nil {
		t.Fatal("expected Run() to fail")
	}
	if s != nil {
		t.Fatalf("Run() server = %#v, want nil", s)
	}
	if !strings.Contains(err.Error(), "failed to listen: run-boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAddrReturnsStartError(t *testing.T) {
	origListenFn := listenFn
	listenFn = func(_, _ string) (net.Listener, error) {
		return nil, errors.New("run-addr-boom")
	}
	defer func() { listenFn = origListenFn }()

	s, err := RunAddr("127.0.0.1:9191")
	if err == nil {
		t.Fatal("expected RunAddr() to fail")
	}
	if s != nil {
		t.Fatalf("RunAddr() server = %#v, want nil", s)
	}
	if !strings.Contains(err.Error(), "failed to listen: run-addr-boom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMinis3StartServeErrorCallsFatal(t *testing.T) {
	origListenFn := listenFn
	origFatalFn := fatalFn
	defer func() {
		listenFn = origListenFn
		fatalFn = origFatalFn
	}()

	listenFn = func(_, _ string) (net.Listener, error) {
		return failingListener{acceptErr: errors.New("accept failed")}, nil
	}

	called := make(chan string, 1)
	fatalFn = func(v ...any) {
		called <- fmt.Sprint(v...)
	}

	s := New()
	if err := s.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	select {
	case msg := <-called:
		if !strings.Contains(msg, "minis3 server error:") {
			t.Fatalf("unexpected fatal message: %q", msg)
		}
		if !strings.Contains(msg, "accept failed") {
			t.Fatalf("expected accept error in fatal message: %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected fatalFn to be called")
	}
}

type failingListener struct {
	acceptErr error
}

func (l failingListener) Accept() (net.Conn, error) {
	return nil, l.acceptErr
}

func (failingListener) Close() error {
	return nil
}

func (failingListener) Addr() net.Addr {
	return staticAddr("127.0.0.1:0")
}

type staticAddr string

func (staticAddr) Network() string {
	return "tcp"
}

func (a staticAddr) String() string {
	return string(a)
}
