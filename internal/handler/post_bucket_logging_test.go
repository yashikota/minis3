package handler

import (
	"encoding/xml"
	"net/http"
	"strings"
	"testing"

	"github.com/yashikota/minis3/internal/backend"
)

func TestPostBucketLoggingFlush(t *testing.T) {
	h, b := newTestHandler(t)
	mustCreateBucket(t, b, "src-log")
	mustCreateBucket(t, b, "tgt-log")
	b.SetBucketOwner("src-log", "minis3-access-key")
	b.SetBucketOwner("tgt-log", "minis3-access-key")
	ownerHeaders := map[string]string{"Authorization": authHeader("minis3-access-key")}

	// Set target bucket policy to allow logging service writes
	tgtPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::tgt-log/*"}]}`
	if err := b.PutBucketPolicy("tgt-log", tgtPolicy, false); err != nil {
		t.Fatalf("PutBucketPolicy failed: %v", err)
	}

	// Configure logging: src-log → tgt-log
	loggingXML := `<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<LoggingEnabled>
			<TargetBucket>tgt-log</TargetBucket>
			<TargetPrefix>log/</TargetPrefix>
		</LoggingEnabled>
	</BucketLoggingStatus>`
	wPut := doRequest(h, newRequest(
		http.MethodPut,
		"http://example.test/src-log?logging",
		loggingXML,
		ownerHeaders,
	))
	requireStatus(t, wPut, http.StatusOK)

	t.Run("flush with pending logs", func(t *testing.T) {
		// PUT an object to generate a log entry
		mustPutObject(t, b, "src-log", "testobj", "hello")
		// Trigger log emission via a GET (which causes emitServerAccessLog)
		doRequest(h, newRequest(
			http.MethodGet,
			"http://example.test/src-log/testobj",
			"",
			ownerHeaders,
		))

		// POST ?logging to force flush
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/src-log?logging",
			"",
			ownerHeaders,
		))
		requireStatus(t, w, http.StatusOK)

		var result backend.PostBucketLoggingResult
		if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to decode response: %v body=%s", err, w.Body.String())
		}
		if result.FlushedLoggingObject == "" {
			t.Fatalf("expected non-empty FlushedLoggingObject, got empty")
		}
		if !strings.HasPrefix(result.FlushedLoggingObject, "log/") {
			t.Fatalf("expected key to start with 'log/', got %q", result.FlushedLoggingObject)
		}

		// The flushed batch must exist as an object in the target bucket.
		logObj, err := b.GetObject("tgt-log", result.FlushedLoggingObject)
		if err != nil {
			t.Fatalf("flushed log object not found in tgt-log: %v", err)
		}
		if len(logObj.Data) == 0 {
			t.Fatal("flushed log object is empty")
		}
		if !strings.Contains(string(logObj.Data), "testobj") {
			t.Fatalf("flushed log object missing testobj entry: %q", logObj.Data)
		}

		// The first batch was consumed: a second flush only contains the
		// first POST's own log entry, so the flushed key must advance.
		wSecond := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/src-log?logging",
			"",
			ownerHeaders,
		))
		requireStatus(t, wSecond, http.StatusOK)
		var second backend.PostBucketLoggingResult
		if err := xml.Unmarshal(wSecond.Body.Bytes(), &second); err != nil {
			t.Fatalf("failed to decode second response: %v", err)
		}
		if second.FlushedLoggingObject == "" {
			t.Fatal("expected second flush to report the first POST's log entry")
		}
		if second.FlushedLoggingObject == result.FlushedLoggingObject {
			t.Fatalf(
				"second flush re-reported consumed batch %q",
				second.FlushedLoggingObject,
			)
		}
	})

	t.Run("flush with empty batch on unconfigured bucket", func(t *testing.T) {
		mustCreateBucket(t, b, "no-log-cfg")
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/no-log-cfg?logging",
			"",
			nil,
		))
		requireStatus(t, w, http.StatusOK)

		var result backend.PostBucketLoggingResult
		if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatalf("failed to decode response: %v body=%s", err, w.Body.String())
		}
		if result.FlushedLoggingObject != "" {
			t.Fatalf("expected empty FlushedLoggingObject, got %q", result.FlushedLoggingObject)
		}
	})

	t.Run("nonexistent bucket", func(t *testing.T) {
		w := doRequest(h, newRequest(
			http.MethodPost,
			"http://example.test/no-such-log-bucket?logging",
			"",
			nil,
		))
		requireStatus(t, w, http.StatusNotFound)
		requireS3ErrorCode(t, w, "NoSuchBucket")
	})
}
