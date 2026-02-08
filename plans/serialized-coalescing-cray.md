# Fix Failing s3-tests: Lifecycle/Restore, Policy Deny, Bucket Logging

## Context

60+ s3-tests are failing across 3 categories. This plan addresses each to make them pass. The user indicated that tests with "error" status (not "FAILED") can be ignored/skipped.

---

## Category 1: Bucket Policy Deny Self (2 tests)

**Problem:** `handleGetBucketPolicy` and `handleDeleteBucketPolicy` skip `checkAccess()`, so deny policies aren't enforced.

### Changes

**`internal/handler/bucket.go`**

1. **`handleGetBucketPolicy` (line 1980):** Change `_ *http.Request` → `r *http.Request`, add `checkAccess(r, bucketName, "s3:GetBucketPolicy", "")` at top (same pattern as `handlePutBucketPolicy` at line 2018).

2. **`handleDeleteBucketPolicy` (line 2115):** Same change — name the request param, add `checkAccess(r, bucketName, "s3:DeleteBucketPolicy", "")`.

**`internal/handler/handler.go`** (checkAccess switch, line 787)

3. Add `"s3:GetBucketPolicy"` to the existing ReadACP case at line 787 (`"s3:GetBucketOwnershipControls", "s3:GetBucketLogging", ...`).

4. Add `"s3:DeleteBucketPolicy"` to the existing WriteACP case at line 794 (`"s3:PutBucketOwnershipControls", ...`).

### Unit Tests

Add tests to existing `internal/handler/bucket_policy_branches_test.go` (or create if needed):
- GET/DELETE policy with deny → 403
- GET/DELETE policy without deny → succeeds

---

## Category 2: Bucket Logging POST Flush (50+ tests)

**Problem:** Tests call `POST /{bucket}?logging` to force-flush log batches. No handler exists for this.

### Changes

**`internal/handler/bucket.go`**

1. **Route POST `?logging`** (line 724, `case http.MethodPost:`): Add `r.URL.Query().Has("logging")` check before the `"delete"` check:
   ```go
   if r.URL.Query().Has("logging") {
       h.handlePostBucketLogging(w, r, bucketName)
       return
   }
   ```

2. **Add `handlePostBucketLogging` handler:** Check access (`s3:PutBucketLogging`), verify bucket exists, call `h.forceFlushServerAccessLogs(bucketName)`, return XML with `FlushedLoggingObject`.

**`internal/handler/handler.go`**

3. **Add `forceFlushServerAccessLogs(sourceBucketName) (string, error)` method:** Like `flushServerAccessLogsIfDue` but skips the 5-second interval check — flushes all pending batches for the given source bucket unconditionally.

4. **Refactor `flushServerAccessLogBatch` return:** Change signature from `error` → `(string, error)`, return the `logKey`. Update the one call site at line 493 to `_, err := ...`.

**`internal/backend/type.go`**

5. Add `PostBucketLoggingResult` XML struct:
   ```go
   type PostBucketLoggingResult struct {
       XMLName              xml.Name `xml:"PostBucketLoggingResult"`
       Xmlns                string   `xml:"xmlns,attr,omitempty"`
       FlushedLoggingObject string   `xml:"FlushedLoggingObject,omitempty"`
   }
   ```

### Unit Tests

New test file or add to existing handler tests:
- POST `?logging` happy path: setup logging config → put object → POST flush → verify response has `FlushedLoggingObject` and log object exists
- POST `?logging` on nonexistent bucket → 404
- POST `?logging` with empty batch → 200 with empty FlushedLoggingObject

---

## Category 3: RestoreObject & Cloud Transitions (7 tests)

**Problem:** No `POST ?restore` handler. No restore state on objects. Archived objects not blocked from GET.

### Changes

**`internal/backend/backend.go`** (Object struct, line 89)

1. Add restore fields after `StorageClass`:
   ```go
   Restored          bool       // true after RestoreObject has been called
   RestoreExpiryDate *time.Time // non-nil for temporary restores
   ```

**`internal/backend/type.go`**

2. Add `RestoreRequest` XML struct and `IsArchivedStorageClass` helper:
   ```go
   type RestoreRequest struct {
       XMLName              xml.Name              `xml:"RestoreRequest"`
       Days                 int                   `xml:"Days,omitempty"`
       GlacierJobParameters *GlacierJobParameters `xml:"GlacierJobParameters,omitempty"`
   }
   type GlacierJobParameters struct {
       Tier string `xml:"Tier"`
   }
   func IsArchivedStorageClass(sc string) bool {
       return sc == "GLACIER" || sc == "DEEP_ARCHIVE"
   }
   ```

**`internal/backend/object.go`** (or new file `restore.go`)

3. Add `RestoreObject(bucketName, key, versionId string, days int) error` method:
   - Lock backend, find bucket and object (with version support)
   - Verify `IsArchivedStorageClass(obj.StorageClass)` → else return `ErrInvalidRequest`
   - Set `obj.Restored = true`
   - If `days > 0`: set `obj.RestoreExpiryDate` to `now + days`
   - If `days == 0`: permanent restore, set `obj.RestoreExpiryDate = nil`
   - Reuse existing `getObjectVersionUnlocked` pattern from `objectlock.go`

**`internal/handler/object.go`**

4. **Route POST `?restore`** (after line 970, near the POST `?uploads` check):
   ```go
   if r.Method == http.MethodPost && query.Has("restore") {
       h.handleRestoreObject(w, r, bucketName, key)
       return
   }
   ```

5. **Add `handleRestoreObject` handler:** Parse `RestoreRequest` XML, call `backend.RestoreObject`, return 200 OK.

6. **Add `setRestoreHeader` helper:** Sets `x-amz-restore` header on responses:
   - Temporary: `ongoing-request="false", expiry-date="<RFC1123>"`
   - Permanent: `ongoing-request="false"`

7. **Add `x-amz-restore` header to GET and HEAD responses** (after `setStorageAndEncryptionHeaders` at lines 1407 and 1661): Call `setRestoreHeader(w, obj)`.

8. **Block GET on non-restored archived objects** (before writing response body in GET handler): If `IsArchivedStorageClass(obj.StorageClass) && !obj.Restored` → return `InvalidObjectState` error. For HEAD, still return metadata (AWS behavior: `retain_head_object = true`).

9. **Read-through support for GET:** If archived and not restored, auto-restore inline then continue (mock test expects `test_read_through` to work by reading through).

**`internal/handler/handler.go`** (checkAccess switch)

10. Add `s3:RestoreObject` case — use bucket ACL write permission as fallback.

### Unit Tests

**`internal/backend/` tests:**
- RestoreObject temporary/permanent
- RestoreObject on non-archived object → error
- RestoreObject on noncurrent version

**`internal/handler/` tests:**
- POST `?restore` happy path (temp + permanent)
- `x-amz-restore` header on GET/HEAD
- GET on archived non-restored → InvalidObjectState
- Read-through behavior

---

## Implementation Order

1. **Category 1** (Bucket Policy) — smallest, 2 files, ~10 lines of production code
2. **Category 2** (Bucket Logging POST) — medium, 3 files, ~60 lines
3. **Category 3** (Restore/Lifecycle) — largest, 4 files, ~120 lines

## Files Modified

| File | Changes |
|------|---------|
| `internal/handler/bucket.go` | Add checkAccess to Get/DeleteBucketPolicy; add POST ?logging route + handler |
| `internal/handler/handler.go` | Add checkAccess cases; add forceFlush method; refactor flushBatch return |
| `internal/handler/object.go` | Add POST ?restore route + handler; add setRestoreHeader; add archive blocking |
| `internal/backend/backend.go` | Add Restored/RestoreExpiryDate fields to Object |
| `internal/backend/type.go` | Add RestoreRequest, PostBucketLoggingResult, IsArchivedStorageClass |
| `internal/backend/object.go` (or `restore.go`) | Add RestoreObject method |

## Verification

1. `task lint` — check formatting and lint
2. `task unit-test` — run unit tests with race detection
3. `task sdk-test` — run SDK integration tests
4. `task s3-test` — run full Ceph s3-tests to verify the 60+ failures are resolved
