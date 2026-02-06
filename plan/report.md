# Minis3 AWS S3 API 忠実度レポート

AWS公式ドキュメントとminis3の実装を突き合わせた比較結果。

---

## 忠実に再現されている部分

### 1. コアオブジェクト操作

| 操作 | 評価 | 詳細 |
|------|------|------|
| **PutObject** | ◎ | `Content-Type`, `Cache-Control`, `Expires`, `Content-Encoding`, `Content-Language`, `Content-Disposition`, `x-amz-meta-*` ヘッダー全対応。AWS chunked encoding もサポート |
| **GetObject** | ◎ | `Range` ヘッダー（`bytes=start-end`, `bytes=start-`, `bytes=-suffix`）、条件付きヘッダー4種（`If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`）を仕様通りの優先順位で評価 |
| **HeadObject** | ◎ | GetObject と同じヘッダーをボディなしで返す。仕様通り |
| **DeleteObject** | ◎ | `versionId` 対応、Delete Marker の `x-amz-delete-marker` / `x-amz-version-id` ヘッダーも正しい |
| **CopyObject** | ◎ | `x-amz-copy-source` のURL decode、`versionId` パース、`x-amz-metadata-directive` (COPY/REPLACE)、自己コピー禁止チェック |

### 2. バケット操作

| 操作 | 評価 | 詳細 |
|------|------|------|
| **CreateBucket** | ◎ | `CreateBucketConfiguration` XML パース、`Location` ヘッダー返却、バケット名バリデーション、`BucketAlreadyOwnedByYou` / `BucketAlreadyExists` エラーコード |
| **DeleteBucket** | ◎ | 空でない場合 `BucketNotEmpty` (409)、存在しない場合 `NoSuchBucket` (404) |
| **HeadBucket** | ◎ | `x-amz-bucket-region` と `x-amz-access-point-alias` ヘッダー。404でもregionヘッダーを返す仕様も再現 |
| **ListBuckets** | ○ | `prefix`, `continuation-token`, `max-buckets` 対応 |

### 3. バージョニング

| 操作 | 評価 | 詳細 |
|------|------|------|
| **GetBucketVersioning** | ◎ | Unset/Enabled/Suspended の3状態を正しく管理。MfaDelete も |
| **PutBucketVersioning** | ◎ | `x-amz-mfa` ヘッダーの検証（シリアル番号 + 6桁トークン）も実装 |
| **ListObjectVersions** | ◎ | `key-marker`, `version-id-marker`, `prefix`, `delimiter`, `max-keys`, `encoding-type` 全対応 |
| **Delete Marker** | ◎ | Delete Marker 時に `x-amz-delete-marker: true` ヘッダーと404を返す挙動が仕様通り |

### 4. マルチパートアップロード

| 操作 | 評価 | 詳細 |
|------|------|------|
| **CreateMultipartUpload** | ◎ | `Content-Type`, `x-amz-meta-*` を保存 |
| **UploadPart** | ◎ | パート番号 1-10000 のバリデーション |
| **CompleteMultipartUpload** | ◎ | `InvalidPart`, `InvalidPartOrder`, `EntityTooSmall` エラー |
| **AbortMultipartUpload** | ◎ | 204 No Content を返す |
| **ListMultipartUploads** | ◎ | `prefix`, `delimiter`, `key-marker`, `upload-id-marker`, `max-uploads` |
| **ListParts** | ◎ | `part-number-marker`, `max-parts` |
| **UploadPartCopy** | ◎ | `x-amz-copy-source-range` 対応 |

### 5. XML レスポンス構造

- `ListBucketResult` (V1/V2)、`ListVersionsResult`、`DeleteResult` 等のXML構造がAWS仕様に準拠
- `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"` が正しく設定
- `EncodingType=url` 時のキーURLエンコードも対応

### 6. エラーレスポンス

- AWS S3 準拠の XML `<Error>` フォーマット（`Code`, `Message`, `Resource`, `RequestId`）
- HTTPステータスコードのマッピングがおおむね正しい（404, 409, 400, 412, 416 等）

### 7. バケット設定系API

タグ、ポリシー、ACL、Object Lock、Lifecycle、暗号化、CORS、Website、Public Access Block — 全て GET/PUT/DELETE の三点セットが揃っており、適切なエラーコードも返す。

---

## 差異・未実装部分

### A. PutObject の未対応ヘッダー

AWS公式ドキュメントではサポートされているが、minis3では未実装のヘッダー:

| ヘッダー | 重要度 | 備考 |
|----------|--------|------|
| `x-amz-server-side-encryption` | 中 | SSE関連ヘッダー群（SSE-S3, SSE-KMS, SSE-C）全般が未対応。バケットレベルの暗号化設定は保存できるが、PutObject時の暗号化処理やヘッダーの受理/返却はされない |
| `x-amz-storage-class` | 低 | 常に `STANDARD` 固定。モックとしては問題ない |
| `x-amz-tagging` | 中 | PutObject時にインラインでタグを設定する `x-amz-tagging` ヘッダーが未対応（PutObjectTagging APIは別途あり） |
| `x-amz-website-redirect-location` | 低 | |
| `Content-MD5` | 中 | データ整合性チェック未実装 |
| `x-amz-grant-*` | 低 | 個別のgrant系ヘッダー（`x-amz-grant-full-control`, `x-amz-grant-read` 等）が未対応。`x-amz-acl` の canned ACL のみ |
| `If-None-Match` (PutObject用) | 低 | PutObject時の条件付き書き込み（キー重複チェック）は未実装 |
| `x-amz-object-lock-mode/retain-until-date/legal-hold` | 中 | PutObject時にObject Lockをインライン設定するヘッダーが未対応（API経由のPutObjectRetention/PutObjectLegalHoldは別途あり） |
| `x-amz-checksum-*` (CRC32C, SHA1, SHA256) | 低 | CRC32のみ対応。CRC32C, CRC64NVME, SHA1, SHA256は未対応 |
| `x-amz-write-offset-bytes` | 低 | Express One Zone向け機能 |

### B. CopyObject の未対応ヘッダー

| ヘッダー | 重要度 | 備考 |
|----------|--------|------|
| `x-amz-copy-source-if-match` | 中 | コピー元の条件付きヘッダー4種が未対応 |
| `x-amz-copy-source-if-none-match` | 中 | 同上 |
| `x-amz-copy-source-if-modified-since` | 中 | 同上 |
| `x-amz-copy-source-if-unmodified-since` | 中 | 同上 |
| `x-amz-tagging-directive` | 低 | タグのコピー方針 |

### C. GetObject の未対応機能

| 機能 | 重要度 | 備考 |
|------|--------|------|
| **レスポンスヘッダーオーバーライド** | 中 | `response-content-type`, `response-content-disposition` 等のクエリパラメータ未対応 |
| **複数Range** | 低 | `bytes=0-100,200-300` のようなマルチレンジは未対応 |

### D. DeleteObjects の差異

| 項目 | 重要度 | 備考 |
|------|--------|------|
| `Content-MD5` チェック | 中 | AWS仕様では必須だが、minis3ではバリデーションしていない |
| `x-amz-mfa` ヘッダー | 低 | MFA Delete有効バケットでのDeleteObjects時のMFAトークン検証が未対応 |
| `x-amz-bypass-governance-retention` | 低 | GOVERNANCE modeのObject Lock回避 |
| **1000件制限** | 低 | リクエスト中のオブジェクト数1000件上限のバリデーションが見当たらない |

### E. ETag の計算

| 項目 | 重要度 | 備考 |
|------|--------|------|
| **通常オブジェクトのETag** | 確認要 | AWS仕様ではMD5ハッシュをETagとして返す。minis3の実装が `md5(data)` ベースかは backend の実装次第 |
| **マルチパートETag** | 中 | AWS仕様では `MD5(concatenation of part MD5s)-N` 形式。この計算が忠実かどうか |

### F. Presigned URL

`auth.go` にPresigned URL検証の実装があるが、SigV4の完全な署名検証ではなく、基本的な形式チェックのみと思われる。テスト用途としては十分。

### G. 未実装のS3 API

以下のAPIはminis3に存在しない:

| API | 重要度 | 備考 |
|-----|--------|------|
| **SelectObjectContent** | 中 | S3 Select (SQLクエリ) |
| **RestoreObject** | 低 | Glacier復元 |
| **GetBucketNotification / PutBucketNotification** | 中 | イベント通知設定 |
| **GetBucketLogging / PutBucketLogging** | 低 | アクセスログ |
| **GetBucketReplication / PutBucketReplication** | 低 | クロスリージョンレプリケーション |
| **GetBucketRequestPayment / PutBucketRequestPayment** | 低 | |
| **GetBucketAnalyticsConfiguration** | 低 | |
| **GetBucketInventoryConfiguration** | 低 | |
| **GetBucketMetricsConfiguration** | 低 | |
| **GetBucketIntelligentTieringConfiguration** | 低 | |
| **CreateSession** | 低 | Directory Buckets用 |
| **WriteGetObjectResponse** | 低 | Lambda Object Transform用 |

### H. Virtual-hosted style リクエスト

path-styleのみ対応。`bucket.s3.amazonaws.com` 形式のvirtual-hosted styleは未サポート（CLAUDE.mdにも明記済み）。

---

## 総合評価

| カテゴリ | 再現度 |
|----------|--------|
| **コアオブジェクト操作 (CRUD)** | ★★★★★ |
| **バージョニング** | ★★★★★ |
| **マルチパートアップロード** | ★★★★☆ |
| **条件付きリクエスト (GET/HEAD)** | ★★★★★ |
| **バケット設定系API** | ★★★★★ |
| **XMLレスポンス構造** | ★★★★★ |
| **エラーハンドリング** | ★★★★☆ |
| **PutObject/CopyObject ヘッダー** | ★★★☆☆ |
| **認証・署名** | ★★☆☆☆ |
| **高度な機能（SSE, Select等）** | ★☆☆☆☆ |

**総合: ★★★★☆**

ユニットテスト用のS3モックサーバーとしては非常に完成度が高い。AWS SDK v2を使った基本的なS3操作（CRUD、バージョニング、マルチパート、条件付きリクエスト、バケット設定）はほぼ忠実に再現されている。

---

## 改善候補（優先度順）

1. **`x-amz-tagging` ヘッダー対応** — PutObject時のインラインタグ設定
2. **CopyObjectの条件付きヘッダー** — `x-amz-copy-source-if-match` 等4種
3. **GetObjectのレスポンスヘッダーオーバーライド** — `response-content-type` 等のクエリパラメータ
4. **PutObject時のObject Lockインライン設定** — `x-amz-object-lock-mode` 等のヘッダー
