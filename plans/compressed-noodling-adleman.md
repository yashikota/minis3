# 実装計画: ドキュメント更新 & コード品質改善（第3弾）

## Context

第1弾・第2弾の改善で多くの S3 機能（Object Lock enforcement, SSE, StorageClass, response overrides, copy conditionals, etc.）を実装済み。
しかし README.md の「Unsupported Features」列が古いままで、実装済み機能が未サポートと誤表示されている。
CLAUDE.md も同様に多数の実装済み機能が未記載。
加えて、軽微なコード品質改善（Content-Type デフォルト、XML namespace 定数化）を行う。

---

## 実装順序

| # | タスク | リスク |
|---|--------|--------|
| 1 | S3 XML namespace 定数化 | なし（純リファクタ） |
| 2 | Content-Type デフォルト `application/octet-stream` | 低 |
| 3 | Content-Type テスト追加 | なし |
| 4 | README.md 更新 | なし（ドキュメントのみ） |
| 5 | CLAUDE.md 更新 | なし（ドキュメントのみ） |

---

## 1. S3 XML namespace 定数化

**変更ファイル**: 6ファイル、23箇所

`internal/backend/type.go` に定数を追加:
```go
const S3Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
```

以下のファイルで `"http://s3.amazonaws.com/doc/2006-03-01/"` → 定数に置換:

| ファイル | 箇所数 | 使用する名前 |
|----------|--------|-------------|
| `internal/backend/bucket.go` | 2 | `S3Xmlns` |
| `internal/handler/bucket.go` | 11 | `backend.S3Xmlns` |
| `internal/handler/object.go` | 3 | `backend.S3Xmlns` |
| `internal/handler/objectlock.go` | 3 | `backend.S3Xmlns` |
| `internal/handler/multipart.go` | 4 | `backend.S3Xmlns` |

---

## 2. Content-Type デフォルト

**変更ファイル**: `internal/backend/object.go`

**PutObject 関数**: `opts.ContentType` が空の場合 `"application/octet-stream"` をデフォルト設定。
（`CompleteMultipartUpload` では既にこのデフォルトが実装済み: `multipart.go:199`）

```go
contentType := opts.ContentType
if contentType == "" {
    contentType = "application/octet-stream"
}
```

**CopyObject 関数**: REPLACE directive 時に `opts.ContentType` が空の場合も同様にデフォルト適用。

---

## 3. Content-Type テスト

**変更ファイル**: `internal/backend/object_test.go`

`TestContentTypeDefault` を追加:
- Content-Type 未指定 → `application/octet-stream` 確認
- Content-Type 明示指定 → そのまま保持確認
- CopyObject REPLACE で未指定 → デフォルト確認
- CopyObject COPY → ソースの Content-Type をコピー確認

---

## 4. README.md 更新

### Object Operations テーブルの修正

| Operation | 現状の Unsupported | 修正後の Unsupported |
|-----------|-------------------|---------------------|
| PutObject | StorageClass, WebsiteRedirectLocation, Tagging, ChecksumAlgorithm | WebsiteRedirectLocation, ChecksumAlgorithm |
| GetObject | ResponseCacheControl, ResponseContentDisposition, ResponseContentEncoding, ResponseContentLanguage, ResponseContentType, ResponseExpires, PartNumber, ChecksumMode | PartNumber, ChecksumMode |
| DeleteObject | MFA Delete (API format only) | *空欄（✅に変更）* |
| CopyObject | 9項目 | WebsiteRedirectLocation, ChecksumAlgorithm |
| HeadObject | PartNumber, ChecksumMode | *(変更なし)* |

### 「Additional Features」セクション追加（テーブルの後に）

以下の横断的な機能を記載:
- Conditional Headers（If-Match, If-None-Match, If-Modified-Since, If-Unmodified-Since）
- Presigned URLs（SigV4 / SigV2）
- AWS Chunked Encoding
- Response Header Overrides（GetObject クエリパラメータ）
- Copy Source Conditionals
- Object Lock Enforcement（delete 時の retention/legal hold チェック + bypass-governance-retention）
- StorageClass サポート
- SSE ヘッダーサポート（モック：保存・返却のみ、暗号化なし）
- x-amz-request-id / x-amz-id-2 ヘッダー
- Metadata / Tagging Directives（CopyObject）

---

## 5. CLAUDE.md 更新

「Supported S3 Operations」セクションに以下を追加:

- **Presigned URLs:** SigV4 / SigV2 presigned URL verification.
- **Additional Features:** に以下を追記:
  - AWS chunked encoding
  - Response header overrides (GetObject query params)
  - Copy source conditional headers
  - Object Lock enforcement on delete (bypass-governance-retention)
  - StorageClass support
  - SSE header support (mock)
  - x-amz-request-id / x-amz-id-2 headers
  - Metadata/Tagging directives in CopyObject
  - Content-Type default to application/octet-stream

---

## 検証手順

```bash
task lint        # Lint（定数化リファクタ後に確認）
task unit-test   # ユニットテスト
task sdk-test    # SDK統合テスト
task test        # 全テスト
```
