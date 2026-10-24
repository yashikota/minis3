# Minis3 🪣

[![codecov](https://codecov.io/gh/yashikota/minis3/graph/badge.svg?token=16VPV4FWZE)](https://codecov.io/gh/yashikota/minis3)
[![s3-tests](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/yashikota/minis3/main/.github/badges/s3-tests.json&cacheSeconds=300)](https://github.com/yashikota/minis3/actions/workflows/s3tests.yaml)

Minis3 は、S3 を使うコードを素早くテストするためのインメモリ S3 サーバーです。  
実際の TCP インターフェースで動作するため、`net/http/httptest` の S3 版のように利用できます。

<img width="962" height="873" alt="minis3" src="https://github.com/user-attachments/assets/cc204216-f665-4f08-b6e4-bc56cfb0bd3b" />

## 使い方

### Go パッケージとして使う

```bash
go get github.com/yashikota/minis3
```

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/yashikota/minis3"
)

func main() {
	// 1. minis3 を起動
	server := minis3.New()
	server.Start()
	defer server.Close()
	fmt.Printf("minis3 started at %s\n", server.Addr())

	// 2. AWS SDK の接続先を minis3 に設定
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(
			aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
				return aws.Credentials{
					AccessKeyID:     "test",
					SecretAccessKey: "test",
					SessionToken:    "",
				}, nil
			}),
		),
	)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + server.Addr())
		o.UsePathStyle = true // 重要: minis3 は現在 path-style をサポート
	})

	// 3. バケット作成
	bucketName := "example-bucket"
	_, err = client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("failed to create bucket: %v", err)
	}
	fmt.Printf("Created bucket: %s\n", bucketName)

	// 4. オブジェクト保存
	key := "example-key"
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
		Body:   strings.NewReader("Hello from minis3 example!"),
	})
	if err != nil {
		log.Fatalf("failed to put object: %v", err)
	}
	fmt.Printf("Put object: %s\n", key)

	// 5. オブジェクト取得
	resp, err := client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Fatalf("failed to get object: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read object body: %v", err)
	}
	fmt.Printf("Got object content body: %s\n", string(bodyBytes))
	fmt.Printf("Got object content type: %s\n", *resp.ContentType)
}
```

### スタンドアロンの S3 互換サーバーとして使う

バイナリをインストール  

```bash
go install github.com/yashikota/minis3/cmd/minis3@latest
```

もしくは [Releases](https://github.com/yashikota/minis3/releases/latest) からダウンロード  

サーバー起動（デフォルトポートは `9191`）  

```bash
minis3
```

ポートを指定する場合  

```bash
minis3 --port 9000
```

ヘルスチェック  

```bash
curl -i http://127.0.0.1:9191/health
```

## 📋 サポート済み操作

> [!Note]
> Minis3 は「単一リージョン・単一オーナー」のインメモリモックサーバーです。  
> `ExpectedBucketOwner`、`BucketRegion` フィルタ、マルチリージョン対応はモック用途では意味が薄いため未実装です。  
> また `x-amz-mfa` ヘッダーは形式のみ検証し、実際の TOTP 認証は行いません。

### サポート状況サマリー

| 領域 | 状態 | 実装済み API 数 |
| ---- | ---- | --------------- |
| バケット操作 | ✅ フルサポート | 41 |
| オブジェクト操作 | ✅ フルサポート | 17 |
| Object Lock 操作 | ✅ フルサポート | 6 |
| マルチパートアップロード操作 | ✅ フルサポート | 7 |

### カテゴリ別 API 一覧

<details>
<summary>🪣 バケット操作 (41)</summary>

`ListBuckets`, `CreateBucket`, `DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketTagging`, `PutBucketTagging`, `DeleteBucketTagging`, `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicyStatus`, `GetBucketAcl`, `PutBucketAcl`, `GetBucketOwnershipControls`, `PutBucketOwnershipControls`, `DeleteBucketOwnershipControls`, `GetBucketRequestPayment`, `PutBucketRequestPayment`, `GetBucketLogging`, `PutBucketLogging`, `DeleteBucketLogging`, `GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetBucketLifecycleConfiguration`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle`, `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption`, `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors`, `GetBucketWebsite`, `PutBucketWebsite`, `DeleteBucketWebsite`, `GetPublicAccessBlock`, `PutPublicAccessBlock`, `DeletePublicAccessBlock`

</details>

<details>
<summary>📦 オブジェクト操作 (17)</summary>

`PutObject`, `GetObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`, `HeadObject`, `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `GetObjectAcl`, `PutObjectAcl`, `GetObjectAttributes`, `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`, `RestoreObject`, `PostObject`（ブラウザベースの multipart form アップロード）

</details>

<details>
<summary>🔒 Object Lock 操作 (6)</summary>

`GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetObjectRetention`, `PutObjectRetention`, `GetObjectLegalHold`, `PutObjectLegalHold`

</details>

<details>
<summary>📤 マルチパートアップロード操作 (7)</summary>

`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`, `ListParts`, `UploadPartCopy`

</details>

### API 固有の制限

| 操作 | 未対応のオプションフィールド / 簡易化された挙動 |
| ---- | ---------------------------------------------- |
| `UploadPartCopy` | `CopySourceSSECustomerAlgorithm`, `CopySourceSSECustomerKey`, `CopySourceSSECustomerKeyMD5`, `SSECustomerAlgorithm`, `SSECustomerKey`, `SSECustomerKeyMD5` |
| `RestoreObject` | リストアは即時完了。`x-amz-restore` は常に `ongoing-request="false"` を返す |
| `aws:kms` 指定の `PutObject` / `CopyObject` | `x-amz-server-side-encryption-aws-kms-key-id` は任意（省略時は AWS 同様デフォルトキー扱い）。ヘッダーは保存のみで実際の暗号化はしない |
| `PutBucketPolicy` | ポリシーは厳格に検証され、未知の要素・アクション・条件演算子や不正な値は `MalformedPolicy` で拒否される。`Principal`/`NotPrincipal`（`AWS` のアカウント ID・アカウント root / ユーザー ARN、`CanonicalUser`、`Service`）、`Action`/`NotAction`、`Resource`/`NotResource`、全 IAM 条件演算子ファミリー（String・Numeric・Date・Bool・Binary・IpAddress・Arn・Null、`IfExists` と `ForAllValues`/`ForAnyValue` 付き）を評価する。`NotPrincipal` と `Allow` の組み合わせは拒否。`Resource` は省略可能で、`Sid` の重複は許容する（RGW と同じ） |
| MFA Delete | `x-amz-mfa` が `<シリアル> <コード>` 形式で存在することのみ検証し、コード自体は検証しない |

### 追加機能

- **条件付きヘッダー:** GetObject/HeadObject で `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`
- **署名付き URL:** SigV4 / SigV2 presigned URL の署名・アクセスキー・期限を検証
- **SigV2 `Authorization` ヘッダー:** アクセスキー、HMAC-SHA1 署名、`Date`/`x-amz-date` の時刻ずれを検証
- **AWS Chunked Encoding:** `aws-chunked` 転送エンコーディングの透過デコード
- **レスポンスヘッダー上書き:** GetObject の `response-content-type`, `response-content-disposition` など
- **コピー元条件ヘッダー:** `x-amz-copy-source-if-match`, `x-amz-copy-source-if-none-match`, `x-amz-copy-source-if-modified-since`, `x-amz-copy-source-if-unmodified-since`
- **認可:** 全ての操作を S3 API リファレンスどおりの IAM アクション（例: `DeleteBucketTagging` → `s3:PutBucketTagging`、`GetObject?versionId` → `s3:GetObjectVersion`）で、バケットポリシー・所有者・ACL（READ/WRITE/READ_ACP/WRITE_ACP は AWS の対応表どおりのアクションだけを許可）・Object Ownership・パブリックアクセスブロックに照らして認可。`DeleteObjects` はキーごとに認可し、拒否したキーを `AccessDenied` として返す。POST Object はフォームの署名者を認可。RGW と同じく、バケットのログ設定を変更できるのは所有者のみ
- **Object Lock 強制:** `x-amz-bypass-governance-retention` を含む削除時の保持/リーガルホールド検証（`s3:BypassGovernanceRetention` 権限がある場合のみ有効）
- **StorageClass:** PutObject, CopyObject, マルチパートアップロードでサポート
- **SSE ヘッダー:** 保存・返却のみ実装（モック。実暗号化は未実装）
- **リクエスト ID:** 全レスポンスに `x-amz-request-id`, `x-amz-id-2` を付与
- **Metadata/Tagging Directive:** CopyObject で `x-amz-metadata-directive`, `x-amz-tagging-directive`
- **Content-Type 既定値:** 未指定時は `application/octet-stream`
- **POST Object（ブラウザアップロード）:** `POST /{bucket}` で `multipart/form-data`（`key`・`file` フィールド、POST ポリシー/署名検証、tagging・checksum・metadata に対応）
- **バケット logging フラッシュ（テスト用拡張）:** `POST /{bucket}?logging` で保留中のサーバーアクセスログバッチを強制フラッシュ
- **CreateBucket の冪等性:** 既に所有するバケットの再作成はエラーではなく成功（`200`）として扱う
- **管理用 ForceDeleteBucket（テスト用拡張）:** `DELETE /_minis3/buckets/{bucket}` でバケットと全オブジェクトを無条件に削除

## 🧪 開発・テスト

- `task lint`: lint / format チェックを実行
- `task unit-test`: ユニットテスト（race 検出・シャッフル実行）
- `task sdk-test`: `integration/sdk` の統合テスト
- `task s3-test`: Docker で Ceph `s3-tests` を実行
- `task test`: `unit-test`, `sdk-test`, `s3-test` を順に実行
- `task formal`: `formal/tla` の TLA+ 仕様を [tlc-static](https://github.com/yashikota/tlc-static) の静的 TLC バイナリ（初回実行時に取得しチェックサムを検証。Java 不要）でモデル検査し、Go のモデルベーステストを実行
- `task tobari`: tobari でスコープ別カバレッジを測定（`./tobari/tobari.json` に出力）
- `task tobari-html`: `tobari/tobari.json` から HTML カバレッジレポートを生成

### 形式検証

`formal/tla` には TLA+ 仕様があり、TLC モデル検査器が小さな範囲で全状態を網羅的に探索します。

- `S3Versioning.tla`: バージョニング状態（Unset → Enabled ⇄ Suspended）、null バージョンの置き換え、削除マーカー、完全削除、Object Lock とリーガルホールド。不変条件は「null バージョンは高々1つ」「バージョン ID の一意性」「新しい順の並び」「Object Lock ならバージョニング有効」など。時相性質は「一度バージョニングしたバケットは未設定に戻らない」「リーガルホールド中のバージョンは消えない」など。
- `S3BucketPolicy.tla`: あらゆるステートメント形（Principal/NotPrincipal、Action/NotAction、Resource/NotResource、条件）でのバケットポリシー評価。実装と同じ形の1パス評価が宣言的な意味（明示的 Deny が優先、なければ Allow が1つでもあれば許可）と一致すること、ステートメントの順序に依存しないこと、Deny は覆らず Allow は単調であること、匿名ユーザーは `*` でしか一致しないこと、Not* 要素が正確な補集合であることを検査します。`S3BucketPolicyPairs.cfg` は2ステートメントの全組み合わせを探索します。
- `S3Authorization.tla`: 1リクエストのアクセス判定。呼び出し元（所有者・他ユーザー・匿名）、アクションの種類、ポリシーの判定、公開ポリシー、ACL 付与、Object Ownership、パブリックアクセスブロックの全組み合わせ（4,800 リクエスト）について、実装の判定手順が宣言的な規則と一致すること、明示的 Deny が優先される（所有者のポリシー管理は例外）こと、BucketOwnerEnforced では ACL が無視されること、IgnorePublicAcls・RestrictPublicBuckets が仕様どおりに働くこと、条件不成立の Allow が ACL にフォールバックしないこと、設定系アクションには所有者かポリシーが必要なこと、付与と Allow が単調でブロックは制限にしか働かないことを検査します。
- `S3PolicyCondition.tla`: 全ての一致関係に対する IAM 条件演算子の代数。通常の演算子では否定が補集合になること、`IfExists` はキーが無い場合だけを変えること、空集合での `ForAllValues`/`ForAnyValue`、集合修飾子と否定のド・モルガン双対性、値リストが論理和であること、`Null` が存在判定であることを検査します。
- `S3ListPaging.tla`: ListObjects V1/V2、ListObjectVersions、ListMultipartUploads に共通する継続マーカーの規則（CommonPrefix も max-keys に数える、`(key, version)` の直後から再開）。全エントリがちょうど1回ずつ順番どおり返ること、IsTruncated が残りがあるときだけ立つこと、ページングが停止することを検査します。

実装とモデルは、同じ規則を実際の backend に対して検査する Go テストで結び付けています。

- `internal/backend/model_versioning_test.go`: バージョニング仕様の参照モデルを backend とロックステップで動かし、ランダムな操作列で比較（`TestVersioningModelRandomSequences`、`FuzzVersioningModel`）
- `internal/backend/paging_property_test.go`: ページごとの一覧結果を独立したオラクルと比較（`TestListPagingProperties`、`FuzzListPagingProperties`）
- `internal/handler/authorization_model_test.go`: 認可モデルの全リクエストを実際のバケットに構成し、ルーターの判定をモデルと比較（`TestAuthorizationModel`）。`internal/handler/operations_test.go` は全ルートの操作→IAM アクション表と、各操作がちょうどそのアクションで判定されることを検査（`TestOperationTable`、`TestOperationAuthorizationMatrix`）
- `internal/backend/policy_model_test.go`: ポリシーと条件のモデルを Go に書き写し、全単一ステートメント・全ステートメント対・ランダムな長いポリシーについて実際のポリシー検証器・評価器と比較（`TestBucketPolicyModel*`、`TestPolicyConditionModel`）

`task formal` で全部、`formal/tla/check.sh` で TLC のみを実行できます。

### `task s3-test` のマーカーポリシー

既定の `task s3-test` は `integration/s3-test/compose.yaml` の `PYTEST_ADDOPTS` により、`fails_on_aws` と `fails_on_rgw` のマーカー付きテストを除外します。  
日常実行では AWS 互換性の確認を優先し、非 AWS / 非 RGW 前提のケースを切り離すためです。  
マーカー除外なしで全件実行する場合は `integration/s3-test` で次を実行してください。  

```sh
docker compose run --rm -e PYTEST_ADDOPTS="" s3tests
```

## Credits

[Miniredis](https://github.com/alicebob/miniredis) is a Redis test server, used in Go unittests. Minis3 is inspired by Miniredis.
