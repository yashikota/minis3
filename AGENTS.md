# Repository Guidelines

## Project Structure & Module Organization
- `minis3.go` is the public entry point for starting the S3 test server.
- `internal/backend/` contains S3 state and behavior (bucket/object/versioning/lifecycle logic).
- `internal/handler/` contains HTTP/S3 request handling, auth checks, and response shaping.
- Root tests (for example `minis3_test.go`) cover package behavior.
- `integration/sdk/` is a separate Go module for AWS SDK integration tests.
- `integration/s3-test/` contains Docker-based compatibility tests and `s3-tests`.
- `taskfile.yaml` defines local commands; `.github/workflows/` mirrors CI checks.

## Build, Test, and Development Commands
- `task`: list available tasks.
- `task lint`: run lint + formatting (`golangci-lint run --fix`, formatter pass).
- `task unit-test`: run unit tests with race detection and shuffled order.
- `task sdk-test`: run integration tests in `integration/sdk`.
- `task test`: run unit + SDK suites.
- `task s3-test`: run Ceph `s3-tests` via Docker (slow, optional locally).
- `go test ./... -coverprofile=coverage.txt`: reproduce coverage job locally.

## Coding Style & Naming Conventions
- Target Go version in `go.mod` (currently 1.25.x).
- Use configured formatters (`gofmt`, `gofumpt`, `goimports`).
- Keep file names lowercase and domain-oriented (for example `bucket.go`, `objectlock.go`).
- Tests must be in `*_test.go`; branch-focused suites can use `*_branches_test.go`.
- Follow Go naming rules: exported symbols in `CamelCase`, unexported in `camelCase`.

## Testing Guidelines
- Prefer table-driven tests for S3 edge cases and error mapping.
- Use `t.Cleanup` for server/resource teardown to keep tests isolated.
- Run `task test` before every PR; run `task s3-test` when protocol behavior changes.
- Target `100%` coverage in touched packages and changed branches.
- For every implementation change, add meaningful unit tests for happy paths, edge cases, and AWS-spec error behavior.

## AWS Spec Priority
- Verify behavior against AWS documentation before implementing or reviewing S3 semantics.
- If implementation behavior conflicts with AWS spec, treat the AWS spec as the source of truth and update code/tests accordingly.

## Commit & Pull Request Guidelines
- Prefer commit prefixes used in history: `feat:`, `fix:`, `test:`, `chore:` (optional scopes like `test(backend):`).
- Keep subjects imperative and concise; include PR refs when applicable (for example `(#16)`).
- PRs should include: change summary, impacted S3 operations, and validation results.
- Link related issues and include request/response examples for API behavior changes.
- Use `git worktree` (`git wt`) for parallel tasks (for example `git worktree add ../minis3-<topic> -b <branch>`).
- Commit at meaningful checkpoints, then open PRs with `gh pr create` after local validation.
