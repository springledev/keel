# AGENTS.md — Keel

Keel holds the small, domain-free Go libraries shared by **Ballast** (`../ballast`, backups) and **Hull** (`../hull`, firewalls). See `../hull/docs/shared-libraries.md` for the extraction plan and timing.

## Rules

1. **Domain-free.** No backup, firewall, catalog or policy concepts. If a package needs to know what a "service" or "rule" is, it belongs in a product, not here.
2. **Extraction is a move, not a rewrite.** Keep code and tests together, change import paths, preserve behavior. Improvements go in a separate change.
3. **Secrets never leak.** Nothing here may log or return a secret; `secret.Set` is the only redaction mechanism.
4. **Stack:** Go 1.25, `CGO_ENABLED=0`, standard `testing` (table-driven), `-race`, golangci-lint v2.14. No third-party dependencies unless unavoidable.
5. **Every exported thing has a doc comment.**
6. **Fix here first.** While Ballast still carries its own `internal/` copies, any fix to a shared package lands in Keel first and is ported back to Ballast.
7. `go build ./...`, `go vet ./...`, `go test ./... -race` must be green before finishing.
8. Versioning: tag `v0.x`; breaking changes are allowed pre-v1 but get a `CHANGELOG.md` entry and a PR in each consumer. Commits: conventional style.

## Packages

- `secret/` — concurrency-safe redaction set for secret strings.
- `runner/` — subprocess execution with pipefail, SIGPIPE handling, cancellation, capped+redacted stderr tails, credential-file env helpers.

## Planned (extract when a product first needs it)

`dockerhost` (Hull step 1), notification `Channel`/`Notifier` (Hull step 7), `proxmox` client (Hull step 8); maybe the SQLite migration runner and XDG/credential-directory helpers.
