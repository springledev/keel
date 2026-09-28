# Keel

Small shared Go libraries for the Ballast family: [Ballast](../ballast) (backups) and [Hull](../hull) (firewalls). Domain-free plumbing only.

| Package | Purpose |
|---|---|
| `secret` | Concurrency-safe redaction set so secrets never reach logs, errors or API responses |
| `runner` | Runs external commands with pipefail semantics, SIGPIPE handling, cancellation, and redacted stderr tails; no shell is ever invoked |

Extracted unchanged (apart from import paths and comments) from Ballast's `internal/secret` and `internal/runner`. Not yet importable from other modules until published; until then use a local `go.work`:

```
go work init ../ballast ../hull ../keel
```
