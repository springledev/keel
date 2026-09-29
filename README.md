# Keel

Small shared Go libraries for the Ballast family: [Ballast](../ballast) (backups) and [Hull](../hull) (firewalls). Domain-free plumbing only.

| Package | Purpose |
|---|---|
| `secret` | Concurrency-safe redaction set so secrets never reach logs, errors or API responses |
| `runner` | Runs external commands with pipefail semantics, SIGPIPE handling, cancellation, and redacted stderr tails; no shell is ever invoked |
| `dockerhost` | Models local, SSH and TLS Docker daemons and builds `docker` CLI commands carrying each host's connection flags; compose project and volume listing |
| `sshkey` | Validates unencrypted SSH private keys for unattended use |

`secret` and `runner` were extracted unchanged (apart from import paths and comments) from Ballast's `internal/secret` and `internal/runner`. `dockerhost` was moved from Ballast's `internal/dockerhost`, and `sshkey` from the SSH branch of Ballast's `backend.RenderCredentials` (see CHANGELOG). Not yet importable from other modules until published; until then use a local `go.work`:

```
go work init ../ballast ../hull ../keel
```
