# Keel

Small shared Go libraries for [Ballast](https://github.com/springledev/ballast), a self-hosted backup tool for homelab Docker services. Domain-free plumbing only.

| Package | Purpose |
|---|---|
| `secret` | Concurrency-safe redaction set so secrets never reach logs, errors or API responses |
| `runner` | Runs external commands with pipefail semantics, SIGPIPE handling, cancellation, and redacted stderr tails; no shell is ever invoked |
| `dockerhost` | Models local, SSH and TLS Docker daemons and builds `docker` CLI commands carrying each host's connection flags; compose project and volume listing |
| `sshkey` | Validates unencrypted SSH private keys for unattended use |
| `proxmox` | Talks to one Proxmox VE host's REST API with an API token: lists VMs and LXCs and reads or changes the Proxmox firewall |
| `notify` | Notification channels (ntfy, generic webhook, Discord, Slack, email) and a per-service `Notifier`; channel secrets are never logged |

`secret` and `runner` were extracted unchanged (apart from import paths and comments) from Ballast's `internal/secret` and `internal/runner`. `dockerhost` was moved from Ballast's `internal/dockerhost`, and `sshkey` from the SSH branch of Ballast's `backend.RenderCredentials` (see CHANGELOG).

## Install

```
go get github.com/springledev/keel@latest
```

Import only the packages you need:

```go
import (
    "github.com/springledev/keel/proxmox"
    "github.com/springledev/keel/runner"
    "github.com/springledev/keel/secret"
)
```

**Developing keel alongside Ballast:** from a Ballast checkout, run `go work init . ../keel` to build Ballast against your local copy of keel. The `go.work` file is gitignored.

## Support the project

Support the project: https://github.com/sponsors/springledev

## License

Apache-2.0. See [LICENSE](LICENSE).
