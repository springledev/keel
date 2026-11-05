# Keel

Small shared Go libraries for self-hosted Go tools: secrets, subprocesses, Docker hosts, SSH keys, Proxmox and notifications. Domain-free plumbing only.

| Package | Purpose |
|---|---|
| `secret` | Concurrency-safe redaction set so secrets never reach logs, errors or API responses |
| `runner` | Runs external commands with pipefail semantics, SIGPIPE handling, cancellation, and redacted stderr tails; no shell is ever invoked |
| `dockerhost` | Models local, SSH and TLS Docker daemons and builds `docker` CLI commands carrying each host's connection flags; compose project and volume listing |
| `sshkey` | Validates unencrypted SSH private keys for unattended use |
| `proxmox` | Talks to one Proxmox VE host's REST API with an API token: lists VMs and LXCs and reads or changes the Proxmox firewall |
| `notify` | Notification channels (ntfy, generic webhook, Discord, Slack, email) and a per-service `Notifier`; channel secrets are never logged |

See CHANGELOG for the history of each package.

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

**Developing keel alongside a consumer:** from the consumer's checkout, run `go work init . ../keel` to build it against your local copy of keel. The `go.work` file is gitignored.

## Support the project

Support the project: https://github.com/sponsors/springledev

## License

Apache-2.0. See [LICENSE](LICENSE).
