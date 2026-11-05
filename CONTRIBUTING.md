# Contributing to Keel

Thanks for helping out. Keel is a small set of shared Go libraries, so changes should stay small and focused.

## Before you open a pull request

Run these from the repository root. All of them must pass:

```
go build ./... && go vet ./... && go test ./... -race
```

Or use `make vet`, `make test` and `make lint`.

## Ground rules

- **Keep Keel domain-free.** No backup, firewall, catalog or policy concepts. If code needs to know what a "service" or a "rule" is, it belongs in the product that uses it, not here.
- **Every exported name needs a doc comment.** Start it with the name, as in `// Set returns ...`.
- **Use table-driven tests** with the standard `testing` package.
- **Never log or return a secret.** Use the `secret` package for redaction.
- **Use conventional commit messages**, such as `feat:`, `fix:`, `test:` and `docs:`.
- **Add a `CHANGELOG.md` entry** for anything a consumer would notice, including breaking changes.

## Developing alongside Ballast or Hull

To test Keel changes inside a product before a release, create a local workspace file. It is not committed, so it will not affect anyone else:

```
go work init . ../ballast
```

The `go.work` file is already in `.gitignore`. Do not add a `replace` directive to `go.mod`.
