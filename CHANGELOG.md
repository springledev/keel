# Changelog

## Unreleased

- Add `dockerhost`, moved from Ballast's `internal/dockerhost` (ballast commit 6fe6639) with its tests. It is decoupled from Ballast's restic `backend` package: SSH key validation now comes from the new `sshkey` package. **Breaking for Ballast's migration:** `DefaultCredentialName(host)` is now `DefaultCredentialName(product, host)`. Ballast must pass `"ballast"` to keep its existing credential file names (`ballast-dockerhost.<host>`). User-facing messages no longer name Ballast (for example, "not installed on this machine" instead of "on the Ballast machine"), so Ballast tests that match those strings need updating.
- Add `sshkey.Render`, moved from the SSH branch of Ballast's `backend.RenderCredentials`, together with `opensshEncrypted` and its tests. The passphrase error message is now product-neutral. Ballast's `backend` can call it once it migrates.
- Initial extraction of `secret` and `runner` from Ballast (commit 8add0bc of ballast), with import paths changed to `github.com/springledev/keel/...` and product-specific comments generalized.
