# Releasing

A tag `vX.Y.Z` on `main` publishes Parallax X.Y.Z
(`.github/workflows/release.yml`). Nothing goes out unless the whole of CI
passes on the tagged commit first.

## What a release publishes

| Where | What |
|---|---|
| [GitHub Release](https://github.com/ninbura/Parallax/releases) | `parallax-X.Y.Z-linux-amd64` and `-arm64` (static, musl), the `.deb` and Arch package for both, `SHA256SUMS` |
| `ghcr.io/ninbura/parallax` | the gateway image, amd64 and arm64, built from the same static binaries |
| `ghcr.io/ninbura/parallax-headscale` | Headscale from the commit `docker/headscale.Dockerfile` pins, amd64 and arm64 |

Both images get the tag `X.Y.Z`. A final release also moves `X.Y` and
`latest`. A pre-release (`X.Y.Z-rc.1`, anything with a `-`) is marked as such
on GitHub and moves neither. The two images always share a version, because
Parallax's Headscale client is written against the pinned Headscale commit.

Every file and both images have a GitHub build provenance attestation,
which records the repository, workflow and commit that built them.

## Cutting a release

1. On a branch, set `version` under `[workspace.package]` in `Cargo.toml`,
   run `cargo check` (it updates `Cargo.lock`), and merge the PR.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -a vX.Y.Z -m "Parallax X.Y.Z"
   git push origin vX.Y.Z
   ```

The workflow fails before publishing anything if the tag isn't
`v<Cargo.toml version>` or the commit isn't on `main`. If a later job fails
(a flaky runner, say), re-run the failed jobs. Image tags move and the
GitHub Release appears only in the last job, once everything else is out.

After the first release, check that both packages on GHCR are public
(package settings, "Change visibility"). Docker and the friends' installs
pull them without logging in.

Semantic versioning, 0.x for now: a minor bump can change the configuration
or the database schema; a patch release doesn't. The database migrates when
it opens, and an older binary refuses a newer database, so take a backup
([backup.md](backup.md)) before moving to a new minor version.

## Verifying a download

With the GitHub CLI:

```sh
gh attestation verify parallax_X.Y.Z-1_amd64.deb --repo ninbura/Parallax
gh attestation verify oci://ghcr.io/ninbura/parallax:X.Y.Z --repo ninbura/Parallax
```

Without it, `sha256sum -c SHA256SUMS --ignore-missing` next to the download
checks it arrived intact, but not who built it.
