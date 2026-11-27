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

Both images get the tag `X.Y.Z`, and `X.Y` and `latest` when no newer
release already has them, so a patch for an older line doesn't move
`latest` back. The two images always share a version, because Parallax's
Headscale client is written against the pinned Headscale commit. Only final
releases are published: there are no pre-releases (nfpm drops a
pre-release's suffix from the Arch package's version).

The binaries, the packages and both images have a GitHub build provenance
attestation, which records the repository, workflow and commit that built
them. `SHA256SUMS` itself isn't attested; it lists the attested files.

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
(a flaky runner, say), re-run **the failed jobs**, not all jobs. Image tags
move and the GitHub Release is published only in the last job, once
everything else is out; until its files are all uploaded it's a draft. That
job refuses to run if the release is already published, or if `X.Y.Z`
already points at other images than the ones this run built (what "re-run
all jobs" after a half-finished release would do). Releases run one at a
time.

## Once per repository

- **Protect release tags.** The checks above run from the tagged commit's
  own workflow, so a tag on a commit without them would skip them. A tag
  ruleset (Settings → Rules → Rulesets, target tags `v*`) restricting
  creation, update and deletion to maintainers closes that.
- **Make the images public.** After the first release, check that both
  packages on GHCR are public (package settings, "Change visibility"), so
  Docker and the friends' installs pull them without logging in.

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
