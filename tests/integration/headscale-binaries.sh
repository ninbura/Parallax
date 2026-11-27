#!/usr/bin/env bash
# Build the Headscale that docker/headscale.Dockerfile pins, and a Tailscale
# client, into <dir> for netns.sh's (t). Prints HEADSCALE=, TAILSCALED= and
# TAILSCALE= lines (the only output on stdout). Needs go and git.
set -euo pipefail

DIR=${1:?usage: headscale-binaries.sh <dir>}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# The client the test joins with. Headscale needs v1.84.0 or newer.
TAILSCALE_VERSION=v1.104.7
COMMIT=$(sed -n 's/^ARG HEADSCALE_COMMIT=\([0-9a-f]\{40\}\)$/\1/p' "$ROOT/docker/headscale.Dockerfile")
[ -n "$COMMIT" ] || { echo "no HEADSCALE_COMMIT in docker/headscale.Dockerfile" >&2; exit 2; }

mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT
git -C "$SRC" init -q
git -C "$SRC" remote add origin https://github.com/juanfont/headscale.git
git -C "$SRC" fetch -q --depth 1 origin "$COMMIT"
git -C "$SRC" checkout -q FETCH_HEAD
[ "$(git -C "$SRC" rev-parse HEAD)" = "$COMMIT" ]
(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -o "$DIR/headscale" ./cmd/headscale)
GOBIN="$DIR" CGO_ENABLED=0 go install "tailscale.com/cmd/tailscale@$TAILSCALE_VERSION" \
    "tailscale.com/cmd/tailscaled@$TAILSCALE_VERSION"
printf '%s\n' "HEADSCALE=$DIR/headscale" "TAILSCALED=$DIR/tailscaled" "TAILSCALE=$DIR/tailscale"
