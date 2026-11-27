# syntax=docker/dockerfile:1
# Headscale built from a pinned commit of its main branch. `tailscale cert`
# and HTTPS `tailscale serve` (juanfont/headscale#3554) aren't in a release
# yet: v0.29.8 is on a release branch without them. Move to the release
# image once one has them (ADR 0014). Parallax's Headscale client is
# written against this commit's API; bump them together.

# The build runs on the builder's own platform and cross-compiles, so a
# multi-arch build (release.yml) doesn't compile Go under emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24 AS build
ARG TARGETOS TARGETARCH
# A commit on main after #3554 (2026-11-25, "CHANGELOG: describe the
# configuration overhaul").
ARG HEADSCALE_COMMIT=d9bf885c4911bfd079842ba70165b809e7c52c6d
RUN apk add --no-cache git
WORKDIR /src
# The full commit id names exactly this source.
RUN git init -q \
    && git remote add origin https://github.com/juanfont/headscale.git \
    && git fetch -q --depth 1 origin "$HEADSCALE_COMMIT" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$HEADSCALE_COMMIT"
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath -ldflags "-s -w" -o /headscale ./cmd/headscale
# Headscale's license and those of every module linked into it (Tailscale's
# among them), which ask that copies of the binary carry them. Fails if a
# module has none, so a new dependency can't slip through without one.
RUN go list -deps -f '{{with .Module}}{{.Path}} {{.Dir}}{{end}}' ./cmd/headscale > /modules \
    && sort -u /modules | while read -r path dir; do \
        mkdir -p "/licenses/$path"; \
        n=$(find "$dir" -maxdepth 1 -type f ! -name '*.go' \( -iname 'licen[cs]e*' \
            -o -iname 'copying*' -o -iname 'notice*' -o -iname 'patents*' \) \
            -exec cp {} "/licenses/$path/" \; -print | wc -l); \
        [ "$n" -gt 0 ] || { echo "no license file in $path ($dir)" >&2; exit 1; }; \
    done \
    && mkdir -p /licenses/go && cp "$(go env GOROOT)/LICENSE" /licenses/go/

FROM alpine:3.24
# ca-certificates: ACME for `tailscale cert` (DNS-01 through the DNS
# provider's API) and the DERP map from Tailscale's servers.
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/headscale /var/run/headscale
COPY --from=build /headscale /usr/local/bin/headscale
COPY --from=build /licenses /usr/share/licenses/headscale
LABEL org.opencontainers.image.source=https://github.com/ninbura/Parallax \
      org.opencontainers.image.licenses=BSD-3-Clause
VOLUME ["/var/lib/headscale"]
ENTRYPOINT ["/usr/local/bin/headscale"]
CMD ["serve"]
