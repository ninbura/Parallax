# syntax=docker/dockerfile:1
# Headscale built from a pinned commit of its main branch. `tailscale cert`
# and HTTPS `tailscale serve` (juanfont/headscale#3554) aren't in a release
# yet: v0.29.8 is on a release branch without them. Move to the release
# image once one has them (ADR 0014). Parallax's Headscale client is
# written against this commit's API; bump them together.

FROM golang:1.27.4-alpine3.24 AS build
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
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /headscale ./cmd/headscale

FROM alpine:3.24
# ca-certificates: ACME for `tailscale cert` (DNS-01 through the DNS
# provider's API) and the DERP map from Tailscale's servers.
RUN apk add --no-cache ca-certificates \
    && mkdir -p /var/lib/headscale /var/run/headscale
COPY --from=build /headscale /usr/local/bin/headscale
VOLUME ["/var/lib/headscale"]
ENTRYPOINT ["/usr/local/bin/headscale"]
CMD ["serve"]
