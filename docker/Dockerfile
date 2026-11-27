# syntax=docker/dockerfile:1
# Parallax gateway image: the engine binary plus everything that touches packets.
# Runs host-networked with NET_ADMIN (see compose.yml).
#
# The default target builds the binary from source. `--target release` takes
# the static binaries CI built and tested instead, from dist/parallax-<arch>/
# (.github/workflows/release.yml, docs/releasing.md).

# Keep in sync with rust-toolchain.toml.
FROM rust:1.100.0-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p parallax-cli && strip target/release/parallax

FROM alpine:3.21 AS runtime
# wireguard-tools: wg/wg-quick; nftables: nft; iptables+ipset: fallback backend;
# iproute2: ip; tailscale: subnet-router node (M2 drives it). DNS is built in.
RUN apk add --no-cache \
        wireguard-tools nftables iptables ipset iproute2 tailscale \
        bind-tools curl ca-certificates tini
COPY docker/entrypoint.sh /usr/local/bin/parallax-entrypoint
COPY LICENSE-MIT LICENSE-APACHE /usr/share/licenses/parallax/
RUN chmod +x /usr/local/bin/parallax-entrypoint \
    && mkdir -p /etc/parallax /var/lib/parallax /var/lib/tailscale
# PARALLAX_CONFIG is imported into the database (PARALLAX_DB) on the first start.
ENV PARALLAX_CONFIG=/etc/parallax/parallax.toml \
    PARALLAX_DB=/var/lib/parallax/parallax.db \
    PARALLAX_OUT=/var/lib/parallax
VOLUME ["/etc/parallax", "/var/lib/parallax", "/var/lib/tailscale"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/parallax-entrypoint"]
CMD ["run"]
LABEL org.opencontainers.image.source=https://github.com/ninbura/Parallax \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

FROM runtime AS release
ARG TARGETARCH
COPY --chmod=0755 dist/parallax-${TARGETARCH}/parallax /usr/local/bin/parallax
COPY dist/parallax-${TARGETARCH}/THIRD-PARTY-LICENSES /usr/share/licenses/parallax/

FROM runtime AS local
COPY --from=build /src/target/release/parallax /usr/local/bin/parallax
