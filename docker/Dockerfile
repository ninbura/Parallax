# syntax=docker/dockerfile:1
# Parallax gateway image: the engine binary plus everything that touches packets.
# Runs host-networked with NET_ADMIN (see docker-compose.yml).

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p parallax-cli && strip target/release/parallax

FROM alpine:3.21
# wireguard-tools: wg/wg-quick; nftables: nft; iptables+ipset: fallback backend;
# dnsmasq: the DNS shim; iproute2: ip; tailscale: subnet-router node (M2 drives it).
RUN apk add --no-cache \
        wireguard-tools nftables iptables ipset dnsmasq iproute2 tailscale \
        bind-tools curl ca-certificates tini
COPY --from=build /src/target/release/parallax /usr/local/bin/parallax
COPY docker/entrypoint.sh /usr/local/bin/parallax-entrypoint
RUN chmod +x /usr/local/bin/parallax-entrypoint \
    && mkdir -p /etc/parallax /var/lib/parallax /var/lib/tailscale
ENV PARALLAX_CONFIG=/etc/parallax/parallax.toml \
    PARALLAX_OUT=/var/lib/parallax
VOLUME ["/etc/parallax", "/var/lib/parallax", "/var/lib/tailscale"]
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/parallax-entrypoint"]
CMD ["run"]
