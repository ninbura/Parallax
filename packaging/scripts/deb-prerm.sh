#!/bin/sh
# Removing, not upgrading: take the gateway down (wg0, its nftables table)
# while the binary is still there. A failed stop warns rather than blocking
# the removal.
set -e
[ "$1" = remove ] && [ -d /run/systemd/system ] || exit 0
systemctl disable parallax.service >/dev/null 2>&1 || true
deb-systemd-invoke stop parallax.service ||
    echo "parallax: warning: stopping the service failed; check for wg0 and 'nft list table inet parallax'" >&2
