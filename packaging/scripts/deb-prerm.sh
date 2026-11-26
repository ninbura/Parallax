#!/bin/sh
# Removing, not upgrading: take the gateway down (wg0, its nftables table)
# while the binary is still there.
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl disable --now parallax.service || true
fi
