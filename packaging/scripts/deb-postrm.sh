#!/bin/sh
# Even on purge, /etc/parallax (the server key) and /var/lib/parallax (the
# database, backups) stay: losing them means new keys for every peer.
# docs/native.md says how to remove them by hand.
set -e
if [ -d /run/systemd/system ] && ! systemd-detect-virt -q --chroot; then
    systemctl daemon-reload || true
fi
