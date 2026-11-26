#!/bin/sh
# Debian and Ubuntu: what pacman's systemd hooks do on Arch.
set -e
[ "$1" = configure ] || exit 0

systemd-sysusers parallax.conf
systemd-tmpfiles --create parallax.conf
# Forwarding and the module now, not only from the next boot. Both fail in a
# container, which is fine: the host decides there.
/usr/lib/systemd/systemd-sysctl 90-parallax.conf || echo "parallax: could not set net.ipv4.ip_forward now; it is set at boot" >&2
modprobe wireguard 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    # An upgrade ($2 is the old version): a running service gets the new binary.
    # A first install leaves it stopped and disabled; it needs a configuration.
    if [ -n "$2" ]; then
        systemctl try-restart parallax.service
    else
        echo "parallax: put your configuration in /etc/parallax/parallax.toml, then: sudo systemctl enable --now parallax (docs/native.md)"
    fi
fi
