#!/bin/sh
# Debian and Ubuntu: what pacman's systemd hooks do on Arch.
set -e
[ "$1" = configure ] || exit 0

systemd-sysusers parallax.conf
systemd-tmpfiles --create parallax.conf

# Only on a running system, not in a chroot or an image build.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload
# ip_forward and the module now, not only from the next boot. Through the
# boot-time services, so every sysctl.d file applies in order and a local
# override still wins.
systemctl restart systemd-sysctl.service systemd-modules-load.service ||
    echo "parallax: warning: could not apply sysctl.d or modules-load.d now; they apply at boot" >&2

if [ -n "$2" ]; then
    # An upgrade ($2 is the old version): a running service gets the new
    # binary. deb-systemd-invoke honours a local policy-rc.d.
    deb-systemd-invoke try-restart parallax.service ||
        echo "parallax: warning: restarting the service failed; see journalctl -u parallax" >&2
else
    # A first install leaves it stopped and disabled; it needs a configuration.
    echo "parallax: put your configuration in /etc/parallax/parallax.toml, then: sudo systemctl enable --now parallax (docs/native.md)"
fi
