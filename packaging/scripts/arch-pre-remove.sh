# Arch: the body of pre_remove() (removal only, not upgrades). Take the
# gateway down (wg0, its nftables table) while the binary is still there.
# A failed stop warns rather than blocking the removal.
if [ -d /run/systemd/system ] && ! systemd-detect-virt -q --chroot; then
    systemctl disable parallax.service >/dev/null 2>&1 || true
    systemctl stop parallax.service ||
        echo "parallax: warning: stopping the service failed; check for wg0 and 'nft list table inet parallax'" >&2
fi
