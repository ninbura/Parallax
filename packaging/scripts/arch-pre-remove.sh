# Arch: the body of pre_remove() (removal only, not upgrades). Take the
# gateway down (wg0, its nftables table) while the binary is still there.
if [ -d /run/systemd/system ]; then
    systemctl disable --now parallax.service || true
fi
