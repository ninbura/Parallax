# Arch: the body of post_install(). pacman's systemd hooks do the rest: the
# user, /etc/parallax, the sysctl, the module and the daemon reload.
echo "parallax: put your configuration in /etc/parallax/parallax.toml, then: sudo systemctl enable --now parallax (docs/native.md)"
