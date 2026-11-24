Put your `parallax.toml` in `docker/config/` (start from `example/parallax.toml`).
On the first start the entrypoint imports it into the database
(`/var/lib/parallax/parallax.db`), renames it to `parallax.toml.imported`, and
creates `wg-server.key` next to it. After that, change the configuration with
`docker exec -it parallax parallax config edit`. See `docs/setup.md`.
