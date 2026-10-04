# Deployment packages

Release archives contain configuration examples, operator runbooks and the
`deploy/` directory. The release matrix builds native Linux glibc ARM64 and
Apple Silicon binaries alongside the existing x86-64 platforms. Every platform
runs the existing extracted-binary smoke checks before publication. ARM64
Linux uses GitHub's `ubuntu-24.04-arm` runner; Apple Silicon uses `macos-latest`.

## Linux systemd

Install the release's `ergo-node` binary as `/usr/local/bin/ergo-node`, then:

```sh
sudo install -d -m 0755 /etc/ergo-node
sudo install -m 0644 config/ergo-node.toml /etc/ergo-node/node.toml
sudo install -m 0644 deploy/ergo-node.service /etc/systemd/system/ergo-node.service
sudo systemctl daemon-reload
sudo systemctl enable --now ergo-node
sudo journalctl -u ergo-node -f
```

The service uses a dynamic unprivileged user and a persistent private
`/var/lib/ergo-node` state directory. It allows five minutes for graceful
shutdown. Configure networking, API authentication and database cache budgets
in `/etc/ergo-node/node.toml` before starting production service. The shipped
ordinary configuration keeps the API on loopback. Paths for logs and derived
data must stay under the service's writable state directory.

## OCI image and Compose

The root Dockerfile builds from the pinned Rust version and installs node and
wallet binaries into an unprivileged Debian runtime. From a source checkout:

```sh
docker build -t ergo-node:local .
docker compose -f deploy/compose.yml up -d --build
docker compose -f deploy/compose.yml logs -f node
```

Compose keeps data in the `ergo-data` named volume, mounts
`deploy/ergo-node.container.toml` read-only, publishes P2P port 9030, and binds
HTTP port 9099 to **host loopback**. Its container API bind is `0.0.0.0` so host
port forwarding works; requests from other containers on the same network can
reach public HTTP routes. Configure authentication and network isolation for
the intended deployment. No master key or named credential is embedded in the
image. The default credential-free configuration closes privileged routes.

The container health check uses **liveness**, allowing initial synchronization
to proceed. Load balancers should call `/api/v1/node/readiness`. An overridden
configuration which disables or moves HTTP must override the health check too.
Compose requests a five-minute graceful stop and runs with dropped capabilities,
a read-only root filesystem and a small writable temporary directory.

On ARM64 Linux, Docker builds natively for ARM64. To create a multi-platform
image with a configured Buildx builder:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t YOUR_REGISTRY/ergo-node:YOUR_TAG --push .
```

Publishing images is an operator action; the repository does not automatically
push this image. Source builds under emulation may take substantially longer
than native builds. A bind-mounted data directory must be writable by container
UID/GID 10001; named volumes initialize ownership from the image automatically.
Keep application data outside the build context. The `.dockerignore` excludes
common data/secret artifacts, but a custom secret configuration file should
only be mounted at runtime.
