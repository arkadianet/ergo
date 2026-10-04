ARG RUST_VERSION=1.99.0
FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --bin ergo-node --bin ergo-wallet

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 ergo && useradd --uid 10001 --gid ergo --no-create-home ergo \
    && install -d -o ergo -g ergo /var/lib/ergo \
    && install -d -o root -g root -m 0755 /etc/ergo
COPY --from=build /src/target/release/ergo-node /src/target/release/ergo-wallet /usr/local/bin/
COPY deploy/ergo-node.container.toml /etc/ergo/node.toml
RUN chmod 0444 /etc/ergo/node.toml
USER 10001:10001
WORKDIR /var/lib/ergo
VOLUME ["/var/lib/ergo"]
EXPOSE 9030 9099
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=300s --retries=4 \
    CMD curl --fail --silent --show-error http://127.0.0.1:9099/api/v1/node/liveness || exit 1
ENTRYPOINT ["ergo-node"]
CMD ["--config", "/etc/ergo/node.toml", "--data-dir", "/var/lib/ergo"]
