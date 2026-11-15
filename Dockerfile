# Multi-stage build for the sendbox-fleet server.
# Base images are pinned by digest; update tag and digest together.

FROM rust:1.93.1-slim-trixie@sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956 AS build
WORKDIR /src
# rust-toolchain.toml is intentionally not copied: the image already provides
# the pinned toolchain and the build does not need clippy or rustfmt.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release --bin sendbox-fleet \
    && install -D -m 0755 target/release/sendbox-fleet /out/sendbox-fleet

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime
RUN groupadd --system --gid 10001 fleet \
    && useradd --system --uid 10001 --gid fleet --no-create-home \
        --home-dir /var/lib/sendbox-fleet --shell /usr/sbin/nologin fleet \
    && install -d -o fleet -g fleet -m 0700 /var/lib/sendbox-fleet /var/log/sendbox-fleet
COPY --from=build /out/sendbox-fleet /usr/local/bin/sendbox-fleet
USER 10001:10001
WORKDIR /var/lib/sendbox-fleet
ENV FLEET_BIND=0.0.0.0:8080 \
    FLEET_LOG_DIR=/var/log/sendbox-fleet
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sendbox-fleet"]
