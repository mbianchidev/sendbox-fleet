# Multi-stage build for the sendbox-fleet server.
# Base images are pinned by digest; update tag and digest together.

FROM rust:1.100.0-slim-trixie@sha256:e9d95b74296f7126a83ae3d041aeaba1ff4c478f13abc5cc034fcf7c131c3d4a AS build
WORKDIR /src
# rust-toolchain.toml is intentionally not copied: the image already provides
# the pinned toolchain and the build does not need clippy or rustfmt.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --locked --release --bin sendbox-fleet \
    && install -D -m 0755 target/release/sendbox-fleet /out/sendbox-fleet

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime
# CA certificates verify identity-provider discovery and JWKS over HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 fleet \
    && useradd --system --uid 10001 --gid fleet --no-create-home \
        --home-dir /var/lib/sendbox-fleet --shell /usr/sbin/nologin fleet \
    && install -d -o fleet -g fleet -m 0700 /var/lib/sendbox-fleet /var/log/sendbox-fleet \
        /var/lib/sendbox-fleet/anchors
COPY --from=build /out/sendbox-fleet /usr/local/bin/sendbox-fleet
USER 10001:10001
WORKDIR /var/lib/sendbox-fleet
ENV FLEET_BIND=0.0.0.0:8080 \
    FLEET_LOG_DIR=/var/log/sendbox-fleet
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sendbox-fleet"]
