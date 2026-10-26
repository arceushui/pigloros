FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS builder

WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml rustfmt.toml ./
COPY crates/ crates/
COPY plugins/ plugins/
COPY apps/ apps/
COPY fixtures/ fixtures/

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --locked --release --bin piglor-gateway

FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

RUN <<EOF
  set -eu
  apt-get update -qq
  apt-get install -y --no-install-recommends curl
  apt-get clean
  rm -rf /var/lib/apt/lists/*
  adduser --disabled-password --gecos "" appuser
EOF

COPY --from=builder /src/target/release/piglor-gateway /usr/local/bin/piglor-gateway
# The third-party notice bundle (#798): the `third-party-notices` artifact of
# the reusable workflow, downloaded into the build context by deploy.yml and the
# ci docker-build job. A build without it fails at this COPY, so no image ships
# without its notices. COPY --chmod would also apply to the directories it
# creates and make them untraversable for appuser, so the modes are set after.
COPY third-party-notices/THIRD-PARTY-NOTICES.txt \
    third-party-notices/third-party-notices.json \
    /usr/share/doc/piglor-gateway/third-party/
RUN chmod 0755 /usr/share/doc/piglor-gateway /usr/share/doc/piglor-gateway/third-party \
    && chmod 0644 /usr/share/doc/piglor-gateway/third-party/*

# The image intentionally ships without curated ledger content. Supply a
# read-only source at runtime when a deployment needs one.
ENV LEDGER_WRITE=0

USER appuser
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1
ENTRYPOINT ["piglor-gateway", "serve", "0.0.0.0:8080"]
