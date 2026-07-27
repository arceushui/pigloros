FROM rust:1-slim-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml rustfmt.toml ./
COPY crates/ crates/
COPY plugins/ plugins/
COPY apps/ apps/

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo build --release --bin piglor-gateway

FROM debian:bookworm-slim AS runtime

RUN adduser --disabled-password --gecos "" appuser

COPY --from=builder /src/target/release/piglor-gateway /usr/local/bin/piglor-gateway

COPY seed/ /ledger/
ENV LEDGER_SOURCE=/ledger
ENV LEDGER_WRITE=0

USER appuser
EXPOSE 8080
ENTRYPOINT ["piglor-gateway", "serve", "0.0.0.0:8080"]
