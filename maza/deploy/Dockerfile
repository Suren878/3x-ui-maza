FROM rust:1.99.1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY tests ./tests
COPY examples ./examples
RUN cargo test --locked
RUN cargo build --locked --release --bins
RUN cargo build --locked --release --example probe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/maza-server /usr/local/bin/maza-server
COPY --from=builder /src/target/release/maza-client /usr/local/bin/maza-client
COPY --from=builder /src/target/release/maza-keygen /usr/local/bin/maza-keygen
COPY --from=builder /src/target/release/examples/probe /usr/local/bin/maza-probe
USER 10002:10002
ENTRYPOINT ["maza-server"]
CMD ["--config", "/config/server.toml", "--watch"]
