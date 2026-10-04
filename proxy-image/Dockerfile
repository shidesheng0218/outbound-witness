FROM rust:1.97-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/core crates/core
COPY crates/cli crates/cli
COPY crates/proxy crates/proxy
RUN cargo build --release -p outbound-witness-proxy

FROM debian:bookworm-slim
COPY --from=build /src/target/release/outbound-witness-proxy /usr/local/bin/outbound-witness-proxy
EXPOSE 3128 8080
ENTRYPOINT ["/usr/local/bin/outbound-witness-proxy"]
