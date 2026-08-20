FROM rust:1.85-slim AS builder
RUN apt-get update && apt-get install -y libclang-dev libpcap-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/netrecon /usr/bin/
COPY --from=builder /build/target/release/shadowscan /usr/bin/
COPY --from=builder /build/target/release/hashsleuth /usr/bin/
COPY --from=builder /build/target/release/packeteye /usr/bin/
ENTRYPOINT ["/usr/bin/netrecon"]
