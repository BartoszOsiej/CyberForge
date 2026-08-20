# ── Stage 1: Build ──
FROM rust:1.80-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --workspace

# ── Stage 2: Runtime ──
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/netrecon /usr/local/bin/
COPY --from=builder /src/target/release/packeteye /usr/local/bin/
COPY --from=builder /src/target/release/shadowscan /usr/local/bin/
COPY --from=builder /src/target/release/hashsleuth /usr/local/bin/
RUN chmod +x /usr/local/bin/netrecon /usr/local/bin/packeteye \
    /usr/local/bin/shadowscan /usr/local/bin/hashsleuth
RUN useradd -m sec
USER sec
ENTRYPOINT ["netrecon"]
