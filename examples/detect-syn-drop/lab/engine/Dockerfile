FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p detect-syn-drop

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/detect-syn-drop /usr/local/bin/detect-syn-drop
COPY examples/detect-syn-drop/lab/engine/run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
