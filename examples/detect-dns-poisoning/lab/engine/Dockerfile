FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p detect-dns-poisoning

FROM debian:bookworm-slim
# dnsutils — dig для боевого DNS-запроса; nftables — очередь.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/detect-dns-poisoning /usr/local/bin/detect-dns-poisoning
COPY examples/detect-dns-poisoning/lab/engine/run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
