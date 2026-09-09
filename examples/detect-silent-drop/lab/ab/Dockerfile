FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p detect-silent-drop --bin detect-silent-drop --bin detect-silent-drop-edge

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/detect-silent-drop /usr/local/bin/detect-silent-drop
COPY --from=builder /src/target/release/detect-silent-drop-edge /usr/local/bin/detect-silent-drop-edge
COPY examples/detect-silent-drop/lab/ab/run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
