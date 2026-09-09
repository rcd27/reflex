# Multi-stage: собираем бинарь герметично, гоняем в тонком runtime.
# Контекст сборки — КОРЕНЬ воркспейса: пример path-зависит от reflex → core/engine/…
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# Только целевой пакет и его граф (не весь воркспейс). crates.io доступен напрямую.
RUN cargo build --release -p detect-silent-drop

FROM debian:bookworm-slim
# nftables — поставить очередь; curl — погнать боевой трафик; ca-certificates — TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/detect-silent-drop /usr/local/bin/detect-silent-drop
COPY examples/detect-silent-drop/lab/engine/run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
