# Multi-stage: собираем бинарь герметично, гоняем в тонком runtime. Контекст сборки — КОРЕНЬ
# воркспейса (пример path-зависит от reflex → core/engine/…), как у соседних стендов `lab/`.
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# ОДИН бинарь на ОБА края: `CARRIER=ct|local` внутри него выбирает носителя (докблок
# `edges_main.rs`) — различие движков живёт в аргументе процесса, не в двух разных сборках.
RUN cargo build --release -p detect-silent-drop --bin detect-silent-drop-edges

FROM debian:bookworm-slim
# nftables — поставить очередь; curl — погнать боевой трафик; ca-certificates — TLS.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/detect-silent-drop-edges /usr/local/bin/detect-silent-drop-edges
COPY examples/detect-silent-drop/lab/edges/run.sh /usr/local/bin/run.sh
COPY examples/detect-silent-drop/lab/edges/compare.sh /usr/local/bin/compare.sh
RUN chmod +x /usr/local/bin/run.sh /usr/local/bin/compare.sh
CMD ["/usr/local/bin/run.sh"]
