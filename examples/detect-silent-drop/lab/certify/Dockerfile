# Девятый закон на ЖИВОМ ядре: собираем certify нормальный И мутантный (apply→None), чтобы
# показать, что закон краснеет ровно на дыре, оставленной сознательно на Task 4.
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
# Нормальный certify.
RUN cargo build --release -p reflex-linux --features certify --example certify \
 && cp target/release/examples/certify /certify-normal
# Мутант: apply не доносит состояние (verdict ..., None). Закон обязан дать StateLost.
RUN sed -i 's/        Answer::Remembered { accept, state } => (accept, Some(state)),/        Answer::Remembered { accept, state } => { let _ = state; (accept, None) }/' linux/src/queue/terminal.rs \
 && cargo build --release -p reflex-linux --features certify --example certify \
 && cp target/release/examples/certify /certify-mutated

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nftables iproute2 curl ca-certificates procps kmod \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /certify-normal /usr/local/bin/certify-normal
COPY --from=builder /certify-mutated /usr/local/bin/certify-mutated
COPY examples/detect-silent-drop/lab/certify/run.sh /usr/local/bin/run.sh
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]
