# УСТРОЙСТВО ДЛЯ СЕРТИФИКАЦИИ КАЛИТКИ.
#
# ОДИН ОБРАЗ НА ОБЕ РОЛИ — подопытного и свидетеля. Второй образ означал бы вторую сборку и вторую
# правду о том, какой код проверяется; роль задаётся командой, а не сборкой.
#
# ОБРАЗ МИНИМАЛЕН НАМЕРЕННО, и это не гигиена, а ОТРИЦАТЕЛЬНОЕ СВИДЕТЕЛЬСТВО: если здесь нет ни
# `nft`, ни `iproute2`, ни загрузчика eBPF, а закон инъекции держится, — тем самым установлено, что
# `AfPacketBackend` не опирается на них тайком. Проверить это на машине разработчика невозможно:
# там есть всё.
#
# ЦЕНА НАЗВАНА: контейнер делит ядро с хозяином, и модуль, загруженный снаружи, виден изнутри.
# Минимальность образа доказывает отсутствие ИНСТРУМЕНТОВ, но не отсутствие возможностей ядра;
# отрицательный preflight — следующий срез.

FROM rust:1-slim-trixie AS build
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY core/ ./core/
COPY runtime/ ./runtime/
COPY linux/ ./linux/
COPY linux-common/ ./linux-common/
COPY os/ ./os/
COPY Cargo.toml Cargo.lock ./

# СБОРКА БЕЗ ЛИШНИХ ФИЧ. `certify` тянет только чтение записи; ни `tc`, ни `nfqueue` здесь нет —
# подопытный обязан обойтись тем, что заявил.
RUN cargo build --release -p reflex-linux --features certify --example certify

FROM debian:stable-slim
ENV DEBIAN_FRONTEND=noninteractive

# `noninteractive` обязателен: tshark спрашивает про захват без root и вешает сборку.
#
# СВИДЕТЕЛЬ — ЧУЖОЙ КОД. `tshark` поверх libpcap: другая реализация, другой автор. «Мы отправили»
# перестаёт доказываться тем же кодом, что отправлял.
RUN apt-get update && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

# СНИФФЕР ПЕРЕЕЗЖАЕТ С СИСТЕМНОГО ПУТИ. AppArmor цепляет профиль ПО ПУТИ бинаря, а ядро с его
# политиками у контейнера общее с хозяином: профиль хозяина для `/usr/bin/dumpcap` молча накрывает
# одноимённый файл ВНУТРИ контейнера. Оплачено в лабе (`lab/probe/Dockerfile`).
RUN cp /usr/bin/dumpcap /usr/local/bin/certify-snif

COPY --from=build /src/target/release/examples/certify /usr/local/bin/certify

CMD ["sleep", "infinity"]
