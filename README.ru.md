# ssh3-c

[English](README.md) | **Русский** | [Deutsch](README.de.md)

## Документация

Все документы проекта трёхязычны (баннер `> Languages:` в каждом файле
ссылается на версии). Канонический текст документов `docs/` — русский;
EN/DE — точные переводы.

| № | Документ | Содержимое | Языки |
|---|----------|------------|-------|
| 1 | [docs/PLAN.md](docs/PLAN.md) | план разработки: фазы P0–P9, история приёмок волн, открытый бэклог | RU · [EN](docs/PLAN.en.md) · [DE](docs/PLAN.de.md) |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | слоистая архитектура: core/event/quic/h3/ssh3/app, конвенции zero-copy | RU · [EN](docs/ARCHITECTURE.en.md) · [DE](docs/ARCHITECTURE.de.md) |
| 3 | [docs/SPEC-wire.md](docs/SPEC-wire.md) | спецификация wire-протокола SSH3 (rev nagual2/1, draft 1) | RU · [EN](docs/SPEC-wire.en.md) · [DE](docs/SPEC-wire.de.md) |
| 4 | [docs/P4-WIRE.md](docs/P4-WIRE.md) | исторический дистиллят: жизненный цикл каналов и датаграммный роутинг (волна 2) | RU · [EN](docs/P4-WIRE.en.md) · [DE](docs/P4-WIRE.de.md) |
| 5 | [docs/PORTING-nginx-quic.md](docs/PORTING-nginx-quic.md) | журнал порта: QUIC-слой nginx → ssh3-c | RU · [EN](docs/PORTING-nginx-quic.en.md) · [DE](docs/PORTING-nginx-quic.de.md) |
| 6 | [docs/DEPS-QUIC.md](docs/DEPS-QUIC.md) | зависимости и лицензии QUIC-стека (OpenSSL ≥3.5 QUIC API) | RU · [EN](docs/DEPS-QUIC.en.md) · [DE](docs/DEPS-QUIC.de.md) |
| 7 | [docs/BENCH-METRICS.md](docs/BENCH-METRICS.md) | методика и метрики бенчмарков (R3) | RU · [EN](docs/BENCH-METRICS.en.md) · [DE](docs/BENCH-METRICS.de.md) |
| 8 | [docs/BENCH-P7-2026-10-06.md](docs/BENCH-P7-2026-10-06.md) | отчёт бенчей фазы P7 | RU · [EN](docs/BENCH-P7-2026-10-06.en.md) · [DE](docs/BENCH-P7-2026-10-06.de.md) |
| 9 | [docs/BENCH-V0.2.0-2026-10-13.md](docs/BENCH-V0.2.0-2026-10-13.md) | отчёт бенчей релиза v0.2.0 | RU · [EN](docs/BENCH-V0.2.0-2026-10-13.en.md) · [DE](docs/BENCH-V0.2.0-2026-10-13.de.md) |
| 10 | [docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md) | отчёт бенчей релиза v0.3.0 | RU · [EN](docs/BENCH-V0.3.0-2026-10-15.en.md) · [DE](docs/BENCH-V0.3.0-2026-10-15.de.md) |
| 11 | [packaging/README.md](packaging/README.md) | сборка дистрибутивных пакетов (deb/rpm/apk/OpenWrt, бандл OpenSSL) | EN · [RU](packaging/README.ru.md) · [DE](packaging/README.de.md) |
| 12 | [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) | сторонние копирайты и лицензии (юридический текст, без перевода) | EN |
| 13 | [docs/PORTING-illumos.md](docs/PORTING-illumos.md) | оценка порта под illumos: факты платформы, конвейер архивации трафика, распределённый ZFS (замороженный пункт F6b) | RU |
| 14 | [docs/PLAN-CURRENT.md](docs/PLAN-CURRENT.md) | операционный срез плана: от последнего сделанного к первому не сделанному (волны A/B, остатки по дистрибутивам, замороженные пункты) | RU |
| 15 | [docs/COEXISTENCE.md](docs/COEXISTENCE.md) | контрольная матрица совместной установки пакетов (OpenSSH, go-форк, два deb-канала) + приёмочная процедура | RU · [EN](docs/COEXISTENCE.en.md) · [DE](docs/COEXISTENCE.de.md) |

Реализация SSH3 на чистом C17 в стиле nginx: пулы памяти, буферы-вьюхи,
chain-интерфейс всего I/O, zero-copy data path. Целевая позиция — «OpenSSH
среди Linux-систем» (см. [docs/PLAN.md](docs/PLAN.md)).

Текущий статус: фазы **P0–P1** готовы (core + event/UDP-слой, GSO-бенч);
идёт подготовка **P2** — адаптация QUIC-слоя nginx (см. [docs/PLAN.md](docs/PLAN.md)).

## Совместимость запуска (drop-in)

ssh3-c — drop-in замена ssh3-go (форк в стиле OpenSSH) и сосед OpenSSH (ssh2):
бинарники носят одинаковые имена (`ssh3`, `ssh3-server`), ключи запуска совпадают там,
где функционал совпадает; пакеты объявляют `Provides`/`Conflicts`/`Replaces` против
ssh3-go, так что один пакет заменяет другой (например, при закрытии уязвимости)
без перенастройки сторонних программ, работающих через ssh3. Полная матрица
совместной установки и её приёмочная процедура —
[docs/COEXISTENCE.md](docs/COEXISTENCE.md).

## Структура

| № | Каталог | Содержимое |
|---|---------|------------|
| 1 | `src/core/` | пул памяти (`s3_palloc`), буферы и цепочки (`s3_buf`), строки (`s3_string`, `s3_str`), rbtree (`s3_rbtree`), интрузивный список (`s3_queue`), лог (`s3_log`), агрегатор `s3_core.h` |
| 2 | `src/event/` | event loop, таймеры, posted events (`s3_event`), соединения (`s3_connection`), UDP-псевдо-коннекции (`s3_event_udp`), epoll-бэкенд (`modules/s3_epoll_module`) |
| 3 | `src/os/unix/` | errno-слой (`s3_errno`), UDP sendmsg-chain (`s3_udp_sendmsg_chain`), UDP recv (`s3_udp_recv`) |
| 4 | `bench/` | `gso_bench` — микробенч UDP GSO (`UDP_SEGMENT`) против plain sendmsg |
| 5 | `tests/` | юнит-тесты (микро-фреймворк `s3_test.h`, без зависимостей) |

## Сборка (из WSL)

```bash
cd /mnt/c/Git/project/ssh3-c
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release --output-on-failure
```

## Sanitizers (ASan + UBSan)

```bash
cmake --preset linux-asan
cmake --build --preset linux-asan
ctest --preset linux-asan --output-on-failure
```

## Установка

Из пакетов дистрибутива (исходники сборки — в `packaging/`: deb/rpm/apk
и OpenWrt ipk):

```bash
sudo apt install ssh3-server
```

Состав пакета:

| № | Файл | Назначение |
|---|------|------------|
| 1 | `/usr/sbin/ssh3-server` | демон |
| 2 | `/etc/ssh3/cert.pem` | TLS-сертификат (PEM) |
| 3 | `/etc/ssh3/key.pem` | приватный ключ (PEM, `0640 root:ssh3`) |
| 4 | `/etc/ssh3/authorized_keys` | ключи для Bearer-JWT-входа (`-K`) |
| 5 | `/usr/share/man/man8/ssh3-server.8` | man-страница |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | systemd-юниты |

Из исходников (install-правила пока нет, бинарник остаётся в build-дереве):

```bash
cd /path/to/ssh3-c
cmake --preset linux-release && cmake --build --preset linux-release
# build/linux-release/ssh3-server
```

## systemd (socket-активация)

Пара юнитов делит привилегию порта и сервис: root-овый
`ssh3-server.socket` биндит UDP/443, а systemd передаёт готовый
datagram-fd в `ssh3-server.service`. С P7.3 сервис работает от root
с **per-session setuid**: после аутентификации каждая сессия с
резолвящимся именем пользователя CONNECT переходит на его идентичность
(`initgroups`, `setgid`, `setuid`, `chdir` в home) перед спавном —
как OpenSSH/sshd; у самого демона минимальный bounding set
(`CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID`) и нет
`CAP_NET_BIND_SERVICE` (демон берёт переданный fd и сам `bind()` не
вызывает):

```ini
# ssh3-server.socket (фрагмент)
[Socket]
ListenDatagram=0.0.0.0:443
FreeBind=yes

# ssh3-server.service (фрагмент)
[Service]
ExecStart=/usr/sbin/ssh3-server -c /etc/ssh3/cert.pem -k /etc/ssh3/key.pem
User=root
NoNewPrivileges=no
RestrictSUIDSGID=no
ProtectSystem=strict
ProtectHome=no
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SETGID CAP_SETUID
PrivateTmp=yes
```

Пользователь без записи в passwd получает 401 ещё на CONNECT; CONNECT
без имени пользователя оставляет сессии идентичность демона.
Одно-идентичная непривилегированная схема (`User=ssh3`,
`--run-as-user off`, харденинг P7.2) описана в комментариях юнита и
`man/ssh3-server.8` (`PRIVILEGE MODEL`).

```bash
sudo systemctl enable --now ssh3-server.socket
```

Смена порта — через drop-in, без правки самого юнита:

```bash
sudo systemctl edit ssh3-server.socket
# [Socket]
# ListenDatagram=0.0.0.0:8443
```

## Конфигурация

Флаги CLI (значения по умолчанию — из `ssh3-server -h`):

| Флаг | По умолчанию | Описание |
|------|--------------|----------|
| `-l addr:port` | — | UDP-listen (IPv4), порт `0` — эфемерный; не нужен при socket-активации |
| `-c cert.pem` | — | TLS-сертификат (PEM), обязателен |
| `-k key.pem` | — | приватный ключ (PEM), обязателен |
| `-A alpn` | `h3` | ALPN-имя |
| `-d dg_size` | `1200` | QUIC `max_datagram_frame_size` |
| `-i idle_ms` | `60000` | QUIC idle timeout, мс |
| `-L level` | `info` | уровень лога: `debug\|info\|warn\|error\|all` или числовой |
| `-P pwfile` | — | файл паролей `user:secret` (Basic-аутентификация) |
| `-K authorized_keys` | — | authorized_keys для Bearer-JWT (`%u` — имя пользователя в пути) |
| `-H dir` | home пользователя | sftp-jail каталог |
| `--oidc-issuer url` | — | OIDC-провайдер (id_token) |
| `--oidc-audience id` | — | ожидаемый audience (client id) |
| `--oidc-jwks-ttl sec` | `3600` | время жизни JWKS-набора |
| `--run-as-user on\|off` | `on` при euid 0 | per-session setuid: сессия с резолвящимся пользователем CONNECT переходит на его идентичность перед спавном |
| `-v` / `-V` / `-h` | — | debug-лог / версия / usage |

Переменные окружения:

| Переменная | По умолчанию | Описание |
|------------|--------------|----------|
| `SSH3_LOG_LEVEL` | как `-L` | уровень лога |
| `SSH3_LOG_FILE` | stderr | файл лога (игнорируется под systemd) |
| `SSH3_SHUTDOWN_DRAIN` | `5` сек | дренаж при SIGTERM, `0` — сразу |
| `SSH3C_PROTO=1` | выкл | runner-маркеры `INTEROP-*` в stdout |
| `S3_OIDC_CA_FILE` | системный store | CA для OIDC discovery/JWKS |
| `LISTEN_PID`/`LISTEN_FDS` | — | протокол `sd_listen_fds(3)`, read-only |

Полный справочник: `man 8 ssh3-server`.

## Стиль кода

- `.clang-format` / `.clang-tidy` — в корне; проверка:
  `clang-format --dry-run --Werror src/core/*.c src/core/*.h tests/*.c`.
- Сборка идёт с `-Wall -Wextra -Werror`; пресет `linux-asan` добавляет
  `-fsanitize=address,undefined -fno-sanitize-recover=all`.

## Адрес ответов (wildcard-лисенер)

Лисенер, привязанный к любому локальному адресу (`[::]`, `0.0.0.0` —
по умолчанию), принимает пакеты на все локальные адреса, и локальный
адрес пришедшего пакета серверу неизвестен, пока его не назовут
ancillary data ядра. Сервер просит его (`IP_PKTINFO` /
`IPV6_RECVPKTINFO`) и отвечает **с того адреса, который набрал
клиент**, а не с того, что предпочитает таблица маршрутизации. На
одноадресном хосте разницы нет; на мульти-address хосте (туннель,
второй IP) именно она решает, признает ли клиент свой ответ: QUIC
отбрасывает пакет, пришедший не с того адреса, который клиент набирал
(RFC 9000, 8.1).

Спуфнутому пути не достаётся ничего: до handshake сервер не отвечает
на датаграмму с неизвестного адреса ни байтом — это строже, чем
разрешает RFC 9000, 8.2.1, и оставляет усиление на нуле. После
handshake пир, сменивший адрес (NAT-rebinding), обрабатывается по
RFC 9000, 9.3.3: прежде активный путь проверяется через
PATH_CHALLENGE, а не прошедший проверку путь уступает последнему
валидированному.

## Производительность

Медианы контрольного бенча (методика R3, `bench/p7-compare.sh`): WSL2
loopback, одна ed25519-пара на все три реализации, sha-верификация
передач, 7 раундов на ячейку (первый — прогрев). Полные таблицы и
оговорки окружения —
[docs/BENCH-V0.3.0-2026-10-15.md](docs/BENCH-V0.3.0-2026-10-15.md).

| № | Метрика | ssh3-c | Go-форк 0.1.35 | OpenSSH 9.6 |
|---|---------|--------|----------------|-------------|
| 1 | 512 МиБ sftp push / pull, МБ/с | 353 / 354 | 28 / 33 | **358 / 421** |
| 2 | Handshake, cold connect+auth+exec, мс | **117** (мин 15) | 172 | 221 |
| 3 | ControlMaster warm exec, мс | **7.6** | 9.0 | 13.8 |
| 4 | CPU / пик RSS сервера, push 512 МиБ | **75% / 81 МБ** | 104% / 26 МБ | 104% / 26 МБ |
| 5 | Каталог 4000×4 КиБ push / pull, files/s | **4667 / 4624** | 4103 / 3518 | 1175 / 1284 |

## Лицензия

Собственный код — BSD 2-clause (`LICENSE`). Код, адаптированный из nginx
(BSD 2-clause), перечислен в `THIRD-PARTY-NOTICES.md` — его заголовки
сохраняют `Copyright (C) Nginx, Inc.`.
