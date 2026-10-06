# ssh3-c

Реализация SSH3 на чистом C17 в стиле nginx: пулы памяти, буферы-вьюхи,
chain-интерфейс всего I/O, zero-copy data path. Целевая позиция — «OpenSSH
среди Linux-систем» (см. [docs/PLAN.md](docs/PLAN.md)).

Текущий статус: фазы **P0–P1** готовы (core + event/UDP-слой, GSO-бенч);
идёт подготовка **P2** — адаптация QUIC-слоя nginx (см. [docs/PLAN.md](docs/PLAN.md)).

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

Пара юнитов делит привилегии: root-овый `ssh3-c-server.socket` биндит
UDP/443, а systemd передаёт готовый datagram-fd в `ssh3-c-server.service`,
который работает от непривилегированного пользователя `ssh3` и не
требует `CAP_NET_BIND_SERVICE` (демон берёт переданный fd и сам
`bind()` не вызывает):

```ini
# ssh3-c-server.socket (фрагмент)
[Socket]
ListenDatagram=0.0.0.0:443
FreeBind=yes

# ssh3-c-server.service (фрагмент)
[Service]
ExecStart=/usr/sbin/ssh3-server -c /etc/ssh3/cert.pem -k /etc/ssh3/key.pem
User=ssh3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

```bash
sudo systemctl enable --now ssh3-c-server.socket
```

Смена порта — через drop-in, без правки самого юнита:

```bash
sudo systemctl edit ssh3-c-server.socket
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

## Лицензия

Собственный код — BSD 2-clause (`LICENSE`). Код, адаптированный из nginx
(BSD 2-clause), перечислен в `THIRD-PARTY-NOTICES.md` — его заголовки
сохраняют `Copyright (C) Nginx, Inc.`.
