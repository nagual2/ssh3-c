# ssh3-c — план разработки клиента и сервера

Создан: 2026-10-01. Источники: [ARCHITECTURE.md](ARCHITECTURE.md) (слои, решения, zero-copy правила), [DEPS-QUIC.md](DEPS-QUIC.md) (зависимости, лицензии). Родительский трек: `project/ssh3/docs/ROADMAP.md`.

## 1. Целевая позиция: «OpenSSH среди Linux-систем»

Пилотная цель: ssh3-c со временем занимает в Linux-системах место, аналогичное OpenSSH, с соответствующей лицензией. Что это означает в конкретных признаках:

| № | Признак OpenSSH | Цель ssh3-c | Статус |
|---|-----------------|-------------|--------|
| 1 | Язык — чистый C | C17 | решено (2026-10-01) |
| 2 | Лицензия — пермиссивная (OpenBSD/ISC-семейство, без copyleft) | собственный код — BSD-2; заимствованный nginx-код — BSD-2 (совместимо); `THIRD-PARTY-NOTICES.md` | решено |
| 3 | Зависимости — только системные (libcrypto, zlib) | только `libcrypto` (OpenSSL ≥3.5 QUIC API) | решено (DEPS-QUIC.md) |
| 4 | Протокольный слой — собственный код проекта | QUIC+H3 — наш исходник (адаптация nginx) | решено |
| 5 | Пакеты в дистрибутивах, man-страницы, systemd-юниты | deb/rpm/apk/ipk, man, socket-активация | фаза P7 |
| 6 | Сосуществование с предшественниками (OpenSSH заменил telnet/rsh, а не стёр их) | ssh3 — отдельный пакет рядом с OpenSSH, не замена | фаза P7–P8 |
| 7 | Качество, приемлемое для security-команд дистрибутивов | fuzzing, sanitizers, аудит (R2), интероп-матрица | фазы P6+ |

Спека протокола — `SSH 3.0 alpha-00` (экспериментальная, у апстрима francoismichel/ssh3). Путь к стандартизации (IETF draft) — отдельный трек P8; статус апстримной спеки проверить в начале P8.

## 2. Язык и лицензия (фиксация решений)

- **C17** (заменило прежнее «C++20»): оба референса (OpenSSH, nginx) — C; libstdc++ отсутствует в базовых системах (Alpine base, embedded/OpenWrt); C-ABI стабилен. Полиморфизм — указатели на функции (паттерн `ngx_connection_t`), не классы.
- **Лицензия**: весь новый код — BSD 2-clause (копирайт Пилота/проекта); адаптированные файлы nginx сохраняют `Copyright (C) Nginx, Inc.` + наша строка; в корень репо — `LICENSE` + `THIRD-PARTY-NOTICES.md`. Это функционально тот же класс пермиссивности, что у OpenSSH (OpenBSD-лицензия ≈ ISC ≈ BSD-2).
- Каталог переименован `project/ssh3-cpp` → `project/ssh3-c` (cpp в имени более не соответствует языку).

## 3. Треки: общий каркас, сервер, клиент

Слои `core/event/os/quic/h3` — общие и симметричные для клиента и сервера. Разветвление начинается на слое `ssh3/`:

| № | Слой | Сервер | Клиент |
|---|------|--------|--------|
| 1 | Общий (P0–P3) | core/event/os/quic/h3 — один код, два бинарника | тот же |
| 2 | `ssh3/` + `app/` | accept-лупы, auth-верификаторы (`authorized_identities`, `getpwnam`/shadow, JWT/Basic), exec/shell/PTY (termios), sftp-подсистема с jail, forward-обработка, agent UDS, login banner | dial+0-RTT, known_hosts TOFU, auth-провайдеры (password/JWT-файл/JWT-агент), session pump (stdin/stdout/PTY raw+resize), forward-инициаторы, ControlMaster, sftp-клиент с resume |

Сборка: два бинарника `ssh3` и `ssh3-server` из одной кодовой базы (аналог `cmd/ssh3`, `cmd/ssh3-server` в Go).

## 4. Фазы разработки

| № | Фаза | Содержимое | Приёмка |
|---|------|-----------|---------|
| P0 | Скелет и core | CMake+presets (release/asan), `src/core`: pool/str/buf/chain/log/rbtree/queue; clang-format/tidy конфиги; LICENSE+NOTICES; тестовый каркас | юнит-тесты core зелёные; `-Wall -Wextra -Werror`; ASan/UBSan чисто |
| P1 | Event loop + UDP I/O | epoll-бэкенд, posted events, таймеры-rbtree; `udp_sendmsg_chain` + GSO (`UDP_SEGMENT`); recvmsg + rbtree псевдо-коннекций | микробенч: GSO on ≥ ×2.5 от off (loopback); event-тесты |
| P2 | QUIC транспорт | адаптация `src/event/quic/` nginx: transport/frames/ack/connid/output/protection/ssl/streams/tokens/migration; ssl-слой под OpenSSL QUIC API; **плюс DATAGRAM RFC 9221** (TP 0x0020, фреймы 0x30/0x31, очередь, flow control) — надбавка, которой нет в nginx | handshake с quic-go; bulk 1 GiB loopback ≥250 MB/s; datagram roundtrip Go↔C |
| P3 | h3-минимум + control stream | QPACK (эксперимент: static-only через SETTINGS_QPACK_MAX_TABLE_CAPACITY=0 для interop с quic-go; если не выйдет — адаптация таблицы nginx), uni-стримы, extended CONNECT; сервер: роут `/ssh3-term`, 403-версия/425-0-RTT; клиент: CONNECT+auth-заголовки | C клиент → Go сервер: 200; Go клиент → C сервер: 200 |
| P4 | ssh3-ядро | messages 91/92/94/95/98 (varint+SSHString), каналы (ChannelID=StreamID), conversation, датаграммный роутинг. **Сервер**: auth-верификаторы, exec/shell/PTY, exit-status, banner. **Клиент**: session pump, PTY raw+resize, known_hosts TOFU, password/JWT-файл/JWT-агент | interop-матрица в обе стороны: shell, exec, pty, resize, signal, exit-status |
| P5 | Фичи паритета форка | **Сервер**: sftp-подсистема (jail $HOME), direct-tcp/direct-udp обработка, agent UDS. **Клиент**: file transfer (resume, `-r`, checksum), TCP/UDP forward-инициаторы, agent forwarding, proxy-jump, ControlMaster (S3CM) | матрица `FORWARDING-TESTPLAN.md` зелёная; transfer roundtrip Go↔C |
| P6 | Hardening | fuzzing парсеров (varint/SSHString/h3/QUIC frames) libFuzzer/AFL, sanitizers в CI, valgrind-прогон, пути ошибок, security-аудит (R2 ROADMAP — закрытой моделью по решению Пилота) | 0 крашей за 24ч fuzz; аудит пройден |
| P7 | Пакетирование | deb/rpm/apk (packaging/), OpenWrt ipk (мандатная зона Пилота), systemd units (`ssh3-server.socket` на UDP — socket-активация), man-страницы, README en/ru (R6), контрольные бенчи C vs Go vs OpenSSH по методике R3 | пакет ставится на Debian 13/Alpine 3.22/OpenWrt, юнит активируется; бенч-отчёт в docs/ |
| P8 | Путь в базовые системы (долгий горизонт) | стабилизация спеки (alpha-00 → draft; проверить апстрим), подача в Debian NEW / Fedora review / Alpine aports, политика сосуществования с OpenSSH (отдельный пакет, порт/конфиги не конфликтуют), контакт с security-командами | пакет принят/в ревью хотя бы в одном крупном дистрибутиве |

Порядок: P0→P8 последовательно; внутри P4–P5 сервер и клиент двигать параллельно в одной фазе (interop требует обеих сторон). Каждая фаза = несколько сессий; приёмка фазы фиксируется `memory_save` и дописью в этот файл (столбец статуса).

## 5. Тестирование и верификация (сквозное)

| № | Вид | Что |
|---|-----|-----|
| 1 | Юнит-тесты | каждый модуль core/ssh3; wire-векторы из Go `wire_vectors_test.go` как фикстуры |
| 2 | Sanitizers | ASan/UBSan пресет — обязателен для каждого Milestone-прогона |
| 3 | Interop | матрица направлений: C-клиент↔Go-сервер, Go-клиент↔C-сервер, C↔C; стенды S1 (WSL loopback) и S2 (host-b) из методики R3 |
| 4 | Бенчмарки | методика R3: bulk/handshake/latency/CPU-RAM; сравнение против Go-форка и OpenSSH на тех же стендах |
| 5 | Fuzzing | парсеры wire/h3/QUIC — с P2 (как только появляются парсеры), непрерывно в фоне |

## 6. Риски

| № | Риск | Митигция |
|---|------|----------|
| 1 | Адаптация nginx QUIC тянет `ngx_cycle`-зависимости | послойный перенос, cycle → `s3_context`; отличия вести в docs/PORTING-nginx-quic.md |
| 2 | DATAGRAM-надбавка в P2 — наш код поверх боевого | изоляция в `quic/frames+datagram.c`, фуззинг с P2, интероп-тесты UDP-форвардинга в P3+ |
| 3 | QPACK static-only может не сработать с quic-go | запасной план — адаптация dynamic table nginx (≈готовый код) |
| 4 | OpenSSL 3.5 QUIC API молод | требование ≥3.5.8 в CMake; CI на свежем патч-релизе; резерв S3_USE_NGTCP2 (DEPS-QUIC.md) |
| 5 | Windows-порт | после P7; ConPTY, sendmsg без GSO; Linux-first |
| 6 | Спека alpha-00 нестабильна | фиксировать версию протокола в User-Agent/Server, version negotiation уже в протоколе |

## 7. Статус фаз

| № | Фаза | Статус | Дата |
|---|------|--------|------|
| 1 | P0 | не начата | — |
| 2 | P1–P8 | не начаты | — |
