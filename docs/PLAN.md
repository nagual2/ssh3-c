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
| 1 | P0 | **готова** — core 23 файла/3.1k строк, ctest 6/6 в release+asan, 0 warnings, clang-format/tidy чисто | 2026-10-01 |
| 2 | P1 | **готова** — event loop (epoll) + таймеры + posted + UDP-псевдо-коннекции + udp_sendmsg_chain; ctest 8/8 в release+asan; GSO-бенч ×3.2–3.8 (цель ≥2.5) | 2026-10-01 |
| 3 | P2 | **D1–D4 закоммичены** (90bc3bc стримы, fbaaf7b миграция); ctest 17/17 release+asan; матрица `interop/run-quic-go.sh` 5/5 PASS; idle-timeout подтверждён (`-i`/`-hold`). **Дедлок flow-control устранён (2026-10-03)**: в `s3_quic_resend_frames` не хватало пересборки кадров `MAX_STREAM_DATA`/`STREAM` при ретрансмиссии — кадр уходил повторно со старым лимитом окна, пиер переставал его расширять, поток вставал на ~100–142 МБ. Починено по эталону nginx (`case NGX_QUIC_FT_MAX_STREAM_DATA` + освобождение `STREAM` при RESET), регресс-тест `test_max_stream_data_retransmit`. Бенч: **128 МБ — 2.1 с; 1 ГиБ — 16.5 с (C↔quic-go), 16.1 с (C↔C)** — потолок на нашей стороне, не у пиера. **MTU-discovery прорыв (2026-10-03, 0d6c17f)**: расследование cwnd/GSO показало — окно не лимитировало (in_flight < window, 289574/289585 ack'ов отсечены флагом idle), но при порте D4 в ACK-обработчике потерян вызов `s3_quic_handle_path_mtu()`: пробы никогда не подтверждались, `path->mtu` навсегда 1200, весь трафик шёл 1200-байтными пакетами (77% стенки — syscalls). Вызов восстановлен по эталону nginx + e2e-фаза DPLPMTUD (red/green). **1 ГиБ C↔C echo: 13.0–17.8 с → 4.23–4.76 с (×3.4, ~231–251 MB/s по дрейфу); паритет с OpenSSH** (та же нагрузка: 4.32/4.41/4.56 с; под strace user-CPU у нас ниже: 2.3–2.5 vs 3.6–3.8 с). Цель ≥250 MB/s — на грани, честно не закрыта (медиана дня ~237 MB/s). **Ретест `stream_buffer_size`**: 16 KiB — стабильный лучший (4.2–4.8 с); 32 KiB — бимодален (3.3/12.4/24.6 с); 64 KiB — **детлок эха 3/3** на ~660–700 МиБ (новый баг: кадр 65584 B не влезает в датаграмму ~65479 B; `split_frame` и сборка пакета сверены с nginx построчно — механизм вне сборки, подозрев: ретрансмиссия/каденция flow-control, семейная тема «гранула окна»); 1 MiB — ×2 медленнее (8 с). Датаграмма в базе ограничена буфером стрима (16432 B при MTU 65527) — буферы ≥64 KiB обещают >250 MB/s после починки детлока. **P2 закрывается после бенч-прорыва + починки детлока 64 KiB**. **Фаза закрыта с ограничением (2026-10-03)**: прорыв и паритет с OpenSSH зашиты (`0d6c17f`), дефолт (буфер 16 KiB) стабилен; детлок буферов ≥64 KiB остаётся открытым и ждёт поимки (жгуты `temp/ssh3-c/{dbg,det,stall}-wedge.sh`, протокол в EchoVault), буферы ≥64 KiB до починки не рекомендованы; попутно rbtree-ключи расширены до 64 бит (`67fd64d`), RFC 9002-сверка PTO чиста | 2026-10-03 |
| 4 | P2-DT | **DATAGRAM переведён на zero-copy (2026-10-03)**: обработчик получал сплющенный блок — на каждую датаграмму `s3_palloc` + копирование цепочки парсера. API переведён на `s3_quic_datagram_pt(c, s3_chain_t *data)`: цепочка передаётся как есть, ни блока, ни копии. Обработчики (interop server/client, тесты) идут по ссылкам; echo на однозвенной цепочке уходит на отправку без копий. Контракт: цепочка валидна только на время вызова — она указывает на статический буфер дешифрования, как в nginx | 2026-10-03 |
| 5 | P3 | **начата 2026-10-03** — волна 1 (субагенты, параллельно): порт QPACK-таблиц и encode (`ngx_http_v3_table/encode` → `src/h3/s3_h3_table/encode`), порт парсера фреймов/стейт-машин (`ngx_http_v3_parse` → `s3_h3_parse`), H3-режимы Go-харнесса (extended CONNECT). Контракты (`s3_h3.h`, заголовки) и CMake-регистрация подготовлены штабом. **Волна 2 закрыта (2026-10-03)**: порт uni/сессии (`ngx_http_v3_uni` → `s3_h3_uni.c`: control/encoder/decoder обеих ролей, `known_streams[]`/`created_streams`, role-aware направление uni-стримов в `s3_quic_create_stream`), CONNECT-роут `/ssh3-term` + auth в сервере, extended CONNECT с `:scheme`/`:authority` в клиенте (RFC 9114 §4.4). Три bug-находки интеграции: (1) **коллизия `c->data`** — UDP-слой паркует бэклинк слушателя в `c->data` принятой коннекции, h3-сессия пишет туда же: на сервере `s3_h3_get_session()` возвращал адрес стека `main()`, `init_session` молча пропускался → «stream already created» → висячий posted-event (`qc->close`) на уничтоженном пуле → SEGV в `s3_event_process_posted`; бэклинк перенесён в `qc->listen` (поле quic-коннекции, `s3_quic_open_sockets` забирает при старте, `s3_quic_listen` читает оттуда); (2) клиент не поднимал сессию при раннем uni-стриме пиера — lazy `init_session` в stream-обработчике (симметрично серверу) + `read->active` арминг request-стрима; (3) selftest `-T` использовал длину секции (`s3_interop_h3_request_section` возвращает длину) как указатель → SEGV; плюс контракт `s3_h3_parse_headers`: последняя field-line секции приходит только с `S3_DONE`. **Волна 3 (закрытие фазы)**: переговоры версий и 0-RTT по эталону version.go/go_server — модуль `src/ssh3/s3_ssh3_version.{h,c}` (парс строки `SSH M.m impl X.Y.Z[ experimental_spec_version=V]` + вердикт IsVersionSupported: 3.0 + alpha-00, legacy francoismichel/ssh3 0.1.3–0.1.5; TDD `test_ssh3_version`, 21/21), клиент и Go-харнесс шлют `user-agent`, сервер: 403 (версия), 425 (запрос до завершения рукопожатия, RFC 8470), 400 (`:authority`/`:scheme` отсутствуют, RFC 9114 §4.4), `INTEROP-H3-REJECT code=` в stdout-протоколе; Go-харнесс получил `-bad-ua` (негативный режим) и проверку версии в h3-сервере. **Интероп: `interop/run-h3.sh` 4/4 PASS** (C→quic-go 200, quic-go→C 200, C→C 200, quic-go `-bad-ua`→C 403); ctest 21/21 в release+ASan/UBSan; clang-format, Go vet/gofmt/build чисто. **Фаза закрыта** — критерии (200 в обе стороны) и скоуп (uni, extended CONNECT, роут, 403/425) выполнены | 2026-10-04 |
| 6 | P4–P8 | не начаты | — |
