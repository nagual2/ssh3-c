# ssh3-c: зависимости сборки и вопрос QUIC (отчёт)

Дата: 2026-10-01. Постановка Пилота: OpenSSH входит в базовые системы Linux и собирается с их библиотеками; минимизировать сторонние библиотеки ssh3-c. Непонятно, что делать с QUIC. Этот отчёт — анализ и рекомендация.

## 1. Базис: что на самом деле линкует OpenSSH

OpenSSH portable требует из внешнего ровно две системные библиотеки:

| № | Библиотека | Роль | Опциональность |
|---|------------|------|----------------|
| 1 | `libcrypto` (OpenSSL/LibreSSL) | вся криптография TLS/SSH | обязательна |
| 2 | `libz` | сжатие канала | обязательна (но канал сжатие почти не использует) |

Опциональные и дистрибутивные: `libedit` (sftp-клиент), `libfido2` (FIDO-ключи), GSSAPI/kerberos, PAM/audit/selinux (патчи дистрибутивов). Суть принципа: **сам протокольный слой (SSH) — собственный код OpenSSH, из системных библиотек берётся только крипто-стек**. SSH-протокол никогда не был «библиотекой» — и именно поэтому OpenSSH собирается везде.

Вывод-мишень для ssh3-c: **единственная системная зависимость — `libcrypto`**. QUIC и HTTP/3 — это наш протокольный слой, аналогичный SSH-слою OpenSSH: собственный код, а не библиотека. Приятный бонус: zlib ssh3 не нужен вовсе (QUIC не использует DEFLATE).

## 2. Анатомия QUIC-зависимости

QUIC нельзя взять «одной библиотекой из базы» — это конгломерат из четырёх слоёв:

| № | Слой | Что требует |
|---|------|-------------|
| 1 | TLS 1.3 с QUIC API | handshake-колбэки, transport parameters в TLS-extension, key phases. Есть в: OpenSSL ≥3.5 (нативный API), BoringSSL, LibreSSL, wolfSSL, GnuTLS ≥3.8 |
| 2 | QUIC-транспорт (RFC 9000/9002) | varint, фреймы, ACK/loss recovery, congestion control, flow control — «монстр» |
| 3 | HTTP/3 + QPACK (RFC 9110/9204) | для ssh3 нужен минимум: extended CONNECT + QPACK, достаточный для interop с quic-go |
| 4 | DATAGRAM (RFC 9221) | обязателен: UDP-форвардинг ssh3 построен на QUIC-datagrams |

Ключевой факт 2025–2026: **OpenSSL 3.5 LTS (апрель 2025) дал нативный QUIC API — сервер + клиент + 0-RTT для сторонних QUIC-стеков**. До этого QUIC-TLS требовал неапстримные форки (quictls) или BoringSSL — именно поэтому «минимальных» QUIC-решений раньше не существовало. Экосистема консолидируется: curl выбросил свой quictls-бэкенд в январе 2026, nginx рекомендует OpenSSL ≥3.5.1.

## 3. Варианты QUIC-стека

| № | Вариант | Язык | TLS | Лицензия | В дистрибутивах | DATAGRAM/0-RTT/GSO | Комментарий |
|---|---------|------|-----|----------|-----------------|--------------------|-------------|
| 1 | **Свой QUIC (адаптация nginx `src/event/quic/`) + OpenSSL 3.5 системный** | C | системный libcrypto | BSD-2 (nginx), OpenSSL | код наш; TLS — из базы | DATAGRAM **дописать** (nginx его не имеет); 0-RTT есть; GSO есть | слой QUIC становится нашим исходником, как SSH-слой у OpenSSH |
| 2 | **ngtcp2 + nghttp3 системные** + OpenSSL 3.5 или GnuTLS | C | libcrypto/gnutls | MIT | Debian 13 (1.11, backports свежее), Fedora, Alpine (1.22–1.25) | оба есть, GSO API есть | 2 доп. библиотеки; QUIC поддерживает апстрим |
| 3 | quiche (Cloudflare) | Rust+CAPI | BoringSSL **vendored** | BSD-2 | нет | есть | тянет тулчейн Rust и BoringSSL — против принципа |
| 4 | lsquic (LiteSpeed) | C | BoringSSL (конкретные коммиты) | MIT | нет | есть | + libevent, zlib; вендоринг BoringSSL |
| 5 | picoquic (Private Octopus) | C | picotls (свой) | MIT | нет | есть | свой TLS-стек — не «системная» зависимость |
| 6 | mvfst (Meta) | C++ | BoringSSL + fizz/folly | MIT | нет | есть | самый тяжёлый; C++ с исключениями, чужой стиль |

Варианты 3–6 отвергаются одним и тем же аргументом: **все они влекут BoringSSL или picotls как вендоренную зависимость** — сборка перестаёт быть «из базовых библиотек», появляется тулчейн (Rust у quiche) или неупаковываемый в дистрибутивы код. Ни один не входит в базовые репозитории Debian/Fedora/Alpine.

## 4. Упаковка системного OpenSSL 3.5 (для варианта 1)

| № | Дистрибутив | OpenSSL | QUIC API | Комментарий |
|---|-------------|---------|----------|-------------|
| 1 | Debian 13 trixie | 3.5.x | есть | текущая stable |
| 2 | Ubuntu 25.10 | 3.5.3 | есть | |
| 3 | Fedora 43 | 3.5.8 | есть | свежие фиксы QUIC-сервера |
| 4 | Alpine 3.22 | 3.5.8 | есть | важно для embedded/контейнеров |
| 5 | Ubuntu 24.04 LTS | 3.0.x | **нет** | окно поддержки до 2029 — ложбина |
| 6 | RHEL 10 | 3.2.x | **нет** | нет и в придачу строгая политика |
| 7 | Windows | n/a (vcpkg OpenSSL 3.5) | есть | сборка через vcpkg — задокументированное исключение |

Upstream OpenSSL публикует официальные пакеты .deb/.rpm (репозиторий openssl/packages) — для Ubuntu 24.04/RHEL есть санкционированный обходной путь без вендоринга.

Для варианта 2: ngtcp2 упакован в Debian 13 (но пакет собран только с GnuTLS-бэкендом; OpenSSL-бэкенд требует ngtcp2 ≥1.12 — брать из backports), Fedora и Alpine — с актуальными версиями.

## 5. Матрица решений (критерии Пилота)

Критерии: минимум сторонних библиотек; сборка из базовой системы; zero-copy; DATAGRAM+0-RTT; зрелость; стиль.

| № | Критерий | В.1: свой QUIC + OpenSSL 3.5 | В.2: ngtcp2+nghttp3 |
|---|----------|------------------------------|---------------------|
| 1 | Сторонних библиотек | **1** (libcrypto — как у OpenSSH) | 3 (libcrypto + ngtcp2 + nghttp3) |
| 2 | Сборка из базовой системы | да (Debian 13/Ubuntu 25.10/Fedora 43/Alpine 3.22) | да, но версии/бэкенды разнятся (Debian: GnuTLS-бэкенд в базе) |
| 3 | Zero-copy контроль | **максимальный** (наш код: shadow-buf, chain, GSO-склейка — паттерны nginx) | хороший (writev-API, GSO), но буферы принадлежат библиотеке |
| 4 | DATAGRAM | дописать самим (RFC 9221: TP 0x0020, фреймы 0x30/0x31, очередь, flow control) — **главная инженерная надбавка** | есть из коробки (`ngtcp2_conn_writev_datagram`) |
| 5 | Зрелость QUIC (loss/cc) | наша ответственность (код nginx — боевой, но DATAGRAM-надбавка наша) | **апстрим ngtcp2** (используется curl/Node) |
| 6 | Объём бинарника | минимальный (своя обрезка под ssh3) | больше (полный QUIC+h3) |
| 7 | Риск свежести OpenSSL 3.5 | QUIC API молод: QUIC-фиксы до 3.5.8 (double-free) — требовать новейший патч-релиз | тот же TLS-слой, но меньше своего кода поверх |
| 8 | Соответствие принципу «как OpenSSH» | **полное**: протокол = наш код, TLS = системная либа | частичное: протокол = чужая библиотека |

## 6. Рекомендация

**Основной путь — вариант 1**: системный `libcrypto` (OpenSSL ≥3.5, требование в CMake `find_package(OpenSSL 3.5)`) + QUIC-транспорт как наш исходник (адаптация `src/event/quic/` nginx, BSD-2) + минимальный h3-слой. Сторонних библиотек — одна, ровно как у OpenSSH; только вместо zlib у нас ничего (не нужно). Это уже зафиксировано в ARCHITECTURE.md (решение №2) — отчёт подтверждает выбор и снимает альтернативы.

**Резервный путь — вариант 2** (документировать, не строить сейчас): билд-опция `S3_USE_NGTCP2` для дистрибутивов без OpenSSL 3.5 (Ubuntu 24.04 LTS, RHEL 10), если спрос появится. ngtcp2 — единственная упакованная в дистрибутивах альтернатива (MIT, C, DATAGRAM/0-RTT/GSO из коробки).

**Отвергнуто**: quiche, lsquic, picoquic, mvfst — вендоринг BoringSSL/picotls, отсутствие в дистрибутивах, у quiche тулчейн Rust. quictls — неапстримный форк, не «базовая» библиотека (curl отказался от этого пути в 2026).

### Лицензия заимствуемого кода nginx (проверено по клону 2026-10-01)

`LICENSE` nginx — **BSD 2-clause** («Copyright (C) 2002-2021 Igor Sysoev, Copyright (C) 2011-2026 Nginx, Inc.»). Разрешает копирование, модификацию и использование в любых проектах (включая закрытые) при двух условиях: (1) в исходниках сохраняется копирайт-заметка и дисклеймер; (2) в бинарных поставках те же заметка и дисклеймер воспроизводятся в документации/материалах поставки. Copyleft нет, патентной оговорки нет.

Объём заимствования: `src/event/quic/` ≈ 17.5k строк (31 из 32 файлов с заголовком `Copyright (C) Nginx, Inc.`), `src/http/v3/` ≈ 7.4k строк, плюс точечные core-примитивы (pool/buf/string/rbtree).

Обязательства ssh3-c:
1. В адаптированных файлах сохранять nginx-заголовок и добавлять свой (паттерн: nginx-строка + наша).
2. В корень репо — `LICENSE` (наша) + `THIRD-PARTY-NOTICES.md` с текстом BSD-2 nginx и перечнем адаптированных файлов.
3. Товарный знак: не называть продукт nginx/SSH3 как «nginx».
4. Совместимо с политикой публикации (dual-source): паблик-репозиторий с этими заметками легален.

Наш собственный код (наш копирайт, без обязательств nginx): DATAGRAM RFC 9221, слой `ssh3/` (conversation/channel/message/auth) целиком, `app/` (CLI, PTY, sftp, forwarding), адаптационный клей и сборка.

## 7. Следствия для ARCHITECTURE.md и открытые вопросы

Следствия:
1. ssl-слой (риск №2 в ARCHITECTURE.md): три API-варианта (OpenSSL 3.5 / quictls / boringssl) сужаются до **одного** — OpenSSL QUIC API; compat-ветки не проектируем. Для старых дистрибутивов — официальные пакеты upstream OpenSSL или опция S3_USE_NGTCP2.
2. Новый инкремент в M2: **DATAGRAM (RFC 9221)** поверх адаптированного nginx-кода — TP 0x0020, фреймы 0x30/0x31, per-conn очередь, flow control датаграмм. Оценка: средняя, код содержится в одном месте (frames + connection), но тесты обязательны (UDP-форвардинг зависит от него целиком).
3. CMake: `find_package(OpenSSL 3.5 REQUIRED)` + compile-time проверка наличия QUIC API (аналог nginx `auto/feature`); failure-сообщение с подсказкой про официальные пакеты.

Открытые вопросы (решать в M3):
1. **QPACK-минимум vs interop с quic-go**: можно ли заставить quic-go/http3 кодировать только статической таблицей (SETTINGS_QPACK_MAX_TABLE_CAPACITY=0, blocked streams=0) — тогда наш h3-слой без dynamic table. Проверить экспериментом в M3; если нет — адаптировать QPACK-таблицу nginx.
2. Зрелость QUIC-сервера OpenSSL 3.5.x: держать в CMake требование новейшего патч-релиза (≥3.5.8); тест на CERT-фиксы в CI.
3. Windows: OpenSSL 3.5 через vcpkg — принять как исключение из «базовых библиотек» (для Windows это аналог «системной»).

## 8. Источники

- [OpenSSL 3.5 Series Release Notes](https://openssl-library.org/news/openssl-3.5-notes) — QUIC-сервер, 0-RTT, LTS
- [OpenSSL 3.5 Final Release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release)
- [curl HTTP/3 docs](https://curl.se/docs/http3.html) — OpenSSL 3.5.0+ требует ngtcp2 ≥1.12
- [curl SSL libraries compared](https://curl.se/docs/ssl-compared.html)
- [More HTTP/3 focus, one backend less](https://daniel.haxx.se/blog/2026/01/17/more-http-3-focus-one-backend-less) — отказ curl от quictls-бэкенда
- [OpenSSL does a QUIC API](https://daniel.haxx.se/blog/2025/02/16/openssl-does-a-quic-api)
- [ngtcp2: writev_datagram (RFC 9221)](https://nghttp2.org/ngtcp2/ngtcp2_conn_writev_datagram.html), [programmers guide: 0-RTT](https://nghttp2.org/ngtcp2/programmers-guide.html)
- [ngtcp2 в Debian trixie](https://packages.debian.org/source/trixie/ngtcp2) (1.11.0), [Fedora ngtcp2](https://packages.fedoraproject.org/pkgs/ngtcp2), [Alpine nghttp3](https://pkgs.alpinelinux.org/package/edge/main/x86_64/nghttp3)
- [openssl 3.5.8 в Alpine 3.22](https://pkgs.alpinelinux.org/package/v3.22/main/x86/openssl)
- [Ubuntu 25.10 openssl 3.5.3](https://www.ubuntuupdates.org/package/core/questing/main/security/openssl), [Fedora 43 openssl 3.5.8](https://packages.fedoraproject.org/pkgs/openssl/openssl/fedora-43-updates.html)
- [openssl/packages — официальные .deb/.rpm от upstream](https://github.com/openssl/packages)
- [lsquic](https://github.com/litespeedtech/lsquic) (BoringSSL обязателен), [quiche](https://github.com/cloudflare/quiche) (BoringSSL vendored), [picoquic build](https://www.privateoctopus.com/picoquic/building_picoquic.html) (picotls)
