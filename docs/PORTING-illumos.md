# ssh3-c: портирование на illumos, архивация трафика, распределённый ZFS
> Languages: RU (this file) · EN (в подготовке) · DE (в подготовке)

Дата: 2026-10-21. Заказчик: владелец проекта. Постановка: «Есть ещё один аспект, который
надо снять сейчас — архивация трафика. Как нужно изменить SSH-3, чтобы его использовали
в проекте illumos, распределённой системе ZFS?»

Документ состоит из двух частей:

- **§2 — инженерная оценка автора** (что менять в ssh3-c, в каком порядке, чего не хватает);
- **§3 — исследовательский отчёт субагента** (проверка фактов по исходникам illumos,
  приложен дословно, со ссылками; метод и границы проверки — в §3.0 и §4).

Ключевая поправка к более ранней оценке FreeBSD-порта: **в illumos `epoll` есть**
(шим над `/dev/poll`), тогда как во FreeBSD его нет принципиально. Проверено по
исходникам: `usr/src/lib/libc/port/sys/epoll.c`, `usr/src/uts/common/sys/epoll.h`,
`usr/src/man/man7/epoll.7` — все три отдают HTTP 200.

---

## 1. Краткое резюме

| № | Вывод | Основание |
|---|-------|-----------|
| 1 | Протокол и большую часть кода ssh3-c для illumos трогать не нужно | `epoll` в illumos есть; Linux-специфичный API (GSO/`UDP_SEGMENT`, `SO_PEERCRED`, `TCP_INFO`, `accept4`) в проекте не используется или корректно деградирует |
| 2 | Главная работа — крипто: OpenSSL 3.5 придётся собирать самим | OpenSSL в illumos отсутствует и в дереве гейта, и в IPS-издателе illumos; `SSL_set_quic_tls_cbs` — 0 совпадений по illumos-gate |
| 3 | Основной объём в C — новый event-backend на event ports | illumos сам предупреждает о гонках в многопоточности при epoll-шиме; `EPOLLEXCLUSIVE` уходит в `EPOLLIGNORED` |
| 4 | Для сервиса — SMF вместо systemd; socket activation аналога не имеет | `man7/smf.7`, `usr/src/pkg/manifests/*.p5m` |
| 5 | **Архивация трафика требует пересборки конвейера, а не правок ssh3** | `/dev/net/tun` и `/dev/tap` в illumos отсутствуют; штатный захват только пассивный (`snoop`, `ipf`, DTrace) |
| 6 | Роль illumos в схеме — приёмник и хранилище, не перехватчик | следствие п. 5 |
| 7 | Репликация ZFS поверх ssh3 уже возможна | `zfs send \| ssh3 node zfs recv`: бинарно-безопасный exec-канал без PTY + `exit-status` |

---

## 2. Инженерная оценка автора

### 2.1. Что уже готово в ssh3-c под этот workload

| № | Механизм | Где в коде | Что даёт для архивации |
|---|----------|-----------|-----------------------|
| 1 | SFTP v3 с джейлом (chroot к home) | `src/ssh3/s3_ssh3_sftp_srv.c`, `src/ssh3/s3_ssh3_sftp_jail.c` | заливка pcap в dataset пользователя; `pwrite` по offset → докачка с места обрыва (`s3_ssh3_sftp_srv.c:1064`) |
| 2 | Resume в клиенте SFTP | `src/ssh3/s3_ssh3_sftp_cli.c:700` (`unsigned resume : 1`), STAT удалённого файла | докачка уже реализована на клиенте |
| 3 | exec/shell без PTY + `exit-status` | `src/ssh3/s3_ssh3_session_srv.c`, `src/ssh3/s3_ssh3_request.c:25` | `zfs send \| ssh3 node zfs recv` — бинарный канал с кодом возврата |
| 4 | DATAGRAM-канал | `src/ssh3/s3_ssh3_dgram.c` | базис для зеркалирования потоков (lossy, без переупорядочивания) |
| 5 | Прямые и обратные форварды, SOCKS5 | `src/ssh3/s3_ssh3_forward.c`, `src/ssh3/s3_ssh3_reverse.c`, `src/ssh3/s3_ssh3_forward_policy.c` | сбор трафика на edge-узле без правок ssh3 |
| 6 | Атомарная фиксация через RENAME | SFTP `RENAME` (тип 18) | схема «пишем в `.part` → rename» работает; в ZFS атомарна |
| 7 | Аутентификация | pubkey (`~/.ssh3/authorized_identities`, `~/.ssh/authorized_keys`), JWT/OIDC (`src/ssh3/s3_ssh3_auth_jwt.c`, `s3_ssh3_oidd.c` → `s3_ssh3_oidc.c`) | приёмник различает источники архива |

Ограничения, важные для объёмов:

| № | Ограничение | Значение | Где |
|---|------------|---------|-----|
| 1 | Максимальный кадр канала | 16 МиБ | `src/ssh3/s3_ssh3_channel.h:31` (`S3_SSH3_CHANNEL_MAX_PACKET_LIMIT`) |
| 2 | Максимальный фрейм SFTP | 256 КиБ | `src/ssh3/s3_ssh3_sftp.h:26` (`S3_SSH3_SFTP_MAX_FRAME`) |
| 3 | Окно flow control QUIC | настраивается через `initial_max_data` / `initial_max_stream_data_*` | `src/event/quic/s3_quic.h:191-196` |

### 2.2. Что надо изменить в ssh3-c для illumos

| № | Слой | Изменение | Оценка |
|---|------|-----------|--------|
| 1 | Крипто | Собрать OpenSSL 3.5 локально в префикс (`/opt/openssl-3.5`) и указать его через `CMAKE_PREFIX_PATH` — прецедент в проекте уже есть: `CMakeLists.txt:386` ищет `$ENV{HOME}/opt/openssl-3.5`, а Windows-ветка — `CMakeLists.txt:123` (`openssl-3.5-mingw`). В illumos OpenSSL нет ни в дереве гейта, ни среди 400+ IPS-манифестов издателя `illumos`; `SSL_set_quic_tls_cbs` — 0 совпадений | **главная работа** |
| 2 | Компилятор | Базовый gcc в illumos — 4.4.4 (`illumos/gcc`, ветка `il-4_4_4`), в legacy-издателе — 3.4.3/4.4.x. C17 и OpenSSL 3.5 на них не собираются → нужен `illumos/gcc` master | **блокер №1** |
| 3 | События | Шим `epoll` покрывает весь используемый набор флагов (`EPOLLIN`, `EPOLLOUT`, `EPOLLRDHUP` — `usr/src/uts/common/sys/epoll.h:52-67`; в `epoll.c` есть трансляция `EPOLLRDHUP → POLLRDHUP`, `EPOLLET → POLLET`), но `man7/epoll.7` предупреждает о гонках при многопоточном использовании и о `close(2)`, а `EPOLLEXCLUSIVE` объявлен, но входит в `EPOLLIGNORED`. Для QUIC-сервера — новый модуль `src/event/modules/s3_evport_module.c` на event ports (`port_create`/`port_associate`/`port_getn`, `usr/src/uts/common/fs/portfs/port.c`, `man3c/port_create.3c`) | **основной объём в C** |
| 4 | Сокеты | GSO/UDP-сегментации в illumos нет (`UDP_SEGMENT` отсутствует в `netinet/in.h`) → ветка `S3_HAVE_UDP_SEGMENT` (`CMakeLists.txt:367`) корректно выключится, отправка пойдёт обычным `sendmsg`. `TCP_INFO`, `SO_PEERCRED`, `accept4` в проекте не используются (проверено grep по `src/` и `app/`) — правок не требуется | без правок |
| 5 | Служба | systemd-юниты (`packaging/systemd/ssh3-server.service`, `ssh3-server.socket`) заменяются SMF-манифестом `service_bundle` в `/usr/smf/manifests/*.xml` (`man7/smf.7`, `man3scf/smf_enable_instance.3scf`). **Socket activation аналога не имеет** — демон биндит UDP/443 сам (`-l`/`-p`), требуется root либо право `net_privaddr` | средний |
| 6 | Упаковка | IPS-манифест `.p5m` (образец: `usr/src/pkg/manifests/service-network-ssh.p5m`, `network-snoop.p5m`) либо install-скрипт; каталог и пути в духе illumos (`/usr/share`, `/var/adm/log/messages`) | средний |
| 7 | Целостность | В SFTP-сервере **нет `fsync`** — для архива, переживающего аварийный сбой ноды, нужен `SSH_FXP_FSYNC` (или расширенный op `200/201`) | маленький, но обязательный |

### 2.3. Архивация трафика: как перестроить конвейер

Ключевой факт: `/dev/net/tun` и `/dev/tap` в illumos **отсутствуют** (0 совпадений по дереву
illumos-gate; `sppptun` — это PPP-туннель, не TUN). Штатные способы захвата — только
пассивные:

| № | Способ | Механизм | Формат вывода |
|---|--------|----------|---------------|
| 1 | `snoop` | STREAMS-модули `pfmod(4M)` + `bufmod(4M)`, `usr/src/uts/common/io/pfmod.c` | pcap-файлы (в `man8/snoop.8` — пример через `mergecap -w`) |
| 2 | `ipf` | `usr/src/cmd/ipf` (+`ipfd`, `ipfs`, `ipfstat`) | лог пакетов |
| 3 | DTrace | провайдер `ip`, демо `ip/ipproto.d`, `ip/tcpsnoop.d` в `usr/src/cmd/dtrace/demo` | буферизация в userspace |

Инструмент `pktsnoop` из OpenSolaris в illumos отсутствует (0 совпадений).

Целевая схема:

| № | Узел | Что делает | Чем |
|---|------|-----------|-----|
| 1 | Edge (Linux / OpenWrt / ESXi) | снимает трафик с TAP-интерфейса, режет на шарды pcapng | существующий сборщик; ssh3 не трогаем |
| 2 | Транспорт | льёт шарды в ZFS-узел | SFTP-канал с resume; параллельные шарды — штатный мультиплексинг каналов внутри одной QUIC-сессии |
| 3 | ZFS-узел (illumos) | приём в staging-dataset → rename → снимок (read-only, WORM-эффект) | ssh3-server + SFTP; `zfs allow` для делегирования; `zfs receive` обычно от root |
| 4 | Метаданные | манифест шардов с SHA-256 | SSH3-протокол хешей не умеет: либо расширенный SFTP-op, либо сверка на приёмнике |

Чего в ssh3-c **не хватает** по существу:

| № | Пробел | Решение | Трудоёмкость |
|---|--------|---------|--------------|
| 1 | `fsync` в SFTP | расширенный op `SSH_FXP_FSYNC` (или `FSETSTAT`-расширение) | малая |
| 2 | Параллельные шарды с докачкой | клиентский режим «split-N»: режет pcap на шарды, один канал на шард, докачка по `offset` | средняя |
| 3 | Формат архива | pcapng + метаданные потоков — протокол о потоках ничего не знает, это слой агента | вне ssh3 |
| 4 | Политика хранения | ZFS-снимки read-only, `zfs send` на вторичный пул, `zfs allow` для сервисного аккаунта | вне ssh3 |
| 5 | Проверка целостности на приёме | сверка SHA-256 манифеста на приёмнике | малая |

### 2.4. Распределённый ZFS

`zfs send | ssh3 node zfs recv` — паттерн документирован в `man8/zfs.8` illumos (Example 12/13).
ssh3 для этого подходит: бинарно-безопасный exec-канал без PTY (клиентский `-T`), `exit-status`
на месте, кадр до 16 МиБ.

| № | Оговорка | Следствие |
|---|----------|-----------|
| 1 | `zfs send -c` (сжатые WRITE-записи) требует `lz4_compress` на приёмнике | либо разжимать до отправки, либо обеспечивать `lz4_compress` на целевой ноде |
| 2 | `zfs send -w` (raw, как на диске) снимает зависимость получателя от ключей | пригодно для «недоверенного» приёмника |
| 3 | Возобновление обрыва — только инкрементальным `zfs send -i`, не внутри одного потока | нужен внешний ретрай на уровне пайплайна |
| 4 | `zfs receive` обычно требует root; ограничение «только в корень пула» в illumos не документировано | делегирование через `zfs allow` |

### 2.5. Порядок работ

| № | Шаг | Содержание | Критерий приёмки |
|---|-----|-----------|------------------|
| 1 | Сборка на illumos | OpenSSL 3.5 в `/opt/openssl-3.5`, `illumos/gcc` master, cmake из IPS, текущий epoll-шим | бинарь собирается; клиент из WSL подключается, открывается сессия |
| 2 | Event-ports backend | `src/event/modules/s3_evport_module.c`, переключение опцией сборки, тесты на illumos | те же тесты, что и на epoll; нет гонок |
| 3 | Служба и упаковка | SMF-манифест + IPS-манифест (или install-скрипт) | `svcs` показывает сервис, логи в `/var/adm/log/messages`, автозапуск |
| 4 | Конвейер архива | edge-агент → шарды → SFTP с resume → staging-dataset → rename → snapshot | архив восстанавливается бит-в-бит, докачка после обрыва работает |
| 5 | Репликация ZFS | `zfs send \| ssh3 node zfs recv` между двумя illumos-нодами | снапшот доезжает и совпадает по контрольной сумме |

### 2.6. Что снять на целевой ноде до начала работ

| № | Команда | Зачем |
|---|---------|-------|
| 1 | `pkg info openssl` и `pkg info -r openssl` | версия OpenSSL в IPS определяет, собираем ли мы 3.5 сами (IPS-каталоги illumos из сети Пилота не резолвятся — NXDOMAIN на `pkg.illumos.org`, `repo.illumos.org`, `man.illumos.org`) |
| 2 | `pkg info -r gcc`, `gcc --version` | какой компилятор доступен в базе |
| 3 | `pkg info snoop` | подтвердить наличие захвата |
| 4 | `ls /usr/include/sys/epoll.h`, `ls /dev/net 2>&1` | подтвердить наличие epoll и отсутствие tun |
| 5 | `uname -a`, `pkg info -r cmake` | целевая сборка и наличие cmake |

---

## 3. Исследовательский отчёт субагента (приложение)

> Приводится дословно. Метод: прямой разбор исходников `github.com/illumos/illumos-gate`
> (raw-файлы + рекурсивное дерево API), репозиториев `illumos/*` и `OpenIndiana/*`.
> `WebFetch` был нерабочим (provider error), `pkg.illumos.org` и `man.illumos.org`
> недоступны из этой сети (NXDOMAIN по DoH dns.google, 2026-10-21) — поэтому часть пунктов
> помечена «не подтверждено» с указанием, что именно проверялось.

### 3.0. Важная поправка к вводным

epoll в illumos **есть** (и в базе, и в master), вопреки распространённому мнению — см. п. 3.2.

### 3.1. OpenSSL в базе illumos

| Факт | Значение | Источник |
|------|----------|----------|
| OpenSSL в дереве illumos-gate | **Отсутствует**: по всему рекурсивному дереву репозитория 20 вхождений «openssl», все посторонние (лицензии ядерного crypto, krb5 pkinit, kmf-плагин). Ни `usr/src/lib/libssl`, ни `libcrypto`, ни `man3ssl` | [tree illumos-gate](https://github.com/illumos/illumos-gate), `usr/src/lib/libkmf/plugins/kmf_openssl/`, `usr/src/common/crypto/aes/amd64/THIRDPARTYLICENSE.openssl` |
| OpenSSL в «illumos» IPS-издателе | **Нет пакета** `library/openssl` среди 400+ манифестов `usr/src/pkg/manifests/*.p5m` (полный листинг проверен) | [usr/src/pkg/manifests](https://github.com/illumos/illumos-gate/tree/master/usr/src/pkg/manifests) |
| Конвейер сборки сторонних библиотек | Два пути: (1) IPS-издатель `illumos` (манифесты `.p5m` в illumos-gate); (2) «userland consolidation» `illumos/illumos-userland` — компоненты: `cmake`, `binutils`, `make`, `automake`, `gcc3` (3.4.3), `gcc44`, `libevent`, `curl` | [illumos-userland/components](https://github.com/illumos/illumos-userland/tree/master/components) |
| OpenSSL в illumos-userland | Только legacy: `openssl-1.0.0`, `openssl-0.9.8-fips-140`, `openssl-fips`; последний коммит по пути — **04.10.2011** → издатель заморожен, это не источник OpenSSL 3.x | [components/openssl/README](https://github.com/illumos/illumos-userland/blob/master/components/openssl/README) |
| Версия OpenSSL в illumos 2.11 / master | **Не подтверждено.** Проверял: `pkg.illumos.org` (NXDOMAIN → каталоги издателей «illumos»/Omnipresence недоступны), `ips.illumos.org`, `repo.illumos.org` (NXDOMAIN), `wiki.illumos.org` (nginx 500), `man.illumos.org` (NXDOMAIN), `code.illumos.org` gitiles (проекты только `illumos-gate`, `illumos-arm64` — Omnipresence там нет) | DoH dns.google; https://code.illumos.org/plugins/gitiles/ |
| `SSL_set_quic_tls_cbs` (QUIC TLS API) | **В дереве illumos — 0 совпадений** (согласен с код-сеarch автора). API появился только в OpenSSL ≥3.2; в illumos OpenSSL вне дерева, поэтому наличие QUIC API определяется версией IPS-пакета, а она не подтверждена | дерево illumos-gate; https://www.openssl.org/docs/man3.5/man3/SSL_set_quic_tls_cbs.html |
| FIPS-провайдер в базе | В дереве illumos — только KMDF-модули OpenSSL (`libkmf/plugins/kmf_openssl`); FIPS-канистра — legacy `openssl-fips` (0.9.8) в illumos-userland | `usr/src/lib/libkmf/plugins/kmf_openssl/` |
| pkgsrc / OpenZFS IPS | pkgsrc в illumos-gate отсутствует (0 путей); OpenZFS IPS-поставка — **не подтверждено** (в illumos ZFS встроен в ядро, см. п. 3.6) | дерево illumos-gate |

**Вывод п. 3.1**: OpenSSL 3.5 / QUIC TLS API в illumos **не подтверждены и маловероятны в «голом»
illumos**; их придётся тащить сборкой из IPS-издателя (Omnipresence-подобного) или самому —
и это отдельный проект, а не «взять из базы».

### 3.2. Механизмы событий

| Факт | Значение | Источник |
|------|----------|----------|
| Event ports — **есть**, нативный API | `port_create`, `port_associate`, `port_dissociate`, `port_alter`, `port_allocate`, `port_get`, `port_getn`, `port_send`, `port_dispatch` | [man3c/port_create.3c](https://github.com/illumos/illumos-gate/blob/master/usr/src/man/man3c/port_create.3c), `port_associate.3c`, `port_get.3c` (описывает `port_get`+`port_getn`), `port_send.3c` (датированы 17.02.2023) |
| Ядро event ports | `usr/src/uts/common/fs/portfs/port.c`, `port_fd.c`, `port_fop.c`, `port_vnops.c` | [fs/portfs](https://github.com/illumos/illumos-gate/tree/master/usr/src/uts/common/fs/portfs) |
| **epoll — есть (!)**, Linux-совместимый | Публичный заголовок `<sys/epoll.h>`, реализация `usr/src/lib/libc/port/sys/epoll.c` (250 стр.), `man3c/epoll_create.3c` / `epoll_ctl.3c` / `epoll_wait.3c`, `man7/epoll.7`, тест `usr/src/test/os-tests/tests/poll/epoll_test.c`, отдельный репозиторий-тест-сьют [illumos/epoll-test-suite](https://github.com/illumos/epoll-test-suite) | ссылки слева |
| На чём построен epoll | **Userland-шим поверх `/dev/poll` (devpoll)**: `epoll.c` включает `<sys/devpoll.h>`, использует `dvpoll_epollfd_t`, `devpoll_ctl()`, `POLLREMOVE` — НЕ нативный kernel epoll | [epoll.c](https://github.com/illumos/illumos-gate/blob/master/usr/src/lib/libc/port/sys/epoll.c) |
| Ограничения epoll (сам illumos предупреждает) | «use of epoll in a multithreaded environment is fraught with peril», гонки с `close(2)`; нативным приложениям предписан event ports | [man7/epoll.7](https://github.com/illumos/illumos-gate/blob/master/usr/src/man/man7/epoll.7) |
| Флаги epoll | Определены `EPOLLET`, `EPOLLONESHOT`, `EPOLLEXCLUSIVE`; ET/ONESHOT транслируются в `POLLET`/`POLLONESHOT` devpoll; **`EPOLLEXCLUSIVE` входит в `EPOLLIGNORED`** (то есть фактически игнорируется) | `usr/src/uts/common/sys/epoll.h` (стр. 60-67), `epoll.c` стр. 60 |
| `/dev/poll` | Есть: `usr/src/head/devpoll.h`, `usr/src/uts/common/sys/devpoll.h`, `usr/src/uts/common/io/devpoll.c`, документ `man4d/poll.4d` | ссылки |
| `poll(2)` | Есть, `man2/poll.2` | ссылка |
| `kqueue` | **Отсутствует** (0 совпадений по дереву) | дерево illumos-gate |

**Вывод п. 3.2**: для ssh3-c epoll-событий **формально доступны** (`<sys/epoll.h>` есть), но это
совместимость поверх devpoll с документированными оговорками по многопоточности. Нативный и
рекомендуемый путь — **event ports**; потребуется отдельный event-backend (`port_associate` +
`port_getn`).

### 3.3. Сокеты

| Факт | Значение | Источник |
|------|----------|----------|
| `SCM_RIGHTS` (передача fd) | **Есть**: `#define SCM_RIGHTS 0x1010` | [sys/socket.h](https://github.com/illumos/illumos-gate/blob/master/usr/src/uts/common/sys/socket.h) стр. 196 |
| Linux-совместимые флаги MSG | Есть `MSG_NOSIGNAL`, `MSG_CMSG_CLOEXEC`, `MSG_CMSG_CLOFORK` | тот же файл, стр. 421-434 |
| `SO_PEERCRED` | **Отсутствует** (0 совпадений) | тот же файл |
| Peer credentials | `getpeerucred(3C)` — есть: `usr/src/lib/libc/port/sys/getpeerucred.c`, `man3c/getpeerucred.3c`, `usr/src/head/ucred.h` | ссылки |
| `TCP_INFO` | **Отсутствует** — в `netinet/tcp.h` его нет. Полный список опций: `TCP_NODELAY, TCP_MAXSEG, TCP_KEEPALIVE, TCP_NOTIFY_THRESHOLD, TCP_ABORT_THRESHOLD, TCP_CONN_NOTIFY_THRESHOLD, TCP_CONN_ABORT_THRESHOLD, TCP_RECVDSTADDR, TCP_INIT_CWND, TCP_KEEPALIVE_THRESHOLD, TCP_KEEPALIVE_ABORT_THRESHOLD, TCP_CORK, TCP_RTO_INITIAL/MIN/MAX, TCP_LINGER2, TCP_ANONPRIVBIND, TCP_EXCLBIND, TCP_KEEPIDLE, TCP_KEEPCNT, TCP_KEEPINTVL, TCP_CONGESTION, TCP_QUICKACK, TCP_MD5SIG`. RTT/cwnd в userspace не отдать | [netinet/tcp.h](https://github.com/illumos/illumos-gate/blob/master/usr/src/uts/common/netinet/tcp.h) стр. 88-142 |
| `UDP_SEGMENT` / GSO / TSO в userspace | **Отсутствует**: в `netinet/in.h` нет ни `UDP_SEGMENT`, ни `UDP_LARGE_SEND`; в `udp_var.h`/`tcp_var.h`/`ip_var.h` нет `gso`/`tso`; TSO/LSO — только внутренние механизмы стека (видны в snoop-тестах `ipv4_tcp_lso_in.snoop`/`ipv4_tcp_lso_out.snoop`), **пользовательского API сегментации нет** | `usr/src/uts/common/netinet/{in.h,udp_var.h,tcp_var.h,ip_var.h}` |
| cmsg/sendmsg/recvmsg | Штатные BSD-сокеты Solaris, `SOL_SOCKET` cmsg работают | `sys/socket.h` |
| `MSG_MAXIOVLEN` | 16 (не 1024) | `sys/socket.h` стр. 438 |

**Вывод п. 3.3**: fd-passing и peer-credentials — есть. **Нет** UDP-сегментации/GSO (для
QUIC-датаграмм придётся фрагментировать самому или терпеть MTU) и **нет** `TCP_INFO`
(наблюдаемость RTT/cwnd — через kstat/`netstat`, не через сокет).

### 3.4. Захват трафика

| Факт | Значение | Источник |
|------|----------|----------|
| `/dev/net/tun`, `/dev/tap` | **Отсутствуют** — 0 совпадений по путям `dev/net|tap|tun` и `tuntap` в дереве illumos-gate | дерево illumos-gate (проверено: `sppptun` — это только PPP-туннель, не TUN) |
| `pktsnoop` | **Отсутствует** в illumos (инструмент OpenSolaris; 0 совпадений) | дерево illumos-gate |
| **snoop(8)** — штатный захват | Реализован через STREAMS-модули **`pfmod(4M)` + `bufmod(4M)`** (в ядре: `usr/src/uts/common/io/pfmod.c`, `bufmod.c`; доки: `man4m/pfmod.4m`, `bufmod.4m`), снимает link-layer кадры через DLPI; выгрузка в **pcap-формат** (в man8/snoop.8 пример `mergecap -w test1.pcap test1-??.snoop`) | [man8/snoop.8](https://github.com/illumos/illumos-gate/blob/master/usr/src/man/man8/snoop.8) |
| snoop как IPS-пакет | `pkg:/network/snoop` — «snoop - capture and inspect network packets» | `usr/src/pkg/manifests/network-snoop.p5m` |
| `ipf` | Есть целиком: `usr/src/cmd/ipf` (+`ipfd`, `ipfs`, `ipfstat`), `man8/ipf.8`; логирование пакетов — штатный режим | `usr/src/cmd/ipf`, `man8/ipf.8` |
| DTrace | Провайдер `ip` присутствует (демо `ip/ipproto.d`, `ip/ipio.d`, `ip/tcpsnoop.d`, `ip/tcprst.d` в `usr/src/cmd/dtrace/demo`) → копирование пакетов в userspace возможно; наличие провайдера `sbuf` — **не подтверждено** | `usr/src/cmd/dtrace/demo/ip/` |
| Итог для workload «съём трафика» | Штатного userspace-TUN нет; варианты: (а) `snoop` — pcap-файлы, (б) `ipf` — лог, (в) DTrace-буферизация. Для «съёма и ретрансляции» в userspace — **нужен собственный STREAMS/драйверный модуль либо ipf-редирект** | — |

**Вывод п. 3.4**: «userspace packet capture + инъекция» на illumos — самая болезненная часть:
нет tun/tap, есть только **пассивный** захват (snoop/ipf/DTrace). Свой «туннель» придётся строить
на STREAMS или на raw-IP сокете (что уже требует привилегий и теряет Ethernet-уровень).

### 3.5. SMF (Service Manager)

| Факт | Значение | Источник |
|------|----------|----------|
| Формат манифеста | XML `service_bundle`, DTD `/usr/share/lib/xml/dtd/service_bundle.dtd.1` | [usr/src/cmd/svc/milestone/network-iptun.xml](https://github.com/illumos/illumos-gate/blob/master/usr/src/cmd/svc/milestone/network-iptun.xml) |
| Путь в поставке | `/usr/smf/manifests/*.xml` (манифесты сервисов), методы-скрипты — `/lib/svc/method/*` | тот же манифест (`exec='&apos;/lib/svc/method/net-iptun %m&apos;`) |
| Ключевые элементы | `<service_bundle type='manifest' name='SUNWcsr:iptun'>` → `<service name='network/iptun' type='service' version='1'>` → `<create_default_instance enabled='true'/>` → `<dependency ... type='service'><service_fmri value='svc:/network/physical'/></dependency>` → `<exec_method type='method' name='start' exec='...' timeout_seconds='600'/>` → `<property_group name='startd' type='framework'><propval name='duration' type='astring' value='transient'/></property_group>` → `<stability value='Unstable'/>` → `<template>` | тот же файл |
| Документация SMF | `man7/smf.7`, `smf_method.7`, `smf_template.7`, `smf_restarter.7`, `smf_bootstrap.7`, `smf_security.7`, `man3scf/smf_enable_instance.3scf` | ссылки |
| Эквивалент rc.d/systemd | `svcadm enable/disable/start/stop`, `svcs`; IPS-манифесты сервисов: `usr/src/pkg/manifests/service-network-ssh.p5m` и др. | дерево illumos-gate |
| systemd **socket activation** | Прямого эквивалента в SMF нет — запуск через `<exec_method>`; приём соединений — либо свой демон, либо `inetd` (`svc:/network/inetd`). **Частично не подтверждено** (детально man7/smf.7 не вычитывал) | — |

**Вывод п. 3.5**: SMF покрывает «юнит/сервис + зависимости + зависимость от сети», но не
покрывает «слушающий сокет, поднимаемый по требованию». Для ssh3-c нужен собственный
accept-цикл либо inetd-обёртка.

### 3.6. ZFS на illumos

| Факт | Значение | Источник |
|------|----------|----------|
| ZFS встроен в ядро illumos | `usr/src/uts/common/fs/zfs` (2635 путей с «zfs» в дереве), IPS `system-file-system-zfs.p5m`, man `usr/src/man/man8/zfs.8` (4886 стр.) | ссылки |
| `zfs send`/`zfs recv` между нодами | **Поддерживается**, в т.ч. по ssh-трубе: пример в man8/zfs.8 — `zfs send pool/fs@a \| ssh host zfs receive poolB/received/fs@a`; также `zfs send -i` (инкрементальный), `zfs receive -d` | [zfs.8](https://github.com/illumos/illumos-gate/blob/master/usr/src/man/man8/zfs.8) (Example 12/13, стр. ~4686-4708) |
| `zfs send -w` (raw) | Есть: «For encrypted datasets, send data exactly as it exists on disk… backup may then be received on an untrusted machine since that machine will not have the encryption keys» | zfs.8 (стр. ~3503, 3618) |
| `zfs send -c` (compressed) | Есть: compressed WRITE records; **требует `lz4_compress` на приёмнике**, иначе данные будут распакованы перед отправкой | zfs.8 (стр. ~3433, 3559) |
| Шифрование | Поддерживается нативно; `zfs receive -o encryption=on -o keyformat=passphrase -o keylocation=file://…` | zfs.8 (стр. ~3894) |
| Делегирование `zfs allow` | Есть: «Delegates ZFS administration permission for the file systems to non-privileged users»; примеры `zfs allow cindys create,destroy,mount,snapshot tank/cindys`, `zfs allow -c destroy tank/users`, `zfs allow -s @pset …` | zfs.8 (стр. 953, 976, 1590, 4761-4825) |
| «recv только в корень пула» | **Не подтверждено** как правило: man показывает `zfs receive poolB/received/fs` (создание dataset по пути) — ограничение «только в корень» в illumos не документировано | zfs.8 |
| `zfs receive` и права | Требует root в общем случае (в man формулировка «Unprivileged users…» есть, но явной фразы «must be run as root» в zfs.8 не нашёл) — **слабо подтверждено** | zfs.8 |
| iSCSI-экспорт ZFS (для «распределённого ZFS») | В базе есть iSCSI target: IPS `network-iscsi-target.p5m`, `network-iscsi-initiator.p5m` | `usr/src/pkg/manifests/` |
| Практики «distributed ZFS» на illumos (NexentaStor, ZFS over iSCSI как appliance) | **Не подтверждено** — проверял: illumos/docs (нет упоминаний), wiki.illumos.org (500), веб-поиск (Bing/DDG отдавали мусор через прокси) | — |

**Вывод п. 3.6**: ZFS-на-illumos вполне годится как «распределённое хранилище» через
`send|recv` по ssh (это ровно тот паттерн, что нужен для репликации сжатых/зашифрованных
потоков), плюс iSCSI-экспорт.

### 3.7. QUIC/TLS-стеки и SSH с QUIC

| Факт | Значение | Источник |
|------|----------|----------|
| OpenSSL QUIC API в illumos | Отсутствует в дереве (нет OpenSSL вообще); в базе IPS — версия не подтверждена | см. п. 3.1 |
| OpenSSH в illumos-org | Репозиторий [illumos/openssh-portable](https://github.com/illumos/openssh-portable): master = **OpenSSH 7.4p1** (`version.h: SSH_VERSION "OpenSSH_7.4"`), ветки V_2_5_2 … V_9_9 (Sun-наследие) | `version.h` |
| SunSSH в базе — помечен устаревшим | IPS-манифесты `network-ssh.p5m` и `service-network-ssh.p5m` содержат `set name=pkg.obsolete value=true` | `usr/src/pkg/manifests/network-ssh.p5m` |
| Реальная версия OpenSSH в illumos 2.11 (через IPS) | **Не подтверждена** (IPS-каталоги недоступны, см. п. 3.1) | — |
| QUIC в OpenSSH illumos | В порте 7.4p1 QUIC нет. Апстрим OpenSSH получил экспериментальный «SSH over QUIC» лишь в ветке 10.x — **не подтверждено источником в этой сессии**, проверять отдельно | — |
| Готовые QUIC-стеки в illumos | Нет ни в дереве, ни в базе IPS (quic/ngtcp2/quiche — 0 совпадений). Переносимы из upstream C, но совместимость не проверялась | дерево illumos-gate |

### 3.8. Сборка

| Факт | Значение | Источник |
|------|----------|----------|
| GCC для illumos | [illumos/gcc](https://github.com/illumos/gcc) — «GCC patched to build illumos», ветка по умолчанию `il-4_4_4` (т.е. 4.4.4 + illumos-патчи), плюс `master` | API репозитория |
| Старые GCC в IPS-издателе | `illumos-userland/components/gcc3` → `COMPONENT_VERSION=3.4.3`; `gcc44` (+gmp/mpc/mpft) | `components/gcc3/Makefile` |
| Сборочные утилиты в базе | IPS-манифесты `developer-build-make.p5m`, `developer-linker.p5m`, `developer-object-file.p5m`; userland: `make`, `binutils`, `automake` | `usr/src/pkg/manifests/`, illumos-userland/components |
| `cmake` | **Есть** как компонент IPS-издателя | `illumos-userland/components/cmake` |
| `pkg-config` | **Не найден** среди компонентов illumos-userland (ни `pkgconfig`, ни `pkg-config`) — не подтверждено как доступный | `illumos-userland/components` (листинг) |
| Oracle Studio | Не подтверждено (в illumos-gate нет; сборка ОС — gcc + Studio для части кода) | — |
| `pthread_rwlock` | Не проверял детально (в illumos есть POSIX rwlocks в libc, но это нужно подтвердить отдельно) | — |

### 3.9. Риски для порта ssh3-c на illumos

1. **QUIC-крипто нет в базе — самый дорогой риск.** В дереве illumos нет OpenSSL; в IPS он
   приходит из отдельного издателя, версия не подтверждена, а `SSL_set_quic_tls_cbs` требует
   OpenSSL ≥3.2 (и 3.5 для нативного QUIC TLS). Значит: либо тянуть и собирать OpenSSL 3.5
   самостоятельно, либо отказываться от OpenSSL QUIC API. Иллюзия «в базе уже есть OpenSSL 3.5»
   — не подтверждена ни одним проверенным источником. *(п. 3.1)*
2. **epoll есть, но это userland-шим поверх `/dev/poll`, а не нативный epoll.** Формально
   `<sys/epoll.h>` есть и `epoll_ctl/epoll_wait` работают, но illumos сам в `man7/epoll.7`
   предупреждает о гонках в многопоточности и о close(2); `EPOLLEXCLUSIVE` объявлен, но
   входит в `EPOLLIGNORED` (игнорируется). Для многопоточного QUIC-сервера — писать отдельный
   backend на **event ports** (`port_associate`/`port_getn`) либо терпеть риски. *(п. 3.2)*
3. **Нет userspace-сегментации UDP и нет `TCP_INFO`.** `UDP_SEGMENT`/GSO отсутствуют в illumos
   целиком (TSO/LSO — только внутренние), `TCP_INFO` нет. Для QUIC-датаграмм (path MTU
   discovery, большие payload'ы) придётся фрагментировать самостоятельно, а наблюдаемость
   cwnd/RTT/keepalive придётся строить на kstat/`netstat` вместо сокетного API. *(п. 3.3)*
4. **Нет TUN/TAP: workload «архивации/съёма трафика» придётся перепроектировать.** Штатные
   варианты — только пассивные: `snoop` (STREAMS pfmod/bufmod, pcap-файлы), `ipf` (лог),
   DTrace-провайдер `ip`. Никакого «захватить в туннель и переслать» из userspace без написания
   собственного STREAMS-модуля или raw-IP сокста. `pktsnoop` (инструмент OpenSolaris) в illumos
   отсутствует. *(п. 3.4)*
5. **SMF не даёт socket activation.** Сервис оформляется манифестом `service_bundle` в
   `/usr/smf/manifests` с `exec_method`/`dependency`/`property_group`, но «слушатель,
   поднимаемый по требованию» придётся реализовывать самому (свой accept-цикл или inetd).
   Дополнительно: SMF-манифесты в поставке пакетов — `pkg.obsolete=true` у SunSSH, значит
   кастомный сервис придётся ставить своим IPS-пакетом. *(п. 3.5)*
6. **Сетевой стек API — BSD/Solaris, а не Linux.** Нет `kqueue` (только event ports + epoll-шим),
   нет `SO_PEERCRED` (нужен `getpeerucred`), `MSG_MAXIOVLEN=16`, `SCM_RIGHTS` есть, но
   `MSG_CMSG_CLOEXEC` — отдельный нестандартный флаг. Весь Linux-специфичный код ssh3-c
   (`SO_REUSEPORT`-семантика, `TCP_INFO`, `UDP_SEGMENT`, `SOCK_NONBLOCK` через `accept4` —
   последний **не проверен**, `epoll` как таковой) потребует слоя абстракции. *(пп. 3.2-3.3)*
7. **Сборочная среда: gcc 4.4.4 (illumos-портированный) вместо современного GCC.** В illumos-org
   доступны ветки `il-4_4_4` и `master` GCC, в legacy-издателе — 3.4.3/4.4.x; `cmake` есть,
   `pkg-config` не найден. Код на C17 с `-std=c17` и современными OpenSSL-фичами может не
   собраться старым GCC без доработки; OpenSSL 3.5 сам по себе требует достаточно нового
   компилятора. *(п. 3.8)*
8. **Риск «неизвестного OpenSSL» — организационный, а не технический.** IPS-каталоги illumos
   (`pkg.illumos.org`) на 2026-10-21 не резолвятся (NXDOMAIN), wiki.illumos.org отдаёт 500,
   `man.illumos.org` недоступен — то есть **версию OpenSSL/OpenSSH в конкретном релизе (2.11 или
   master) подтвердить по первоисточникам не удалось**. Перед любыми работами нужно зафиксировать
   целевую сборку (дистрибутив + репозиторий) и снять `pkg info -r openssl` / `pkg info openssl`
   на целевой ноде — иначе оценка сроков по п. 3.1 будет гаданием. *(пп. 3.1, 3.7)*

---

## 4. Что осталось непроверенным (сводно субагента)

| № | Вопрос | Что проверялось | Статус |
|---|--------|-----------------|--------|
| 1 | Версия OpenSSL/OpenSSH в illumos 2.11 и master | `pkg.illumos.org`, `ips.illumos.org`, `repo.illumos.org`, `wiki.illumos.org`, `man.illumos.org`, `code.illumos.org` | не подтверждено (сеть) |
| 2 | Наличие OpenSSL ≥3.2/3.5 и QUIC API в IPS | дерево illumos-gate (0 совпадений), каталоги IPS | не подтверждено |
| 3 | «Распределённый ZFS» на illumos (NexentaStor и аналоги) | illumos/docs, wiki, веб-поиск | не подтверждено |
| 4 | Точная дата/состав релиза illumos 2.11 | illumos.org без номера версии | не подтверждено |
| 5 | `accept4` / `SOCK_NONBLOCK` | — | не проверено (в ssh3-c не используются) |
| 6 | `pthread_rwlock` | — | не проверено |
| 7 | Наличие Oracle Studio в базе | illumos-gate | не подтверждено |
| 8 | Прайм-тайм ZFS `recv` без `-F` | — | не проверено |
| 9 | Эквивалент socket activation в SMF | man7/smf.7 детально не вычитывался | частично |

---

## 5. Источники и метод

| № | Источник | Что использовано |
|---|----------|------------------|
| 1 | `github.com/illumos/illumos-gate` (master) | рекурсивное дерево API GitHub, raw-файлы, code search: `usr/src/lib/libc/port/sys/epoll.c`, `usr/src/uts/common/sys/epoll.h`, `usr/src/man/man7/epoll.7`, `usr/src/uts/common/fs/portfs/port.c`, `usr/src/man/man3c/port_create.3c`, `usr/src/man/man8/zfs.8`, `usr/src/man/man8/snoop.8`, `usr/src/cmd/svc/milestone/network-iptun.xml`, `usr/src/pkg/manifests/*.p5m` |
| 2 | `github.com/illumos/gcc` | ветки `il-4_4_4` и `master` |
| 3 | `github.com/illumos/illumos-userland` | компоненты `cmake`, `gcc3`, `gcc44`, `openssl` (legacy, заморожен 04.10.2011) |
| 4 | `github.com/illumos/illumos-openssh-portable` → `illumos/openssh-portable` | `version.h` (7.4p1) |
| 5 | `github.com/illumos/epoll-test-suite` | подтверждение наличия epoll-тестов в экосистеме illumos |
| 6 | Локальный репозиторий ssh3-c | `CMakeLists.txt`, `src/event/modules/s3_epoll_module.c`, `src/os/unix/s3_cmsg.c`, `src/ssh3/*`, `app/ssh3_client.c` |

Код-сеarch по illumos-gate, выполненный автором при подготовке §2 (совпадает с выводами субагента):
`port_create` — 76 совпадений; `getpeerucred` — 47; `SSL_set_quic_tls_cbs` — 0;
`OPENSSL_VERSION_TEXT` — 0; `dev/net/tun` — 0; `tuntap` — 0; `OPENSSL_VERSION_NUMBER` — 7
(только потребители заголовков: kmf-плагин, krb5 pkinit, sendmail).
