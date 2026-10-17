# Сверка ключей запуска: канон ssh2 (OpenSSH) · отклонения ssh3-go и ssh3-c

Этап P8(1) «Совместимость запуска», решение Пилота 2026-10-17: **при
совпадении функционала ключи запуска соответствуют OpenSSH (ssh2)** —
ssh(1) для клиента, sshd(8) для сервера. Оба проекта — ssh3-go (форк
0.1.35) и ssh3-c — сверяются на отклонения от канона; где функционала в
ssh2 нет (QUIC, HTTP/3-маршрут, TLS-пара, OIDC, forward udp) — формы
проектные, паритет не требуется.

Источники: ssh3-go — `cmd/ssh3-server.go`, `cmd/ssh3.go`,
`cmd/cli_flags.go` (nagual2/ssh3, main); ssh3-c — `app/ssh3_server.c`
(getopt `l:c:k:A:d:i:L:P:H:K:3vVh` + длинные флаги), `app/ssh3_client.c`
(getopt `i:U:J:L:R:o:rMl:e:O:vXVh`); OpenSSH 9.x — ssh(1)/sshd(8).

> Languages: RU (этот файл) · EN · DE — переводы волной i18n этапа P8(1).

Обозначения: ✓ — совпадает с ssh2; ✗ — отклонение (форма/имя); ⛔ — ключ
**занят** другой семантикой (конфликт: скрипт ssh2 ломается молча или с
чужим эффектом); — — функционала нет. Отклонение помечено владельцем:
Go / C / оба.

## 1. Клиент против ssh(1)

| № | Функционал | ssh2 канон | ssh3-go | ssh3-c | Владелец отклонения |
|---|------------|-----------|---------|--------|---------------------|
| 1 | identity-файл | `-i` | ✗ `-privkey` | ✓ `-i` | Go |
| 2 | порт | `-p port` | ✗ `-P` (только в `-f`-режиме) | ✗ нет (порт в операнде `host:port`) | оба |
| 3 | агент-форвард | `-A` | ✗ `-forward-agent` | ⛔ `-X` занят агентом (у ssh2 `-X` — X11) | оба |
| 4 | X11 | `-X/-x/-Y` | — | ⛔ `-X` занят агентом | оба (нет фичи; C держит чужой ключ) |
| 5 | локальный форвард | `-L [bind:]port:host:hostport` | ✗ нет `-L`; `-forward-tcp localport/remoteip@remoteport` | ✗ `-L tcp\|udp://[bind:]port/host/port` | оба (форма) |
| 6 | reverse-форвард | `-R [bind:]port:host:hostport` | ✗ `-R` repeatable, своя форма | ✗ `-R [bind:]port[/tcp\|/udp]:host:port` | оба (udp-расширение легитимно, базу сверить) |
| 7 | SOCKS-форвард | `-D [bind:]port` | ✓ `-D` | — | C |
| 8 | без сессии | `-N` | ✓ `-N` | — | C |
| 9 | подсистема | `-s` | ✓ `-s` | — (sftp через `-J`) | C |
| 10 | pty | `-t` / `-T` | ✓ / ✓ | — (pty автоматом) | C |
| 11 | конфиг | `-F file` (`~/.ssh/config`) | ✓ `-F` | — | C |
| 12 | jump host | `-J user@host[:port]` | ✗ `-proxy-jump` | ⛔ `-J` занят sftp-трансфером | оба |
| 13 | логин | `-l user` | ✗ нет (только `user@` операнд) | ⛔ `-l` занят уровнем лога | оба; C — конфликт ключа |
| 14 | escape-символ | `-e char` / `-o EscapeChar` | ✓ `-o EscapeChar` | ⛔ `-e` занят slave-командой CM | C — конфликт ключа |
| 15 | ctl master | `-M` + `-S path` + `-o ControlMaster/ControlPath/ControlPersist` | ✗ `-control-master/-control-path/-control-persist` | `-M` ✓; ⛔ путь сокета через занятый `-U` | Go — формы; C — `-S`-аналог |
| 16 | ctl ops | `-O check\|stop\|exit\|cancel` | ✓ `-O check\|stop\|exit` | ✓ `-O check\|stop\|exit` | — |
| 17 | версия | `-V` | ✗ `-version` | ✓ `-V` | Go |
| 18 | quiet | `-q` | — | — | оба |
| 19 | семейство адресов | `-4` / `-6` | — | — | оба |
| 20 | фон (background) | `-f` | ⛔ `-f` занят режимом передачи | — | Go — конфликт ключа |
| 21 | stdin `/dev/null` | `-n` | — | — | оба |
| 22 | ключи `-o` | ~100 ключей ssh_config | частично: EscapeChar ✓, VerifyHostKeyDNS ✓, StrictHostKeyChecking | ✗ только `insecure` (не ssh2-ключ), `strict-host-key-checking` ✓ | оба; добор: ForwardAgent, Port, User, IdentityFile, LocalForward, RemoteForward, DynamicForward, ProxyJump, EscapeChar |
| 23 | пароль | tty-промпт (без флага) | ✗ `-use-password` | ✗ `-U user:pass` (двойное использование: Basic / сокет CM) | оба (HTTP-специфика; без tty-промпта) |

## 2. Сервер против sshd(8)

| № | Функционал | ssh2 канон | ssh3-go | ssh3-c | Владелец отклонения |
|---|------------|-----------|---------|--------|---------------------|
| 1 | порт | `-p port` | ✗ `-bind [::]:443` (адрес+порт слиты) | ✗ `-l addr:port` (слиты) | оба; у ssh3 адрес нужен (QUIC) — добавить `-p` как порт-алиас |
| 2 | host key | `-h keyfile` | ✗ `-key` | ⛔ `-k`; `-h` занят help | оба; C — конфликт `-h` |
| 3 | host certificate | `-c file` | ✗ `-cert` | ✓ `-c` (TLS-серт, семантика близка) | Go |
| 4 | конфигурация | `-f config` | ✗ env-файл deb | ✗ только env-переменные | оба |
| 5 | debug/лог | `-d`, `-E file`, `-e` | ✗ `-v` | ✗ `-v`, `-L level` | оба (без прямого маппинга, приемлемо) |
| 6 | foreground/inetd | `-D`, `-i` | systemd-юнит | systemd socket-activation (расширяет канон) | — |
| 7 | test-режимы | `-t` / `-T` / `-G` | — | — | оба |
| 8 | PermitOpen | `-o PermitOpen=…` | флаг `-permit-open` + env | флаг `--permit-open` + env | форма; синтаксис spec совпадает |
| 9 | PermitListen | `-o PermitListen=…` | флаг `-permit-listen` | — | C — лакуна |
| 10 | GatewayPorts | `-o GatewayPorts=…` | флаг `-gateway-ports` | — | C — лакуна |
| 11 | MaxStartups | `-o MaxStartups=…` | `-max-unauth-conversations` | `--max-unauth-conversations` | форма |
| 12 | AuthorizedKeysFile | `-o AuthorizedKeysFile=…` | `--authorized-identity` (файл цепочки) | `-K authorized_keys` (+env) | форма (оба) |
| 13 | ChrootDirectory | `-o ChrootDirectory=…` | `-sftp-jail`/`-sftp-chroot` | `-H`/`--sftp-jail` | форма |
| 14 | версия | sshd без CLI-`-V` | `-version` | `-V` | неканонично — оставить |

Серверные лимиты Go без ssh2-аналога: `-max-reverse-forwards`,
`-max-channels-per-conversation`, `-max-sftp-sessions-per-user`,
`-max-connections`, `-max-idle-timeout`, `-handshake-idle-timeout`,
`-max-incoming-streams`, `-max-incoming-uni-streams` (ssh3-специфика; у C
те же лакуны, см. таблицу 3).

## 3. SSH3-специфика (ssh2-аналога нет, паритет не требуется)

| № | Функционал | ssh3-go | ssh3-c | Примечание |
|---|------------|---------|--------|------------|
| 1 | HTTP/3-маршрут | `-url-path` | `--url-path` | дефолт `/ssh3-term` совпадает |
| 2 | TLS-пара (клиент QUIC-стека) | `-cert/-key` (сервер) | `-c/-k` | канона ssh2 нет (sshd -h — ближайший смысл) |
| 3 | OIDC | клиент: `-use-oidc`, `-oidc-config`, `-no-pkce`; сервер: нет | сервер: `--oidc-*`; клиента: нет | зеркальные лакуны |
| 4 | bearer-ключи | `--authorized-identity` | `-K` (repeatable, `%u`) | |
| 5 | pass-файл | `-use-password`/env | `-P pwfile` | |
| 6 | sftp-jail | `-sftp-jail chroot\|lexical` | `--sftp-jail chroot\|lexical` | значения совпадают |
| 7 | передача файлов | `-f`+операнды, `-r`, `-continue`, `-checksum` | `-J put\|get:local:remote`, `-r` | формы не унифицированы |
| 8 | QUIC-транспорт | `-stream-rx-mb`, `-conn-rx-mb`, `-initial-packet-size`/`-packet-size` | `-d dg_size`, `-i idle_ms`, `-A alpn` | |
| 9 | окно drain/лог | env `SSH3_SHUTDOWN_DRAIN`, `SSH3_LOG_*` | те же env ✓ | совпадает |
| 10 | setuid-модель | — (дети под юзером) | `--run-as-user on\|off` | C-надмножество |
| 11 | `-keylog`, `-proxy-jump` | есть | нет | заморожено соседствует с №4/№6 §8 |

## 4. Сводка зеркальности

Объединение флагов двух проектов почти покрывает ssh2-канон: у Go есть
`-D -N -s -t -T -F`, у C — `-i -V -M -O`; расхождения зеркальны. Жёсткие
конфликты занятых ключей — только у C (`-J`, `-e`, `-l`, `-X`, `-h`) и у
Go (`-f`); их скрипты ssh2 ломают молча — приоритет №1.

## 5. План приведения к канону (оба проекта)

1. **Волна A — развести занятые ключи:** C: `-J`→jump (трансферу новое
   имя), `-e`→escape (slave-режим переименовать), `-l`→логин (уровень
   лога переехать), `-X`→X11 или изъять (агенту `-A`), сервер `-h`→host
   key (help переехать); Go: `-f`→background или изъять (трансферу новое
   имя). Решение Пилота по каждому.
2. **Волна B — добор отсутствующих ssh2-ключей:** C: `-D -N -s -t -T -F
   -p -A -q -4/-6` + ключи `-o`; Go: `-i -V -M -S -q -4/-6` + ключи `-o`.
3. **Волна C — формы уже имеющихся:** `-L`/`-R` к ssh2-синтаксису (udp —
   расширением поверх), порт сервера `-p`, host key `-h`, jump `-J`,
   ctl `-S`/`-o Control*`; у Go — `-i/-V/-A/-J/-L` вместо проектных имён.
4. **Волна D — заморожено:** клиентский OIDC, `proxy-jump`, `keylog`,
   окна flow-control (№4/№6 §8).

Пакетная взаимозамена ssh3-go ↔ ssh3-c (`Conflicts`/`Replaces`) сохраняет
смысл: после волн A–C скрипты, написанные под любой из трёх бинарников,
ведут себя одинаково.
