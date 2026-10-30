# Сосуществование пакетов ssh3
> Languages: RU (this file) · [EN](COEXISTENCE.en.md) · [DE](COEXISTENCE.de.md)

Дата: 2026-10-30. Пункт P8(3) плана ([PLAN.md](PLAN.md) §4): ssh3 — отдельный
пакет **рядом с OpenSSH**, не замена; с ssh3-go — взаимозаменяемость через
этап P8(1) (один пакет заменяет другой, а не соседствует). Этот документ —
контрольная матрица совместной установки и её приёмочная процедура.

## Принцип

| № | Пара | Правило |
|---|------|---------|
| 1 | ssh3 ↔ OpenSSH (ssh2) | сосуществуют всегда: разные бинарники, конфиги, порты, форматы ключей; ничто не наводится друг на друга |
| 2 | ssh3 (C) ↔ ssh3-go (форк) | замена на уровне пакетов: одинаковые имена бинарников и unit-файлов, поэтому соседство одной роли исключено `Conflicts`/`Obsoletes`, а замена идёт через `Replaces`/`Provides` — сторонние программы, вызывающие `ssh3`/`ssh3-server`, не переконфигурируются |

## Что ставит каждый пакет

| № | Файл | Пакет |
|---|------|-------|
| 1 | `/usr/sbin/ssh3-server` | ssh3-server (build.sh deb; debian/ source-пакет ставит `/usr/bin/ssh3-server`) |
| 2 | `/usr/bin/ssh3`, ссылка `/usr/local/bin/ssh3` | ssh3-client |
| 3 | `/etc/ssh3/cert.pem`, `/etc/ssh3/key.pem` (0640 root:ssh3), `/etc/ssh3/authorized_keys` | ssh3-server |
| 4 | `/etc/ssh3/ssh3-server.env` (conffile, `EnvironmentFile`) | только debian/ source-пакет |
| 5 | `/usr/lib/ssh3-c/lib/libssl.so.3`, `libcrypto.so.3` (RUNPATH-бандл) | ssh3c-libssl3 (deb only) |
| 6 | `/usr/lib/systemd/system/ssh3-server.{socket,service}` | ssh3-server |
| 7 | `/usr/share/man/man8/ssh3-server.8`, `/usr/share/man/man1/ssh3.1.gz` | ssh3-server / ssh3-client |

Клиентское состояние живёт в домашнем каталоге пользователя и пакетом не
захватывается: пины сертификатов — `~/.ssh3/known_hosts` (формат
`x509-certificate`), конфиг читается ssh2-совместимым подмножеством через
`-F` (дефолт `~/.ssh/config`) — файл **читается**, но никогда не пишется.

## Матрица совместной установки

| № | Сценарий | Результат | Чем гарантирован |
|---|----------|-----------|------------------|
| 1 | `ssh3` (C-клиент) + OpenSSH `ssh` | сосуществуют | нет пересечений файлов (`/usr/bin/ssh3` против `/usr/bin/ssh`), конфигов (`~/.ssh3` против `~/.ssh`), man (`man1/ssh3.1` против `man1/ssh.1`) |
| 2 | `ssh3-server` (C) + `sshd` | сосуществуют | транспорт: UDP/443 (socket-активация, демон не зовёт `bind()`) против TCP/22; `/etc/ssh3` против `/etc/ssh`; unit-пара `ssh3-server.*` против `sshd.service` |
| 3 | `ssh3-server` (C) + `ssh3-go-server` | исключено пакетно | deb `packaging/deb/control:8-9`, rpm `packaging/rpm/ssh3-server.spec:31-35` (`Obsoletes`), apk `packaging/apk/PKGINFO.in:22-25` |
| 4 | `ssh3-client` (C) + `ssh3-go-client` | исключено пакетно | deb `packaging/deb/client-control:8-9`, rpm `spec:47-49`, apk `PKGINFO-client.in:23-24` |
| 5 | C-клиент + go-сервер (без пакетного конфликта — роли разные) | сосуществуют, wire-совместимы | файлы не пересекаются; интероп-ноги `interop/go-server-channel-e2e.sh`, `interop/go-compat-e2e.sh` |
| 6 | C-сервер + go-клиент | сосуществуют, wire-совместимы | интероп-матрица `interop/run-h3.sh`, `interop/jump-chain-smoke.sh` (форк `1b6872a`) |
| 7 | build.sh deb ↔ debian/ source-пакет | один канал за раз | одно имя пакета `ssh3-server`: два канала сборки — не два пакета; dpkg/apt ставит только один (пути различаются: `/usr/sbin` против `/usr/bin`) |

Историческая заметка (почему пункт 3 устроен заменой, а не соседством):
на интеграции P7 unit-пара была переименована `ssh3-c-server.*` →
`ssh3-server.*` из-за файл-конфликта с уже установленным пакетом
`ssh3-go` — принцип сосуществования P8 проведён на уровне «одна роль —
один владелец имени».

Вне матрицы: метапакеты (`ssh3c`/`ssh3go` для rpm/apk) и подпись
rpm/apk — ждут решения владельца (PLAN-CURRENT.md, «Ждут решения
владельца»).

## Контрольная процедура

Приёмка матрицы на чистом хосте (команды для deb; rpm/apk — в конце):

| № | Проверка | Команда | Ожидание |
|---|----------|---------|----------|
| 1 | пункты 1–2: бинарники рядом | `command -v ssh ssh3 sshd ssh3-server; ssh -V; ssh3 -V` | все присутствуют, версии независимы |
| 2 | пункты 1–2: порты не спорят | `ss -lnt` / `ss -lun` | sshd: TCP/22; ssh3-server: UDP/443 (после enable) |
| 3 | пункты 1–2: конфиги раздельны | `dpkg -L ssh3-server \| grep -c /etc/ssh/` | `0` — пакет ничего не пишет под `/etc/ssh` |
| 4 | пункт 3: замена, не соседство | `apt-get install -s ssh3-server` на хосте с ssh3-go-server | план apt: go-пакет удаляется (`Conflicts`), конфиг `/etc/ssh3` сохраняется |
| 5 | пункт 4: аналогично клиенту | `apt-get install -s ssh3-client` на хосте с ssh3-go-client | план apt: go-клиент удаляется |
| 6 | пункты 5–6: живая cross-нога | `sh interop/go-server-channel-e2e.sh` (C-клиент → go-сервер) | вердикт e2e `OK` |
| 7 | пункт 7: каналы не смешиваются | `dpkg -I` двух deb из `_build` и `_debian` | имя `ssh3-server` у обоих — установка второго вытесняет первый |

rpm: `rpm -q --conflicts ssh3-server`, `rpm -q --obsoletes ssh3-server`
(ожидание: обе пары ssh3-go-*); apk: строки `conflicts`/`replaces` в
`apk info` установленного пакета.

## Отсылки

- Разбор канона сплита и размещение файлов — `packaging/README.md`
  (§ The packages, § Debian source package).
- Матрица отклонений CLI от ssh(1)/sshd(8) — `docs/CLI-COMPAT.md`.
- Политика безопасности (куда сообщать, CVE-процедура) — `SECURITY.md`.
