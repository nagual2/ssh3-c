# PKI-утилиты: ssh3-cert и ssh3-ca — подробное руководство с примерами
> Languages: RU (this file) · [EN](PKI-TOOLS.en.md) · [DE](PKI-TOOLS.de.md)

Дата: 2026-11-20. Волна 19 ([PLAN.md](PLAN.md) §19): `ssh3-cert` несёт
одношаговые операции PKI-жизни вне постоянно запущенного демона,
`ssh3-ca` — собственный центр сертификации одной инсталляции (корень,
выпуск, отзыв, ротация). Обе утилиты собираются из тех же исходников
что демон и клиент, единственная зависимость — libcrypto/OpenSSL 3.5+.

## Обзор: кто для чего

| № | Утилита | Зона ответственности |
|---|---------|----------------------|
| 1 | `ssh3-cert` | одношаговые операции: генерация ключа (`keygen`), заявка на сертификат (`csr`), докачка траст-набора (`trust-update`), ключ сессионных тикетов (`ticket-key`), диагностический снимок (`probe`) |
| 2 | `ssh3-ca` | центр сертификации: инициализация корня (`init`), выпуск серверных (`sign-server`) и клиентских (`sign-client`) сертификатов из CSR, отзыв с CRL (`revoke`), ротация корня (`rotate`) |

Типовой поток: `ssh3-cert keygen` → `ssh3-cert csr` → `ssh3-ca
sign-server` → демон потребляет готовые файлы.  Утилиты не общаются
между собой по сети — их посредник это файловая система.

## Состояние CA: раскладка каталога

`ssh3-ca` живёт в одном каталоге — `SSH3_CA_DIR` или `~/.ssh3/ca`:

| № | Файл | Что | Права |
|---|------|-----|-------|
| 1 | `ca.key` | приватный корневой ключ (ed25519) | `0600` |
| 2 | `ca.pem` | самоподписанный корневой сертификат, 10 лет, `O=ssh3-c/CN=ssh3-ca` | `0644` |
| 3 | `index` | плоская книга выпусков: `serial|type|subject|notafter|status` (`V` жив, `R` отозван) | `0600` |
| 4 | `crl.pem` | список отозванных, подписан корнем; появляется после первого `revoke` | `0644` |

Пример после выпуска пары сертов:

```text
$ ls -la ~/.ssh3/ca/
-rw------- 1 max max  119 Nov 20 18:33 ca.key
-rw-r--r-- 1 max max  489 Nov 20 18:33 ca.pem
-rw------- 1 max max   82 Nov 20 18:33 index
$ cat ~/.ssh3/ca/index
1eea69181eb1b6c0|C|/CN=alice|1734765900|V
```

## Инициализация корня

```text
$ ssh3-ca init ~/.ssh3/ca
the CA state of ~/.ssh3/ca rides: ca.key + ca.pem + index
```

Повторный `init` на существующем состоянии **отказывается** — корень
никогда не перезаписывается молча:

```text
$ ssh3-ca init ~/.ssh3/ca
ssh3-ca: the state of ~/.ssh3/ca was not created (an existing ca.key declines)
```

Корень — ed25519, срок 10 лет, расширения: `basicConstraints=critical,
CA:TRUE`, `keyUsage=critical,keyCertSign,cRLSign`, `subjectKeyIdentifier`.

## Серверный сертификат: полный поток

### Шаг 1 — ключ и CSR сервера

```text
$ ssh3-cert keygen srv.key rsa
the key rides: srv.key (rsa2048)
$ ssh3-cert csr srv.key srv.csr myserver dns:myserver.lan,dns:alt.lan,ip:192.0.2.10
the csr rides: srv.csr (CN=myserver, SAN DNS:myserver.lan,IP:192.0.2.10)
```

Формы SAN: `dns:` имя, `ip:` адрес, `email:` почта — через запятую.
`keygen` без аргумента даёт ed25519; слово `rsa` — RSA 2048.

### Шаг 2 — выпуск

```text
$ ssh3-ca sign-server srv.csr srv.pem
sign-server issued: srv.pem (serial 0e7f224314e4235f)
```

`srv.pem` — цепочка (лист + корень) прямо пригодная демону: SAN берётся
из заявки, срок 825 дней, issuer — корень CA, расширения
`basicConstraints=critical,CA:FALSE`, `keyUsage=digitalSignature`,
`extendedKeyUsage=serverAuth`, `authorityKeyIdentifier`.

### Шаг 3 — демон

```text
$ ssh3-server -3 -l 0.0.0.0:443 -c srv.pem -k srv.key -K authorized_keys
[info] ssh3-server version 0.5.21 listening on :::443
```

Клиент доверяет паре одним из способов:

- **пин листа** — `known_hosts`-канал работает всегда (`-o
  StrictHostKeyKey=accept-new` на первом контакте и дальше обычный пин);
- **доверие корню** — корень CA в траст-наборе клиента (политика
  `system` с `SSL_CERT_FILE`, или файл-надстройка `~/.ssh3/ca-bundle.pem`
  в политике `own` — механика волны 14).

## Клиентский сертификат: полный поток

### Шаг 1 — ключ и CSR пользователя

```text
$ ssh3-cert keygen alice.key
the key rides: alice.key (ed25519)
$ ssh3-cert csr alice.key alice.csr alice
the csr rides: alice.csr (CN=alice)
```

SAN заявки не обязателен: маппинг пользователя читает **CN**; для
безпарольных учётных записей полезнее SAN — `email:alice@corp.test`
или `spki:...` (механика фазы 3, `s3_ssh3_auth_cert_user()`).

### Шаг 2 — выпуск от CA

```text
$ ssh3-ca sign-client alice.csr alice.pem alice
sign-client issued: alice.pem (serial 072c89023b0b534b)
```

CN заявки замещается аргументом `user` (последний аргумент), срок 398
дней, `extendedKeyUsage=clientAuth`.

### Шаг 3 — демона с требованием клиентского сертификата

```text
$ ssh3-server -3 -l 0.0.0.0:8443 -c srv.pem -k srv.key \
    --run-as-user off \
    --client-cert-ca ca/ca.pem --client-cert require
```

- `--client-cert-ca` — файл якорей для верификации клиентской цепочки
  (наш корень CA);
- `--client-cert require|optional|none` — политика (дефолт `none` —
  совместимость);
- `--run-as-user off` — спавн без локальной учётной записи: юзер
  узнаётся из сертификата (механика фазы 3, живая приёмка в
  [PLAN.md](PLAN.md) §14).

### Шаг 4 — диал клиента

```text
$ ssh3 -insecure -o TrustStore=system --cert alice.pem --key alice.key \
    "alice@server.lan:8443/ssh3-term"
```

- `--cert`/`--key` — пара клиентского сертификата (цепочка
  `alice.pem`: лист + корень);
- `SSL_CERT_FILE=ca/ca.pem` вместо `-o TrustStore=system` — тот же
  якорь через переменную (тест-крюк и явный путь одновременно);
- `-insecure` здесь снимает только проверку **самоподписанного**
  серверного серта вне корня — якорь CA при политике `system` работает
  штатно.

Вердикт сервера: сертификат валиден → user = CN (alice) → сессия.  Без
сертификата при `require` — отказ на хендшейке.  Чужой сертификат
(не от нашего корня) — `401`, в журнале вердикт `err 18`.

## Отзыв: revoke и CRL

```text
$ ssh3-ca revoke alice.pem
revoked: alice.pem (crl.pem regenerated)
```

Аргумент — файл выданного сертификата **или** serial из вывода
`sign-*` (или из `index`).  После отзыва:

- строка в `index` помечается `R`;
- `crl.pem` перегенерируется и подписывается корнем.

Проверка средствами OpenSSL (независимый прибор):

```text
$ openssl verify -crl_check -CAfile ca/ca.pem -CRLfile ca/crl.pem alice.pem
error 23 at 0 depth lookup: certificate revoked
error alice.pem: verification failed
```

**Граница v1:** сервер пока не проверяет CRL на диале — энфорсмент
на стороне демона и публикация CRL по сети — следующий инкремент
([PLAN.md](PLAN.md) §19, задокументировано).  Отзыв сейчас — запись в
книге CA и готовый CRL для инфраструктуры.

Отзыв несуществующего serial отказывается, состояние не трогает:

```text
$ ssh3-ca revoke ffffffffffffffff
ssh3-ca: the revoke of ffffffffffffffff declined (the serial is unknown or the state is frozen)
```

## Ротация корня

```text
$ ssh3-ca rotate
the CA rotated: the old state backs aside, 2 cert(s) need the re-issuance
```

Весь старый каталог отъезжает в `~/.ssh3/ca.old.<unix-epoch>`, свежий
корень встаёт на его место.  Серты старого корня требуют пере-выпуска
(другой issuer) — инструмент печатает счётчик; `~/.ssh3/ca.old.*/`
остаётся у оператора как архив.  Это осознанная форма v1: «плавная»
ротация с двумя живыми корнями — следующий инкремент.

## ssh3-cert: остальные команды

### trust-update — докачка траст-надстройки

```text
$ ssh3-cert trust-update
```

Тихо качает траст-набор (по умолчанию Mozilla-набор curl.se),
проверяет каждый PEM-блок и атомарно кладёт
`~/.ssh3/trust-bundle.pem` поверх зашитых корней; манифест рядом
носит источник и SHA-256; любой отказ оставляет прошлую копию (офлайн
прогон шедулера — норма).  Exit 0 — свежий набор, 255 — устаревший.
Шедулер: systemd user-юниты `ssh3-trust-update.{service,timer}`
(deb/openwrt) или задача планировщика на win (ман).  Подробно —
[PLAN.md](PLAN.md) §14, фаза 1c.

### ticket-key — ключ сессионных тикетов до первого старта

```text
$ ssh3-cert ticket-key /etc/ssh3/session-ticket.key
```

Генерирует 80-байтный файл (16 name + 32 HMAC + 32 AES, `0600`) —
пред-посеянный ключ переживает первый lifetime демона и делает
reconnect-тикет стабильным с первого запуска.

### probe — диагностический снимок

```text
$ ssh3-cert probe
[info] the embedded ISRG roots ride the store (109 added)
```

Печатает версию OpenSSL и счётчики траст-сторов (own/system) — без
диала и сети.

## Окружение и интеграция

| № | Переменная | Что |
|---|------------|-----|
| 1 | `SSH3_CA_DIR` | каталог состояния CA (по умолчанию `~/.ssh3/ca`) |
| 2 | `SSL_CERT_FILE` / `SSL_CERT_DIR` | якоря политики `system` (проверено стандартным OpenSSL-крюком) |
| 3 | `S3_TRUST_BUNDLE` | тест-крюк пути надстройки (только юниты) |

Пакеты: deb-канал `ssh3-client-bundle` несёт `/usr/bin/ssh3-cert` и
`/usr/bin/ssh3-ca` с man-страницами; openwrt — обёртки
`/usr/bin/ssh3-{cert,ca}` поверх бандл-каталога; Windows —
`ssh3-cert.exe` в релизных ассетах рядом с `ssh3.exe` (обновляется
вместе с клиентом с волны 19).

Открытые границы v1 (задокументированы в [PLAN.md](PLAN.md) §19):
CRL-энфорсмент на сервере, публикация CRL, плавная ротация с двумя
корнями, пароль на `ca.key`.  Формат v1-состояния стабилен — будущие
инкременты читают те же файлы.
