# packaging — дистрибутивные пакеты для ssh3-server
> Languages: [EN](README.md) · RU (this file) · [DE](README.de.md)

Собирает дистрибутивные пакеты для демона `ssh3-server` из бинарника
`build/linux-release/ssh3-server` (при отсутствии собирается по требованию
через пресет `linux-release`).

## Структура

| Path | Contents |
|------|----------|
| `build.sh` | the orchestrator: `bash packaging/build.sh [deb\|rpm\|apk\|all]` |
| `deb/` | debian control, postinst, copyright payloads |
| `rpm/` | rpm spec template (`@VERSION@` substituted from the binary) |
| `apk/` | apk-tools v2 `.PKGINFO` template |
| `openwrt/` | openwrt feed makefile (built inside the openwrt SDK, not here) |
| `_build/` | final packages (gitignored, never committed) |

## Использование

```
bash packaging/build.sh          # deb + rpm + apk
bash packaging/build.sh deb      # one format at a time
```

Staging выполняется под `/tmp` и автоматически очищается: dpkg-deb и rpm
требуют настоящих POSIX-прав на файлы, которые checkout через windows drvfs
(`/mnt/c`, всё 0777) обеспечить не может. В `packaging/_build/` попадают
только итоговые пакеты.

Версия пакета берётся из самого демона (`ssh3-server -V`); `deb/control`
содержит её буквально, а `build.sh` сверяет её с бинарником. Шаблоны rpm/apk
подставляются на этапе сборки.

## Матрица целевых платформ (OpenSSL >= 3.5 с QUIC TLS API)

| Target | OpenSSL 3.5 in the base repo | Bundled? | Notes |
|--------|------------------------------|----------|-------|
| Debian 13 (trixie) | yes (3.5.x) | deb ships it | primary deb target; the bundle loads even here (RUNPATH wins) |
| Mint 22.x / Ubuntu 24.04 | no (3.0.13) | deb ships it | the bundle is the point - the deb installs as-is |
| Alpine 3.22 | yes | no | apk needs a musl build; bundle port is backlog |
| Fedora | <= 42: no (3.0/3.2), 43+: yes | no | rpm keeps the system-openssl scheme; bundle port is backlog |

## OpenSSL в bundle (deb)

Демон общается через QUIC TLS API OpenSSL 3.5, но mint 22.x и ubuntu 24.04
(целевые платформы установки deb) до сих пор поставляют 3.0.x. Поэтому
пакет встраивает пару разделяемых библиотек:

- источник — официальный пакет Debian 13 (trixie) `libssl3t64`
  (на момент написания — 3.5.7, URL зафиксирован в `build.sh`),
  скачивается через curl/wget и распаковывается `dpkg-deb -x`, кэшируется
  в `packaging/_build/cache/`;
- обе библиотеки (`libssl.so.3`, `libcrypto.so.3`, mode 0644, root)
  в ходе staging попадают в приватный каталог `/usr/lib/ssh3-c/lib/` —
  без изменений; системный `libssl` не требуется и не затрагивается;
- бинарник после staging несёт `RUNPATH=/usr/lib/ssh3-c/lib`
  (patchelf, обязательно): RUNPATH разрешается раньше путей по умолчанию,
  поэтому bundle побеждает только для этого бинарника. В глобальные пути
  линкера ничего не просачивается, и никакой другой бинарник не подхватит
  приватную пару.

Порядок разрешения источника bundle (шаг fetch-bundle):

1. `LIBSSL_SRC` — путь к файлу `.deb`, deb-URL или каталогу с локальной
   сборкой OpenSSL (в самом каталоге, `lib/`, `lib64/` ищутся
   `libssl.so.3`/`libcrypto.so.3`);
2. `LOCAL_OPENSSL_DIR` — то же переопределение каталога, в старой записи
   (оставлен как fallback без сети);
3. кэш (`packaging/_build/cache/`), затем зафиксированный
   deb.debian.org URL.

Неудачная загрузка фатальна — с инструкциями в сообщении. Без сети
передайте `LIBSSL_SRC=<local deb, url or build dir>` (или
`LOCAL_OPENSSL_DIR=<build dir>`). Если переопределение — локальная сборка,
библиотеки собраны не Debian — их версия и опции сборки тогда на совести
вызывающего (демону нужен QUIC TLS API 3.5).

Почему bundle, а не статическая линковка или системная зависимость:

- статическая линковка отвергнута владельцем дизайна (большая поверхность
  diff/пересборки на каждый релиз; история с NSS-модулем в обеих схемах
  не трогается, bundle просто проще);
- системная зависимость (`libssl3t64 (>= 3.5)`) не может выразить «в
  trixie есть, в noble нет» одной строкой `Depends` без собственного
  apt-репозитория — bundle решает это с нулём репозиториев.

Примечание: если в системе уже есть OpenSSL 3.5 (Debian 13), bundle
всё равно загружается (RUNPATH важнее путей по умолчанию). Это сделано
намеренно — поставляемая пара протестирована и заведомо рабочая (3.5.x).

`Depends` у deb повторяет список NEEDED пары bundle:
`libc6, zlib1g, libzstd1, adduser` (libcrypto нужны zlib и zstd;
libcrypt поставляется с libc6). Системный `libssl3t64`/`libssl3` больше
не упоминается.

Backlog: перенос той же схемы (приватный каталог + RUNPATH) на payload
пакетов rpm и apk отслеживается отдельно; оба по-прежнему вырезают RUNPATH
сборки и ожидают системный OpenSSL 3.5.

## Известные ограничения

1. Бинарник из build-дерева линкуется с разработческим OpenSSL 3.5
   (`~/opt/openssl-3.5`) и несёт его RUNPATH. deb заменяет этот RUNPATH
   на приватный путь bundle (patchelf, обязательно) и поставляет пару
   bundle — см. «OpenSSL в bundle (deb)»; rpm и apk по-прежнему вырезают
   RUNPATH и требуют системный OpenSSL 3.5.
2. Пакет apk собирается вручную (два склеенных потока tar.gz,
   apk-tools v2); настоящий пакет alpine нужно собирать под musl внутри
   окружения alpine — поставляемый бинарник слинкован с glibc.
3. Ни apk, ни rpm не подписаны (ключа подписи в дереве нет);
   неподписанные пакеты apk ставятся через `apk add --allow-untrusted`.
4. openwrt ipk — заглушка в виде feed makefile: ему нужен openwrt SDK с
   OpenSSL >= 3.5 (openwrt main; ветки 24.10/23.05 несут 3.0.x).
5. Подключение systemd unit (блок интеграции в deb postinst) появится на
   шаге интеграции, источник — `packaging/systemd/`.
