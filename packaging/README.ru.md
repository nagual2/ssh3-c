# packaging — дистрибутивные пакеты для ssh3
> Languages: [EN](README.md) · RU (this file) · [DE](README.de.md)

Собирает дистрибутивные пакеты для демона `ssh3-server` и клиента `ssh3`
из бинарников `build/linux-release/` (при отсутствии собираются по требованию
через пресет `linux-release`).

## Структура

| Path | Contents |
|------|----------|
| `build.sh` | the orchestrator: `bash packaging/build.sh [deb\|rpm\|apk\|all]` |
| `deb/` | debian control, postinst, copyright payloads |
| `rpm/` | rpm spec template: пакеты `ssh3-server` и `ssh3-client` (`@VERSION@` substituted from the binary) |
| `apk/` | apk-tools v2 шаблоны `.PKGINFO`: `PKGINFO.in` (сервер) и `PKGINFO-client.in` (клиент) |
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
подставляются на этапе сборки. Клиентская половина сверяется тоже: `ssh3 -V`
называет свою версию (`ssh3 version SSH 3.0 ssh3-c X.Y.Z ...`), и `build.sh`
отказывается паковать клиент, чья версия отличается от версии демона — две
половины выходят одним релизом.

## Пакеты

Расщепление по канону openssh и по исходному debian-пакету
(`debian/control`): демон и CLI — два пакета одной версии; клиенту
безсерверного хоста демон не нужен, демону клиент тоже.

| Формат | Пакеты | Состав клиентской половины |
|--------|--------|-----------------------------|
| deb | `ssh3-server`, `ssh3-client`, `ssh3c-libssl3` | `/usr/bin/ssh3`, `ssh3(1)` |
| rpm | `ssh3-server`, `ssh3-client` (одна спека, два пакета) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |
| apk | `ssh3-server`, `ssh3-client` (два шаблона `.PKGINFO`) | `/usr/bin/ssh3`, `/usr/share/man/man1/ssh3.1.gz` |

rpm-спека собирает оба пакета за один прогон `rpmbuild`: демон — главный
пакет (`%{_sbindir}/ssh3-server`), клиент — подпакет `%package -n ssh3-client`
(`%{_bindir}/ssh3` и man-страница). Танец с drop-in заменой против go-форка
повторяет deb-сторону: клиент конфликтует с (и вытесняет) `ssh3-go-client`,
демон — с обоими, `ssh3-go-client` и `ssh3-go-server`.

Man-страница клиента — тот же файл, который ставит исходный debian-пакет:
`debian/ssh3.1` (mdoc). Отдельного шаблона для apk нет — страница
упаковывается в payload пакета.

Архитектура rpm и apk берётся из переключателя `ARCH` в `build.sh`
(`amd64` -> x86_64, `arm64` -> aarch64); сами arm64-бинарники — пункт B7
плана.

## Пакет apk (APKv2)

Пакет apk — два склеенных gzip-потока: control-сегмент (`.PKGINFO`) и
data-сегмент (payload). Две детали неочевидны и проверены на настоящем
apk-tools (2.14, контейнер alpine 3.22):

1. tar обоих сегментов — POSIX ustar (`tar --format=ustar`): у apk-tools
   свой парсер tar, и GNU-формат (магия `ustar  `) он отвергает с
   «BAD archive»;
2. control-сегмент НЕ должен нести маркер конца архива tar (две пустые
   шапки): apk-tools v2 разбирает control-сегмент с маркером неверно и
   отвергает весь пакет с «BAD archive» — alpine-пакеты обрезают маркер
   так же, их сегмент кончается сразу после записи `.PKGINFO`. `build.sh`
   срезает маркер через `truncate`.

data-сегмент маркер сохраняет (там apk его терпит). В шаблоне control есть
и плейсхолдер `@APKARCH@` — подставляется из того же переключателя `ARCH`,
что и в rpm.

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
   окружения alpine — поставляемый бинарник слинкован с glibc. Формат
   проверен: `apk verify` принимает оба пакета, `apk add --allow-untrusted`
   их ставит (файлы ложатся на место); зависимость `so:libssl.so.3` в
   голом alpine-контейнере не разрешается (alpine 3.22 дробит библиотеку
   на `libssl3`/`libcrypto3`), поэтому apk считает по одной неразрешённой
   зависимости на пакет — ровно как у старого серверного пакета.
3. Ни apk, ни rpm не подписаны (ключа подписи в дереве нет);
   неподписанные пакеты apk ставятся через `apk add --allow-untrusted`.
4. openwrt ipk — заглушка в виде feed makefile: ему нужен openwrt SDK с
   OpenSSL >= 3.5 (openwrt main; ветки 24.10/23.05 несут 3.0.x).
5. Подключение systemd unit (блок интеграции в deb postinst) появится на
   шаге интеграции, источник — `packaging/systemd/`.
