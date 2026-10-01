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

## Стиль кода

- `.clang-format` / `.clang-tidy` — в корне; проверка:
  `clang-format --dry-run --Werror src/core/*.c src/core/*.h tests/*.c`.
- Сборка идёт с `-Wall -Wextra -Werror`; пресет `linux-asan` добавляет
  `-fsanitize=address,undefined -fno-sanitize-recover=all`.

## Лицензия

Собственный код — BSD 2-clause (`LICENSE`). Код, адаптированный из nginx
(BSD 2-clause), перечислен в `THIRD-PARTY-NOTICES.md` — его заголовки
сохраняют `Copyright (C) Nginx, Inc.`.
