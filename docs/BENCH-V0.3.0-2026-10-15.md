# Контрольный бенч v0.3.0: ssh3-c vs Go-форк vs OpenSSH (методика R3)
> Languages: RU (this file) · [EN](BENCH-V0.3.0-2026-10-15.en.md) · [DE](BENCH-V0.3.0-2026-10-15.de.md)

Дата: 2026-10-15. Прогон: `bench/p7-compare.sh` (`--stage all` + `--stage
manyfiles --files 4000 --rounds 7`), сырые CSV — `~/p7bench/results/`.
Предшественники: [BENCH-V0.2.0-2026-10-13.md](BENCH-V0.2.0-2026-10-13.md),
[BENCH-P7-2026-10-06.md](BENCH-P7-2026-10-06.md). Разбор метрик —
[BENCH-METRICS.md](BENCH-METRICS.md).

## Окружение

| № | Параметр | Значение |
|---|----------|----------|
| 1 | Стенд | WSL2, loopback 127.0.0.1, payload/вывод на tmpfs `/dev/shm`, WORK на `~/p7bench` |
| 2 | ssh3-c | **v0.3.0** (`ssh3-server -V` подтверждён), clang `linux-release` — в дереве конвейер per-file sftp и RSS-фикс READ |
| 3 | Go-форк | nagual2/ssh3 **0.1.35**, `CGO_ENABLED=0 -tags disable_password_auth` |
| 4 | OpenSSH | 9.6p1 Ubuntu, выделенный sshd :2222 (`aes128-gcm@openssh.com`) |
| 5 | Фон | бокс под нагрузкой (ambient); ротация A→B→C, медианы |

## 1. Throughput, sftp/scp (MB/s, медиана 7 раундов, sha-verified)

| № | Реализация | 512 MiB push | 512 MiB pull | 8 MiB push | 8 MiB pull |
|---|------------|-------------:|-------------:|-----------:|-----------:|
| 1 | OpenSSH (scp) | **357.6** | **421.1** | 20.5 | **29.6** |
| 2 | ssh3-c (sftp, конвейер) | 353.4 | 353.6 | 16.6 | 16.6 |
| 3 | Go-форк (sftp-подсистема) | 27.8 | 33.0 | 19.1 | 25.7 |

Чтение: ssh3-c сравнялся с scp на push (99%) и сузил gap на pull до
84%; направления выровнялись между собой (353/354 — следствие
конвейера и write-through фикса). 8 МиБ — setup-доминированный
режим, как раньше.

## 2. Handshake, cold connect+auth+exec (мс, 30 прогонов)

| № | Реализация | median | min | p95 | max |
|---|------------|-------:|----:|----:|----:|
| 1 | ssh3-c | **117.3** | 15.1 | 121.1 | 126.4 |
| 2 | Go-форк | 171.6 | 156.4 | 243.2 | 245.2 |
| 3 | OpenSSH | 221.4 | 213.9 | 231.3 | 249.0 |

## 3. ControlMaster, warm exec `true` (мс, 300 итераций)

| № | Реализация | median | min |
|---|------------|-------:|----:|
| 1 | ssh3-c | **7.6** | 5.8 |
| 2 | Go-форк | 9.0 | 7.5 |
| 3 | OpenSSH | 13.8 | 11.6 |

## 4. CPU / RAM сервера на 512 MiB push (свежий демон, сэмплы 50 мс)

| № | Реализация | CPU (дерево) | RSS пик |
|---|------------|-------------:|--------:|
| 1 | ssh3-c | **75.1%** | 81 MB |
| 2 | Go-форк | 103.8% | **26 MB** |
| 3 | OpenSSH | 104.2% | 26 MB |

RSS-фикс READ-буфера (бэклог §8.12) подтверждён на живом бенче:
81 MB против 526 MB до фикса; CPU — минимум из трёх.

## 5. Manyfiles: каталог 4000 × 4 КиБ (files/s, медиана 7/7 раундов)

| № | Реализация | push | pull |
|---|------------|-----:|-----:|
| 1 | ssh3-c (`-J -r`, конвейер) | **4667** | **4624** |
| 2 | Go-форк (`-f -r`) | 4103 | 3518 |
| 3 | OpenSSH (`scp -r`) | 1175 | 1284 |

ssh3-c обгоняет Go-форк в обоих направлениях (×1.14 push, ×1.31 pull)
и scp в 4 раза. Замечание: в параллельном прогоне 2000-каталога у C
было 3 транзиентных отбраковки (seed/pull под ambient-нагрузкой) —
на 4000 раунды 7/7 чистые.

## Замечания перегона

| № | Что | Детали |
|---|-----|--------|
| 1 | Бинарник первой попытки перегона подписывался 0.2.0 | замер остановлен, дерево пересобрано на 0.3.0 (`-V` подтверждён), перегон повторён |
| 2 | 1 отбраковка c-pull в 512m таблице | sha-гейт сработал, раунд пересдан — итог n=7 валидных |

## Воспроизведение

```bash
# в WSL: go-бинарники в ~/p7bench/bin (CGO_ENABLED=0 -tags
# disable_password_auth из project/ssh3), WORK на ~/p7bench
bash bench/p7-compare.sh --stage all --work ~/p7bench \
    --c-build /mnt/c/Git/project/ssh3-c/build/linux-release \
    --go-bin ~/p7bench/bin
bash bench/p7-compare.sh --stage manyfiles --files 4000 --rounds 7 \
    --work ~/p7bench --c-build /mnt/c/Git/project/ssh3-c/build/linux-release \
    --go-bin ~/p7bench/bin
```
