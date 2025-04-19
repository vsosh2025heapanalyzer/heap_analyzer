# memcheck‑canary

LD_PRELOAD‑библиотека, перехватывающая `malloc`/`calloc`/`realloc`/`free`
и выявляющая **heap‑overflow**, **double‑free**, **use‑after‑free** и утечки
памяти.  
Подходит для отладки C / C++‑приложений и демонстраций по информационной
безопасности (ВсОШ ИБ).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Возможности
| Проверка | Метод |
|----------|-------|
| Переполнение кучи | «Канарейки» по 16 байт до и после блока |
| Double Free | Ведение списка уже освобождённых указателей |
| Use‑After‑Free | Проверка в перехваченных `memcpy` / `memset` / `puts` |
| Контроль лимита аллокаций | ENV `MEMCHECK_MAX_ALLOCS` |
| Отчёты | При крите/по завершению программы |

## Быстрый старт
```bash
LD_PRELOAD=$PWD/analyzer.so ./your_app
