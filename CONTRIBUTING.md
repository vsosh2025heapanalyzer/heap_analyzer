# Contributing Guide

## Workflow
1. Форк → отдельная ветка (`feature/my‑change`)
2. `clang-format -i *.c *.h`
3. `make test`  – все тесты должны проходить
4. Pull Request + описание чего и почему

## Commit Style
* `feat: add overflow detection for strcpy`
* `fix: handle realloc(ptr, 0) correctly`

## Code Style
* K&R, 4 spaces indentation
* В каждом файле первая строка:  
  ```c
  /* SPDX-License-Identifier: MIT */
