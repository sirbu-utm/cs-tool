# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии —
[SemVer](https://semver.org/lang/ru/). Пока проект живёт в `1.0.0`, всё
накапливается в «Unreleased»; при выпуске раздел получает номер и дату.

## [Unreleased]

### Added
- Флаг `-v` / `--verbose` у `init`, `run`, `pipeline`, `status`: поднимает
  уровень логов до `DEBUG` только для этого запуска и печатает трассировку
  установки — разрешение релиза, URL и размер загрузок, выбранный под платформу
  ассет, каталог распаковки и путь к бинарнику (для Chromium — платформу CfT,
  версию и URL). Постоянный `log_level` не меняется.
- Автозагрузка portable Chromium (Chrome for Testing) для gowitness: `cyberfw
  init` докачивает браузер в `tools_bin/chromium/`, если gowitness в наборе, а
  системного Chrome нет. Скачанный Chromium имеет приоритет над системным,
  виден в `cyberfw status` и передаётся gowitness через `--chrome-path`. Уже
  имеющийся Chrome (системный или portable) повторно не качается (строка
  `present`); платформа без сборки CfT помечается `skipped`. Пропустить —
  `cyberfw init --no-chromium`.
- Живая таблица прогона: состояние каждого этапа, счётчик записей, прогресс
  fan-out по целям, время этапа и причина падения обновляются на месте, под
  ними — последние находки. Цвет записей отражает severity nuclei и класс
  HTTP-кода. По завершении — панель-сводка (статус, записи по инструментам,
  длительность, сессия, пути к отчётам).
- `PipelineEngine.set_stage_callback` — события жизненного цикла этапа
  (`start` / `progress` / `done`) для внешних представлений.
- Единая таблица инвентаря для лаунчера и `status`: колонка версии, состояние
  `ready` / `blocked` / `not installed` и сводка `N/M ready`; `init` печатает
  результат таблицей.
- Пре-флайт `pipeline`: недоступные инструменты (`not installed` / `blocked`)
  и отсутствующие жёсткие внешние зависимости (Chrome для gowitness)
  называются до старта, команда выходит с кодом 2; `--force-start` запускает
  всё равно. Необязательные зависимости (`nmap` для rustscan) выводятся
  предупреждением и не мешают прогону. Упавший этап и зависящие от него `skipped` перечислены в сводке.
- `stage_timeout` (`CYBERFW_STAGE_TIMEOUT` / `config.local.yaml`): зависший
  инструмент останавливается, этап помечается `failed`, pipeline идёт дальше.
- Pipeline из файла: любой `pipelines/<name>.yaml` запускается по имени и
  появляется в лаунчере; пример `pipelines/ports-to-vuln.yaml`.
- `version:` и `sha256:` в `registry.yaml` — пин релиза и его дайджестов;
  `init` пропускает уже установленную версию (`up to date`), `init --force`
  переустанавливает.
- Блок провенанса в отчётах (`run` в JSON, таблица «Run» в HTML): pipeline,
  seed, сессия, платформа, время и длительность, версии инструментов.
- `PipelineEngine.run_single` — публичный вход для одиночного запуска.
- Адаптеры несут свои подсказки и проверку цели (`target_prompt`,
  `extra_input_prompt`, `validate_target`); `adapter_class(name)`.
- CI гоняет ubuntu × Python 3.10–3.14 плюс windows и macos; порог покрытия 80 %.
  Dependabot для `uv.lock` и actions, `.pre-commit-config.yaml` (ruff + mypy).

### Changed
- Баннер: вместо строки «Integrated Cybersecurity Framework · v1.0.0» —
  градиентная линия и полоса состояния с `▰` на каждый инструмент (цвет по
  `ready` / `blocked` / `not installed`), счётчиком готовых, платформой и
  версией.
- Сохранение результата стало выбором пользователя: по окончании `run` и
  `pipeline` спрашивают, сохранять ли отчёт. «Нет» удаляет каталог сессии,
  созданный этим прогоном (ранее существовавший не трогается). Ответ можно
  задать заранее: `--save`/`--no-save` и `--report`/`--no-report`; без TTY
  вопроса нет и поведение прежнее. Одиночный `run` теперь тоже пишет
  `report.json` и `report.html`, а не только JSONL.
- Каждый инструмент ставится в `tools_bin/<tool>/`; архив удаляется после
  распаковки, каталог инструмента очищается при переустановке, старые архивы
  и бинарники плоской раскладки убираются.
- Лаунчер: номера инструментов `1..N` от реестра, pipeline на `r`, выход `0`/`q`.
- Context Store держит файл этапа открытым на время этапа (flush после каждой
  записи) вместо open/close на каждую запись.
- При отмене дочернему процессу даётся 3 с на выход по SIGTERM, затем SIGKILL;
  ошибки называют сигнал («crashed with SIGSEGV») или NTSTATUS-код на Windows.
- Известный, но не установленный инструмент — это `failed`-этап, а не обрыв
  всего прогона без отчёта.
- Загрузка без контрольной суммы (нет записи в `checksums.txt` или самого
  файла) логируется как `not verified` вместо молчаливого успеха.

### Fixed
- Этап падал с `Separator is not found, and chunk exceed the limit`, если
  инструмент печатал одну строку stdout длиннее 64 КиБ (лимит ридера asyncio
  по умолчанию) — например крупная находка `nuclei -jsonl`. Лимит поднят до
  8 МиБ, а строка сверх него теперь отбрасывается с предупреждением, не убивая
  этап.
- Windows: инструменты-скрипты с shebang не запускались, если bash находился
  как `Git\bin\bash.exe` (так его видят PowerShell и раннер GitHub) — путь
  конвертировался по WSL-схеме `/mnt/c/...`, и Git Bash отвечал
  `No such file or directory` (exit 127). Теперь `cygpath` ищется и в соседнем
  `usr\bin`, а без него схема выбирается по тому, какой bash найден:
  `/mnt/c/...` только для WSL-шима, `/c/...` для MSYS/Git.
- naabu получал URL целиком (`-host https://999.md`) и падал с `no valid ipv4
  or ipv6 targets were found`; теперь и seed, и цели предыдущего этапа
  приводятся к имени хоста — общий `cyberfw/tools/targets.hostname_of`,
  которым пользуется и rustscan.
- Этап, чей источник упал, больше не подставляет seed вместо результатов
  этого источника (httpx сканировал сам seed и рапортовал успех).
- `Settings.max_archive_size` не доходил до установщика (читался приватный
  `CYBERFW_MAX_ARCHIVE`).
- `UnicodeEncodeError` при перенаправлении вывода на Windows (`status > out.txt`,
  `init | tee`): не-UTF-8 stdout/stderr переконфигурируются в UTF-8.
- Три Windows-ориентированных теста падали на Linux-раннере CI.
- `append_raw` в Context Store не закрывал файл.

## [1.0.0] — 2026-09-21

Первая версия: кроссплатформенный CLI для установки прекомпилированных
инструментов из GitHub Releases и их оркестрации (subfinder, naabu, httpx,
nuclei, ffuf, rustscan, gitleaks, gowitness), pipeline `recon-to-vuln`,
интерактивный лаунчер, JSON/HTML-отчёты, checksum-верифицированный bootstrap uv.
