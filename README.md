# CS-TOOL

Кроссплатформенный CLI-фреймворк для запуска и оркестрации инструментов
security testing. Проект скачивает готовые релизные бинарники из GitHub,
проверяет платформу и запускает их через единый интерфейс.

Поддерживаются Windows, Linux и macOS на x64 и ARM64.

## Быстрый старт

После клонирования запусти launcher из корня репозитория.

### Windows

```powershell
.\cstool.bat
```

### Linux / macOS

```bash
./cstool
```

Launcher автоматически:

1. устанавливает `uv`, если его нет;
2. синхронизирует Python-зависимости без запроса подтверждения;
3. скачивает отсутствующие инструменты под текущую ОС и архитектуру;
4. открывает интерактивное меню.

### Как вызывать команды

`uv sync` ставит команды `cstool`, `cs-tool` и `cyberfw` **внутрь окружения
проекта** (`.venv\Scripts` / `.venv/bin`). Само по себе это не кладёт их в
`PATH`, поэтому просто `cyberfw status` в новой сессии PowerShell даёт
«имя не распознано». Рабочие способы:

| Откуда | Windows | Linux / macOS |
|---|---|---|
| Из корня репозитория | `.\cstool.bat status` | `./cstool status` |
| Из корня репозитория | `uv run cyberfw status` | `uv run cyberfw status` |
| Из любого каталога | `uv tool install .`, затем `cyberfw status` | то же |

Launcher (`cstool.bat` / `cstool`) передаёт аргументы дальше без изменений,
поэтому `.\cstool.bat status` — это тот же `cyberfw status`, но с
автоматической подготовкой окружения.

После `uv tool install .` uv сам предупредит, если его каталог с командами не
в `PATH`; добавить туда — `uv tool update-shell` (новая сессия терминала).

Голое `cstool` без `.\` в `cmd.exe` работает только там, где cmd ищет команды
в текущем каталоге; при `NoDefaultCurrentDirectoryInExePath=1` (частая
настройка безопасности) не находит. `.\cstool.bat` работает всегда.

### Установка как пакета

Запускать из клона не обязательно: `uv tool install .` (или `pip install .`)
даёт команду `cyberfw`, которая работает из любого каталога. В wheel входят
`registry.yaml` и `pipelines/` (как `cyberfw/data/`), а `tools_bin/`,
`reports/` и `logs/` создаются в пользовательском каталоге данных —
`%LOCALAPPDATA%\cyberfw` на Windows, `~/Library/Application Support/cyberfw`
на macOS, `$XDG_DATA_HOME/cyberfw` (по умолчанию `~/.local/share/cyberfw`) на
Linux — а не в текущей папке. Каталог с `registry.yaml` считается workspace:
из него всё по-прежнему кладётся рядом. Корень можно задать явно:
`CYBERFW_ROOT_DIR=/path`.

## Интерактивное меню

После автоматической подготовки отображается рабочая панель: слева —
подсказки и текущие настройки, справа — таблица инструментов со статусом.

```text
SHORTCUTS                TOOLS
  1-8  select tool        #  tool        version   state    source
  r    run pipeline       1  ffuf        2.3.0     ready    ffuf/ffuf
  0    exit               2  gitleaks    8.30.1    ready    gitleaks/gitleaks
                          3  gowitness   —         blocked  sensepost/gowitness
SETTINGS                  ...
  p  parse      on
  l  log level  INFO
  f  log file   on
STATUS
  7/8 ready
```

`state` отвечает на вопрос «запустится ли»: `ready` — бинарь на месте и
исполняется, `blocked` — файл скачан, но не читается (обычно карантин
антивируса), `not installed` — не скачан. `version` берётся из install-записи
`tools_bin/.<tool>.install.json`; прочерк значит, что инструмент работоспособен,
но записи о его установке нет. Та же таблица и та же сводка `N/M ready`
показываются в `cyberfw status`.

Диапазон номеров считается от `registry.yaml` (девятый инструмент получит
номер `9`), pipeline запускается клавишей `r`, выход — `0` или `q`.
В том же приглашении доступны переключатели настроек:

- `p` — включить/выключить парсинг по схеме (выкл. = сырой stdout/stderr, как `--no-parse`);
- `l` — циклически менять уровень логов (DEBUG → INFO → WARNING → ERROR);
- `f` — включить/выключить запись логов в `logs/cyberfw.log`.

Переключение действует на все последующие запуски в этой сессии (реализовано
через переменные `CYBERFW_*`) и сразу отражается в панели SETTINGS. Панель —
это live-регион (Rich `Live`): при нажатии `p`/`l`/`f` она перерисовывается на
месте, а не печатается заново, так что терминал не «уезжает» вниз. При выборе
инструмента или pipeline вывод команды идёт обычным потоком под панелью.

Перед запуском выбранного инструмента UI показывает краткий гайд:
назначение, ожидаемый target и пример команды.

## Инструменты

| Инструмент | Назначение | Target |
|---|---|---|
| `ffuf` | Фаззинг директорий, файлов и параметров | URL с `FUZZ` или обычный URL |
| `gitleaks` | Поиск секретов и ключей | Локальная директория репозитория |
| `gowitness` | Снимки веб-страниц | URL или список веб-целей |
| `httpx` | HTTP probing и определение технологий | Домен, URL или список хостов |
| `naabu` | Поиск открытых портов | Домен, IP или список хостов |
| `nuclei` | Проверка уязвимостей по шаблонам | Домен или URL |
| `rustscan` | Быстрое обнаружение открытых портов | Домен, IP или URL |
| `subfinder` | Пассивный поиск поддоменов | Домен |

`gitleaks` не сканирует веб-адреса. Для него нужно указать существующую
локальную папку, например `C:\Projects\app` или `/home/user/app`.

`rustscan` передаёт в сканер hostname вместо URL и выполняет только обнаружение
открытых портов. Определение сервисов и версий через Nmap не запускается
автоматически этим этапом; при необходимости Nmap нужно запускать отдельно.
Если `nmap` отсутствует в `PATH`, фреймворк лишь выводит предупреждение с
командой установки под текущую ОС (winget/brew/apt) и продолжает работу —
инициализация не прерывается.

## Командный режим

Интерактивное меню не обязательно.

```bash
# Автоматически установить все зарегистрированные инструменты
cyberfw init

# Установить только выбранные инструменты
cyberfw init subfinder nuclei

# Переустановить, даже если нужная версия уже стоит
cyberfw init --force

# Проверка готовности окружения (алиас: cyberfw doctor)
cyberfw status

# Запустить один инструмент
cyberfw run subfinder --target example.com
cyberfw run httpx --list hosts.txt
cyberfw run gitleaks --target ./my-repository

# Показать весь stdout утилиты без парсинга схемой
cyberfw run rustscan --target example.com --no-parse

# Сохранить результат одиночного запуска сразу, не спрашивая
cyberfw run subfinder --target example.com --save

# Или наоборот — точно ничего не сохранять
cyberfw run subfinder --target example.com --no-save

# Запустить pipeline: Subfinder -> Httpx -> Nuclei
cyberfw pipeline recon-to-vuln --target example.com

# Дополнительные этапы pipeline
cyberfw pipeline recon-to-vuln --target example.com --ffuf --gowitness

# Pipeline из файла pipelines/<name>.yaml (см. раздел «Свои pipeline»)
cyberfw pipeline ports-to-vuln --target example.com
```

Перед стартом `pipeline` проверяет, что бинарники всех его этапов
действительно запускаются. Если какой-то `not installed` или `blocked`
(карантин антивируса), команда сразу называет инструмент и этап и выходит с
кодом 2, не тратя минуты сканирования на прогон, который всё равно не даст
результата. Запустить вопреки этому — `--force-start`: доступные этапы
отработают, недоступный будет помечен `failed`, а зависящие от него —
`skipped`.

Команда `cyberfw status` (алиас `cyberfw doctor`) — пре-флайт проверка
окружения: какие инструменты установлены/готовы (`ready`), скачаны, но
нечитаемы, например заблокированы антивирусом (`blocked`), или отсутствуют
(`not installed`), их версии; наличие внешних зависимостей (`nmap` для
rustscan, Chrome для gowitness); и текущие настройки (`parse`, `log_level`,
вордлист, токен GitHub, каталоги). Полезно запускать до `pipeline`, чтобы
увидеть недостающее заранее, а не в середине прогона.

`cyberfw init` распаковывает каждый инструмент в собственный каталог
`tools_bin/<tool>/`; скачанный архив после распаковки удаляется, а при
повторной установке каталог инструмента очищается, так что от предыдущей
версии ничего не остаётся. Бинарники и архивы старой «плоской» раскладки
(`tools_bin/<tool>`, `tools_bin/<tool>_*.zip`) убираются при следующей
установке того же инструмента; README/LICENSE прежних версий, если они
остались на верхнем уровне `tools_bin/`, можно удалить вручную.

Флаг `--no-parse` доступен для отдельного запуска любой утилиты. Он отключает
валидацию по Pydantic-схеме и выводит в реальном времени каждую строку stdout
*и* stderr ровно так, как их печатает сама утилита — включая баннеры,
диагностические сообщения, пустые строки и форматы, которые не являются
JSONL. Launcher-файлы (`cstool.bat` для Windows, `cstool`/`start.sh` для
Linux/macOS) передают аргументы командному режиму без изменений.

Для `pipeline` флаг `--no-parse` (или `parse: false` / тумблер `p` в меню)
включает «подробный» режим: вместо живой таблицы в реальном времени
показывается сырой stdout/stderr каждого этапа — всё, что делают утилиты под
капотом. При этом записи всё равно парсятся внутри, чтобы результат одного
этапа передавался следующему (Subfinder → Httpx → Nuclei), так что конвейер
продолжает работать.

### Живая картина прогона

В обычном режиме `pipeline` и `run` показывают таблицу, которая обновляется
на месте: состояние каждого этапа (`pending` → `running` → `ok`/`failed`),
число записей, для fan-out-этапов (ffuf, gowitness) — сколько целей из скольких
обработано, время этапа (идёт, пока этап работает, и замирает на итоговом
значении) и причину падения. Под ней — последние найденные записи по мере
поступления; цвет отражает серьёзность: severity nuclei (`critical`/`high` —
красный, `medium` — жёлтый, `low`/`info` — приглушённый) и класс HTTP-кода
(2xx зелёный, 3xx голубой, 4xx жёлтый, 5xx красный).

```text
                   pipeline recon-to-vuln · example.com

 tool         stage        status    records    time   note
 ─────────────────────────────────────────────────────────────────────────
 subfinder    subdomains   ok              2     0.9s
 httpx        live_http    ok              1     0.7s
 nuclei       vulns        running         1     3.1s
 gowitness    screenshots  pending

                             Latest findings

 tool        kind   target                   detail
 ─────────────────────────────────────────────────────────────────────────
 subfinder   host   a.example.com            crtsh
 httpx       http   https://a.example.com/   Home
 nuclei      vuln   https://a.example.com/   critical
```

Колонки появляются по надобности: `targets` (сколько целей из скольких
обработано) — когда в прогоне есть fan-out-этап, `note` — когда есть что
сказать о падении или пропуске.

По завершении последний кадр остаётся на экране, а под ним печатается сводка:
статус, число записей, длительность, записи по инструментам, идентификатор
сессии и пути к отчётам. Если вывод перенаправлен в файл или идёт в лог CI,
таблица печатается один раз в финальном виде, а не мелькает кадрами.

### Сохранять или нет — решает пользователь

Когда прогон закончился и результат на экране, `run` и `pipeline` спрашивают
`Save the <name> report? [y/n]`:

- **да** — в `reports/<session>/` остаются JSONL-записи по этапам, `report.json`
  и `report.html`; пути печатаются в сводке;
- **нет** — каталог сессии, созданный этим прогоном, удаляется целиком, на
  диске не остаётся ничего.

Ответ можно дать заранее флагом, тогда вопроса не будет: `--save` / `--no-save`
у `run`, `--report` / `--no-report` у `pipeline`. Если спросить не у кого
(вывод в файл, CI, `< /dev/null`), команда не зависает и берёт поведение по
умолчанию: `pipeline` сохраняет, одиночный `run` — нет. Пустой результат не
сохраняется и вопроса не вызывает — сохранять нечего.

Каталог, который существовал до прогона (например, свой `--session` от прошлого
раза), не удаляется никогда: при ответе «нет» команда скажет, что оставила его
как есть.

Для GitHub API можно указать токен через переменную окружения:

```powershell
$env:CYBERFW_GITHUB_TOKEN = "your-token"
cyberfw init
```

```bash
export CYBERFW_GITHUB_TOKEN=your-token
cyberfw init
```

Токен не записывается в репозиторий.

Загрузка бинарников идёт с `objects.githubusercontent.com` и при обрывах,
таймаутах или ошибках 5xx повторяется автоматически (4 попытки с растущей паузой).
Если соединение до GitHub медленное и `cyberfw init` всё равно падает с
`timed out`, увеличь сетевой таймаут (ожидание соединения/ответа на каждую
операцию, по умолчанию 60 с) или
укажи прокси — `httpx` берёт его из стандартных переменных окружения:

```powershell
$env:CYBERFW_REQUEST_TIMEOUT = "180"
$env:HTTPS_PROXY = "http://127.0.0.1:1080"
cyberfw init
```

```bash
export CYBERFW_REQUEST_TIMEOUT=180
export HTTPS_PROXY=http://127.0.0.1:1080
cyberfw init
```

## Результаты и отчёты

Во время прогона `pipeline` пишет в `reports/<session>/`, поскольку
JSONL-контекст по этапам — это механизм передачи результата между узлами
конвейера (Context Store) и защита от потери данных при сбое. По завершении
каталог либо остаётся (с отчётами), либо удаляется — см. «Сохранять или нет»:

- JSON-отчёт;
- self-contained HTML-отчёт;
- JSONL-файлы контекста по этапам pipeline.

Оба отчёта начинаются с блока провенанса (`run` в JSON, таблица «Run» в
HTML): имя pipeline, seed-цель, сессия, платформа (`windows/amd64`), время
начала (UTC) и длительность, версии инструментов из install-записей
`tools_bin/.<tool>.install.json` и версия cyberfw. Без этого находку нельзя
воспроизвести или привязать к релизу сканера.

```json
"run": {
  "generated_at": "2026-09-22T09:41:07+00:00",
  "cyberfw_version": "1.0.0",
  "pipeline": "recon-to-vuln",
  "seed": "example.com",
  "session_id": "pipeline-recon-to-vuln-20260922-124055",
  "platform": "windows/amd64",
  "started_at": "2026-09-22T09:40:55+00:00",
  "finished_at": "2026-09-22T09:41:07+00:00",
  "duration_s": 12.3,
  "tool_versions": {"httpx": "1.12.0", "nuclei": "3.6.0", "subfinder": "2.9.0"}
}
```

Одиночный `cyberfw run` пишет те же два отчёта и JSONL-записи — если ответить
«да» на вопрос о сохранении (или передать `--save`).

Диагностические логи находятся в `logs/`. Эти каталоги и скачанные бинарники
игнорируются Git и не должны добавляться в коммит.

## Конфигурация

Настройки имеют следующий приоритет:

1. переменные окружения `CYBERFW_*`;
2. локальный `config.local.yaml`;
3. значения по умолчанию.

Пример `config.local.yaml`:

```yaml
concurrency: 4
request_timeout: 60
github_rate_fallback: true

# Лимит времени на один процесс инструмента (секунды). Зависший nuclei/httpx
# по истечении лимита останавливается, а этап помечается как failed — pipeline
# идёт дальше. При fan-out (ffuf, gowitness) лимит действует на каждую цель
# отдельно. Не задан = без ограничения.
stage_timeout: 1800

# Отключить парсинг по схеме глобально — выводить сырой stdout/stderr утилит
# как есть (эквивалент флага --no-parse, но по умолчанию для всех запусков).
parse: false

# Логирование
log_level: INFO       # DEBUG / INFO / WARNING / ERROR
log_to_file: true     # писать ли диагностику в logs/cyberfw.log

# Вордлист для Ffuf (нужен для --ffuf в pipeline и `run ffuf`)
wordlist: C:\wordlists\common.txt

# Каталог с pipeline-файлами <name>.yaml (по умолчанию pipelines/ в корне)
pipelines_dir: pipelines
```

Те же ключи доступны как переменные окружения: `CYBERFW_PARSE=false`,
`CYBERFW_LOG_LEVEL=DEBUG`, `CYBERFW_LOG_TO_FILE=false` и т.д. Отключение
парсинга: глобально через `parse` в настройках, либо разово флагом `--no-parse`
у `cyberfw run`. Уровень логирования и запись логов в файл управляются
`log_level`/`log_to_file` (неверный уровень отклоняется с понятной ошибкой).

Файл локальной конфигурации игнорируется Git.

## Свои pipeline

Помимо встроенного `recon-to-vuln`, любой файл `pipelines/<name>.yaml`
(каталог настраивается ключом `pipelines_dir`) — это pipeline, который
запускается по имени файла: `cyberfw pipeline <name> --target ...`; он же
появляется в списке выбора лаунчера (`r`). В репозитории лежит пример
`pipelines/ports-to-vuln.yaml` — активный вариант recon-to-vuln через naabu:

```yaml
description: Active port scan, HTTP probe of the open ports, then nuclei on the live services
nodes:
  - tool: naabu          # имя из registry.yaml
    stage: ports         # имя этапа: reports/<session>/ports.jsonl
  - tool: httpx
    stage: live_http     # по умолчанию узел получает записи предыдущего этапа
  - tool: nuclei
    stage: vulns
    input_from: live_http  # либо любого более раннего этапа по имени
    max_records: 0         # обрезать вывод этапа (0 = без ограничения)
```

Движок уже управляется данными, так что файл — это только описание узлов:
fan-out по целям (ffuf, gowitness), передача списка хостов через `-l`,
`stage_timeout`, изоляция ошибок и отчёты работают так же, как для
встроенного pipeline. Ошибки в файле (опечатка в ключе, `input_from` на
несуществующий или более поздний этап, повтор `stage`, инструмент, которого
нет в `registry.yaml`) выявляются до запуска и завершают команду с кодом 2.
Флаги `--ffuf`/`--gowitness`/`--max-httpx` относятся к `recon-to-vuln`; для
YAML-pipeline они игнорируются с предупреждением. При совпадении имён
встроенный pipeline имеет приоритет.

## Реестр инструментов

`registry.yaml` является декларативным источником метаданных релизов:

```yaml
subfinder:
  repo: projectdiscovery/subfinder
  asset_patterns:
    - "subfinder_*_windows_amd64.zip"
  archive: zip
  binary: subfinder
  needs_checksum: true
  version: latest            # или тег релиза, например v2.6.6
```

### Версии и контрольные суммы

По умолчанию `init` берёт последний релиз (`version: latest`). Чтобы
установка была воспроизводимой — одинаковой на всех машинах и не ломающейся
от смены формата вывода в новом релизе, — укажи тег: `version: v2.6.6`.
Повторный `cyberfw init` ничего не скачивает, если нужная версия уже
установлена (для пина это проверяется без обращения к сети, для `latest` —
после одного кэшируемого запроса к API), и печатает `= <tool> vX.Y.Z up to
date`; `cyberfw init --force` переустанавливает в любом случае.

`needs_checksum: true` сверяет архив с `checksums.txt` релиза. Если релиз не
публикует контрольную сумму для нужного ассета (или файла с суммами нет
вовсе, как у rustscan и gowitness), установка проходит, но в лог пишется
предупреждение `not verified`. Для таких инструментов дайджест можно
зафиксировать прямо в реестре вместе с версией — тогда несовпадение
останавливает установку:

```yaml
gowitness:
  repo: sensepost/gowitness
  version: v3.2.0
  sha256:
    gowitness-3.2.0-windows-amd64.exe: "<sha256 из релиза>"
    gowitness-3.2.0-linux-amd64: "<sha256>"
```

Установщик учитывает реальные варианты именования релизов:

- `amd64`, `x86_64`, `x64` и `aarch64`;
- порядок `os-arch` и `arch-os`;
- `.zip`, `.tar.gz` и raw-бинарники;
- Windows PE-сигнатуру `MZ`, чтобы не запускать Linux ELF-файлы.

## Разработка

```bash
uv sync --extra dev
uv run pytest -q                              # быстрый набор (без реальных бинарей и сети)
uv run pytest --cov=cyberfw --cov-fail-under=80
uv run ruff check .
uv run mypy cyberfw
```

Если `uv run pytest` (или `uv run mypy`) вдруг отвечает `uv trampoline failed
to canonicalize script path`, окружение устарело — так бывает после
переименования или копирования каталога проекта. Лечится пересозданием:
`rm -rf .venv && uv sync --all-extras`.

Быстрый набор не скачивает инструменты и использует фиктивные бинарники, поэтому
он детерминированный и подходит для CI. CI (`.github/workflows/ci.yml`) гоняет
его на ubuntu для Python 3.10–3.14 и дополнительно на windows и macos — код,
зависящий от ОС (поиск Git Bash и PE-сигнатуры на Windows, exec-биты и сигналы
на POSIX), проверяется на своей платформе. Те же ruff и mypy можно повесить на
коммит: `uvx pre-commit install` (конфиг — `.pre-commit-config.yaml`).
Dependabot раз в неделю обновляет `uv.lock` и версии actions.

Отдельный **опт-ин слой** гоняет *настоящие* бинарники из `tools_bin/` против
`localhost`/`example.com` и ловит расхождения адаптеров с реальными CLI-флагами
(именно такие баги фиктивные тесты пропускают). Он помечен маркером
`integration`, исключён из обычного прогона и запускается явно:

```bash
uv run pytest -m integration -q
```

Каждый такой тест аккуратно пропускается, если бинарника нет или отсутствует
сеть, поэтому слой не «краснеет» на машине без инструмента или без интернета.

## Структура

```text
cyberfw/
  cli.py                 Typer CLI и интерактивное меню
  ui.py                  Rich UI, логотипы и гайды инструментов
  manager/               GitHub API, реестр, установка и проверка бинарников
  pipeline/              executor, context store и pipeline engine
  pipelines/             встроенные pipeline и загрузчик YAML-описаний
  tools/                 адаптеры восьми внешних инструментов
  report/                JSON и HTML отчёты
  resources.py           данные пакета и пользовательские каталоги (workspace / installed)
tests/                   unit и integration тесты
registry.yaml            декларативный реестр релизов (в wheel — cyberfw/data/)
pipelines/               свои pipeline в YAML (пример: ports-to-vuln.yaml; в wheel — cyberfw/data/)
cstool.bat               Windows launcher (bootstrap + CLI)
cstool / start.sh        Linux/macOS launcher (bootstrap + CLI)
```

## Безопасность

- архивы проверяются на Zip Slip/Tar traversal;
- доступен SHA-256 контроль релизных архивов;
- URL скачивания валидируются;
- бинарники проверяются по формату текущей ОС;
- токены читаются из окружения и не сохраняются в Git.

## Лицензия

MIT — см. [LICENSE](LICENSE).
