# Falco-lite

Агент runtime-захисту Linux на eBPF. Програма на C стежить за системними викликами в ядрі та в реальному часі виявляє підозрілу поведінку процесів: reverse shell, запуск файлів із `/tmp`, читання `/etc/shadow`, підвищення привілеїв, криптомайнери. Правила описуються в YAML-конфігу. Коли правило спрацьовує, агент пише алерт і може сам зупинити процес.

Груповий проєкт з курсу «Процедурне програмування», НаУКМА.

Команда: Микита Вельбовець, Томас Іванаускас, Назар Дяченко.

## Стан проєкту

Каркас збирається й працює наскрізно на одному хуку: `execve` → ring buffer → демон → вивід у консоль. Решта — заглушки з `TODO(ім'я)` і списком того, що зробити, прямо у файлі.

| Модуль | Власник | Уже є | TODO |
|---|---|---|---|
| eBPF: `bpf/falco.bpf.c`, `src/loader.c` | Микита | exec, fork, exit; ring buffer; лічильник втрат; фільтр власного pid | connect, openat із фільтром у ядрі, setuid, ptrace |
| Правила: `src/rules.c` | Томас | контракт `src/rules.h`, таблиці імен | парсер YAML |
| Дерево процесів: `src/proctree.c` | Томас | API | хеш-таблиця, сканування `/proc`, предки |
| Рушій: `src/engine.c` | Томас | вибір найсильнішої дії | зіставлення умов |
| Реакція: `src/action.c` | Назар | захист pid 1 / kthreads / себе, `--dry-run`, `kill()` | pidfd + звірка `start_ns`, список за comm |
| Вивід: `src/out_json.c`, `src/out_syslog.c`, `src/tui.c` | Назар | текстовий вивід (`src/output.c`) | JSONL, syslog, TUI |
| CI і тести | Назар | юніт-тести, CI зі smoke-тестом на живому ядрі | e2e у CI, бенчмарки |

Спільні частини — `main.c`, `pipeline.c`, `record.c` — готові.

## Збірка

Потрібне ядро з BTF: перевірити `ls /sys/kernel/btf/vmlinux`. Рекомендоване середовище — VM з Ubuntu 24.04.

```bash
sudo apt install clang llvm make gcc pkg-config libelf-dev zlib1g-dev libzstd-dev libyaml-dev libncurses-dev
git clone --recurse-submodules https://github.com/zxkeee/FALCO-Lite.git
cd FALCO-Lite
make
sudo ./falco-lite -c rules/rules.yaml
```

Якщо клонували без `--recurse-submodules`: `git submodule update --init --recursive`.

libbpf (v1.8.0) і bpftool (v7.8.1) підключено сабмодулями, вони збираються разом із проєктом. `vmlinux.h` генерується з BTF поточного ядра. Щоб зібрати на машині без BTF (наприклад, у WSL), скопіюйте `/sys/kernel/btf/vmlinux` з VM і вкажіть шлях: `make VMLINUX_BTF=./vmlinux.btf`.

## Запуск

| Опція | Що робить |
|---|---|
| `-c, --config FILE` | файл правил (обов'язково) |
| `-j, --json FILE` | алерти в JSONL-файл |
| `-s, --syslog` | алерти в syslog |
| `-t, --tui` | інтерфейс на ncurses |
| `-n, --dry-run` | не вбивати, лише алерти |
| `-r, --record FILE` | записати всі події у файл |
| `-R, --replay FILE` | прогнати записані події без eBPF і root (завжди dry-run) |
| `-v, --verbose` | показувати fork/exit і налагодження libbpf |

## Як працювати паралельно

**Контракт.** `include/events.h` (що ядро віддає демону) і `src/rules.h` (на що перетворюється YAML) змінюються лише за домовленістю всієї команди. Після зміни `events.h` старі `.flrec`-записи не читаються.

**Запис і відтворення.** На VM записується справжня атака:

```bash
sudo ./falco-lite -c rules/rules.yaml --record attack.flrec
```

Потім файл можна ганяти скільки завгодно без root і без eBPF — так зручно налагоджувати рушій і вивід:

```bash
./falco-lite -c rules/rules.yaml --replay attack.flrec
```

**Тести.** `make test` збирає все, крім eBPF-частини: потрібні лише gcc, libyaml і ncurses, без root і clang. Тести на ще не готові модулі вже написано, вони починаються з `SKIP(...)`: реалізували модуль — видаліть рядок `SKIP`, і тест почне перевірятися. Новий тест: `TEST(ім'я)` у `tests/unit/test_*.c` і `RUN(ім'я)` у `tests/unit/test_main.c`.

**E2E.** `make e2e` запускає агента й три атаки з демо (reverse shell з-під `php-fpm`, запуск із `/tmp`, читання `/etc/shadow`) і перевіряє JSON-лог. Пройде повністю після MVP.

**CI.** На кожен push: юніт-тести, збірка, smoke-тест — агент запускається під `sudo` на раннері GitHub і має побачити `execve`.

## Правила

`rules/rules.yaml` — список правил:

```yaml
- name: reverse_shell
  severity: critical          # low | medium | high | critical
  when:
    syscall: connect          # execve | connect | openat | setuid | ptrace
    proc.comm: [bash, sh, dash, zsh]
    proc.ancestor: [php-fpm*, nginx, cron]
  action: kill                # log | alert | kill
```

Усередині одного поля значення об'єднуються через OR, різні поля — через AND. Рядки — glob-шаблони (`fnmatch`). Якщо подія збіглася з кількома правилами, повідомляються всі, а виконується найсильніша дія: kill > alert > log.

| Поле | Значення | Зміст |
|---|---|---|
| `proc.comm`, `proc.comm.not` | рядки | ім'я процесу (15 символів, як у ядрі) |
| `proc.ancestor`, `proc.ancestor.not` | рядки | будь-який предок, сам процес не враховується |
| `proc.exe.prefix` | рядки | початок шляху до виконуваного файлу |
| `proc.uid`, `proc.uid.not` | числа | реальний uid |
| `file.path`, `file.path.prefix` | рядки | шлях в `openat` |
| `net.dport` | числа | порт призначення в `connect` |
| `setuid.uid` | числа | аргумент `setuid` |
| `ptrace.request` | `attach`, `seize`, `poketext`, `pokedata` | тип запиту `ptrace` |

## Структура

```
bpf/falco.bpf.c      eBPF-програми
include/events.h     контракт ядро <-> userspace
src/main.c           CLI, головний цикл
src/loader.c         завантаження BPF, читання ring buffer
src/pipeline.c       шлях події: дерево -> вивід -> правила -> реакція
src/rules.c|h        правила та їхня схема
src/proctree.c       дерево процесів
src/engine.c         зіставлення подій із правилами
src/action.c         kill / alert
src/output.c         текстовий вивід і диспетчер приймачів
src/out_json.c       JSONL
src/out_syslog.c     syslog
src/tui.c            ncurses
src/record.c         --record / --replay
rules/rules.yaml     правила за замовчуванням
tests/unit/          юніт-тести (make test)
tests/e2e/           атаки з демо (make e2e)
Falco-lite.pdf       презентація проєкту
```
