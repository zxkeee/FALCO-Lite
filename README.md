# Falco-lite

[English](#english) · [Українська](#українська)

## English

Falco-lite is a runtime security agent for Linux written in C on top of eBPF. Small programs in the kernel report what processes do: which programs start, where they connect, which sensitive files they open, when a process gains root and when one process attaches to another with ptrace. The agent matches these events against rules from a YAML file. When a rule fires it writes an alert and, if the rule says so, kills the process.

It catches reverse shells from a web server, programs started from `/tmp`, reads of `/etc/shadow`, privilege escalation and crypto-miners.

Group project for the "Procedural Programming" course at NaUKMA. Team: Mykyta Velbovets, Tomas Ivanauskas, Nazar Diachenko.

### Requirements

Linux on x86-64 with BTF (`/sys/kernel/btf/vmlinux` must exist) and root access. We tested on kernel 6.18 (WSL2, Ubuntu 26.04). If a kernel function the agent hooks is missing, the agent disables only the hooks that depend on it and prints a warning.

Ubuntu 25.04 or newer, Debian:

```
sudo apt install clang llvm bpftool libbpf-dev libelf-dev libyaml-dev libncurses-dev zlib1g-dev pkg-config make gcc netcat-openbsd tmux python3
```

On Ubuntu 24.04 and 22.04 `bpftool` is a virtual package. Replace it with `linux-tools-common linux-tools-$(uname -r)`, as CI does.

Arch Linux (not tested):

```
sudo pacman -Syu --needed clang llvm bpf libbpf libelf libyaml ncurses zlib make gcc pkgconf openbsd-netcat tmux python
```

### Build and run

```
make
sudo ./falco-lite --config rules.yaml
```

```
[+] eBPF: 12 programs loaded (execve, fork, exit, connect, openat, setuid, ptrace)
[+] ring buffer attached, kernel 6.18.54.1-microsoft-standard-WSL2, CO-RE
[+] rules: 7 from rules.yaml
[+] watching...
18:34:20 kill  reverse_shell  killed         pid=341724 uid=1000 comm=bash connect 127.0.0.1:9001
         process tree: bash ← bash ← php-fpm ← runuser ← …   ·   SIGKILL 0.07 ms after the kernel event
18:34:43 alert shadow_read    alerted        pid=342432 uid=1000 comm=cat open /etc/shadow (denied)
         process tree: cat ← php-fpm ← runuser ← tmux: server ← …
```

Each alert is followed by the process's ancestor chain. For a kill, the line also shows the time from the kernel event to the SIGKILL. The JSON log carries the same data in the `chain` and `reaction_us` fields.

| Option | What it does |
|---|---|
| `-c, --config FILE` | rules file (default `rules.yaml`) |
| `-j, --json FILE` | append alerts to a file, one JSON object per line |
| `-s, --syslog` | send alerts to syslog (`LOG_AUTHPRIV`) |
| `-t, --tui` | ncurses dashboard with event counters and recent alerts, `q` quits |
| `-n, --dry-run` | never kill, log `would_kill` instead |
| `-v, --verbose` | print every event |
| `-h, --help` | show the options |

`--tui` and `--verbose` cannot be used together.

`make static` builds a single static binary. It needs the static versions of libbpf, libelf, zstd, zlib, libyaml and ncurses; CI builds it on Ubuntu 24.04.

The agent kills processes by default. On a new machine or kernel, start with `sudo ./falco-lite -n` and check two things: `sudo -n true` must not raise an alert, and `cd /tmp && ./x` must be reported with the full path `/tmp/x`. Switch to kill mode only after that.

### Rules

```yaml
- name: reverse_shell
  when:
    syscall: connect
    proc.comm: [bash, sh, dash, zsh, ksh]
    proc.ancestor: [php-fpm, php-fpm8.1, php-fpm8.2, php-fpm8.3, php-fpm8.4, nginx, apache2, httpd, cron]
  action: kill
```

`syscall` is one of `execve`, `connect`, `openat`, `setuid`, `ptrace`. `action` is `alert` or `kill`.

| Condition | Value | Events |
|---|---|---|
| `proc.comm` | process name, up to 15 bytes | all |
| `proc.ancestor` | name of any ancestor in the process tree, up to 15 bytes | all |
| `file.path` | exact path | execve, openat, setuid |
| `file.prefix` | start of the path | execve, setuid |
| `net.port` | destination port | connect |

A value is a string or a list. A rule matches when every condition holds, and a condition holds when any of its values matches. The `.not` suffix inverts a condition, which is how allow-lists are written: `proc.comm.not: [sshd]`. An `openat` rule needs a `file.path` list, because the agent watches those exact files by inode.

The agent refuses to start if the rules file has an unknown or misspelled key or condition, a condition that does not apply to the rule's syscall, a repeated key, an empty list, a name longer than 15 bytes, an invalid port, a `kill` rule without conditions, an `openat` rule without `file.path`, more than 64 watched files or more than one YAML document. A rule that silently meant something else could kill the wrong processes. A typo inside a path is not caught: that file simply never matches.

### What `rules.yaml` catches

| Rule | What the agent sees | Reaction |
|---|---|---|
| `reverse_shell` | a shell calls `connect()` and a web server or cron is among its ancestors, even if the process in between has already exited (`&`, `setsid`) | SIGKILL |
| `exec_from_tmp` | a file is executed from `/tmp`, `/dev/shm` or `/var/tmp`, including `cd /tmp && ./x` | SIGKILL |
| `shadow_read` | `/etc/shadow` or `/etc/gshadow` is opened by a program outside the allow-list, including failed attempts | alert |
| `setuid_root` | a non-root process becomes root through something other than sudo, su, passwd and the other system setuid programs on the list | SIGKILL |
| `ptrace_attach` | `PTRACE_ATTACH` or `PTRACE_SEIZE` from a program that is not a debugger | SIGKILL |
| `miner_exec`, `miner_pool` | a known miner starts, or anything connects to a stratum pool port | SIGKILL |

The agent never kills pid 1, itself or its own ancestors.

### Tests and demos

```
make test
sudo bash demo/run.sh
```

`make test` runs 128 unit checks of the rule parser, the process tree, the rule engine and the output code. It does not need root.

`demo/run.sh` starts the agent in kill mode and runs every attack from the table above as a regular user: the one who ran sudo, or the user name given as an argument. It checks the reaction and the JSON log for each one, then checks that ordinary commands raise no alerts. A clean run prints `passed: 9, failed: 0`. Its files go to `/var/lib/falco-lite-demo`.

GitHub Actions (`.github/workflows/ci.yml`) builds the project and runs the unit tests, the static build and `demo/run.sh` on every push and pull request.

### Live demo

```
sudo bash demo/show.sh
```

Run it from the repository root. A guided demo in tmux, with English captions. The top pane explains each step. In the middle is the attacker's web shell inside php-fpm, running as a regular user, next to the attacker's listener on `127.0.0.1:9001`. The bottom pane is Falco-lite. Press Enter, Space or the right arrow to run the next scene:

1. a reverse shell with no protection: the attacker gets a shell and runs commands;
2. Falco-lite starts;
3. the same reverse shell is killed;
4. a shell started through `setsid -f`, whose parent has already exited, is killed;
5. a payload dropped in `/tmp` and started as `./.kworker` is killed;
6. a read of `/etc/shadow` is denied by the OS and reported anyway;
7. a SUID-root binary is killed the moment it becomes root;
8. a "miner" written in Python is killed when it connects to pool port 3333;
9. a summary: how many attacks were stopped, the reaction times and one JSON line.

The terminal must be at least 160×45. If the script says it is too small, make the window fullscreen and reduce the font size (Ctrl+minus in Windows Terminal). Before the first scene the script watches the machine for 5 seconds in dry-run mode; if the agent would react to processes that are already running, it asks `[y/N]` before going on. `q` quits between scenes. On exit the script stops the agent and removes the payload and the SUID file. Working files are kept in `/srv/falco-demo`.

`presentation/index.html` is the defence presentation: one offline HTML file with screenshots from this demo. Arrow keys switch slides, F toggles fullscreen, N shows the speaker notes, M turns animations off.

### Overhead

Measured on our laptop (WSL2, Ryzen 9 5900HS, kernel 6.18). A loop of 5000 runs of `/bin/true` took 4.85 s without the agent and 5.10 s with it (median of three runs), so about 5% in the worst case, when the system does nothing but start processes. The agent used 0.57 s of CPU for 15,000 such processes, about 38 µs per process (its fork, exec and exit), and 14 MB of memory. In our demo runs the time from the kernel event to the SIGKILL was between 0.03 and 0.11 ms.

### Wazuh and syslog

Wazuh can read the agent's JSON log as a `localfile`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/falco-lite.json</location>
</localfile>
```

```
sudo ./falco-lite -j /var/log/falco-lite.json -s
```

### Architecture

```
kernel:     execve  fork  exit  connect  openat  setuid  ptrace
              │      │     │       │        │       │       │
              └──────┴─────┴── ring buffer (struct event) ──┘
userspace:  event reader → process tree → rule engine → kill / JSON / syslog / TUI
```

| Module | Files |
|---|---|
| eBPF programs and loader | `bpf/falco.bpf.c`, `src/event.h`, `src/loader.c` (loading, attaching hooks, watched files) |
| Rule engine and process tree | `src/rules/` (`rules.c` parses YAML, `engine.c` matches events), `src/proctree/`, `rules.yaml` |
| Response and output | `src/response/` (`response.c`, `output.c`), `src/tui/`, `src/main.c`, `tests/`, `demo/`, `.github/` |

Hooks:

| Event | Hook | Why this one |
|---|---|---|
| execve | `sched_process_exec` plus `fentry/security_file_open` with `bpf_d_path`, reset in `fentry/alloc_bprm` | the full path of the file, even for `./x`, scripts and 32-bit calls |
| fork, exit | `tp_btf/sched_process_fork`, `sched_process_exit` | a process tree without gaps, including workers that never call exec |
| connect | `fentry/tcp_v4_connect`, `fentry/tcp_v6_connect` | TCP over IPv4 and IPv6, however the connection is made |
| openat | `fexit/may_open`, matched by inode | sees the result of the permission check, relative paths and hard links |
| setuid | `fentry/commit_creds`, binary path taken only inside `begin_new_exec` | a non-root process becoming root, through a setuid binary or `setuid()`/`seteuid()` |
| ptrace | `fentry/ptrace_attach` | only real attach attempts |

PIDs are translated into the agent's own pid namespace, which differs from the root one under WSL and in containers. If a kernel function is missing, the agent disables only the hooks that depend on it and prints a warning; when the exec path hooks are missing, the setuid hook is disabled too.

### Limitations

- Paths longer than 255 characters are recorded as they were passed to exec.
- A chroot inside a user namespace can disguise a file path.
- The agent does not see processes in pid namespaces above its own, so run it in the outermost pid namespace you want to watch.
- Only TCP connections are seen. A UDP `connect()` does not reach the agent.
- The kill comes from userspace, so the process still completes the system call that triggered the rule. In theory the PID can be reused between the event and the kill.
- The allow-lists for `ptrace_attach` and `shadow_read` go by process name, which a process can change for itself.
- Starting a file from `/tmp` through the dynamic loader (`ld-linux.so /tmp/x`) is not an exec of that file, so `exec_from_tmp` does not catch it.
- The process tree only knows what it has seen. Ancestry that was broken before the agent started cannot be recovered.
- Watched files (`openat`) are re-read every 5 seconds, so replacing a file by renaming leaves a short window. There can be at most 64 of them. If two paths in the rules point to the same file (a symlink or hard link), the rule with the first path fires, and the agent warns about it at startup.

## Українська

Falco-lite захищає Linux під час роботи: це агент, написаний на C поверх eBPF. Невеликі програми в ядрі повідомляють, що роблять процеси: які програми запускаються, куди підключаються, які важливі файли відкривають, коли процес отримує root і коли один процес під'єднується до іншого через ptrace. Агент перевіряє ці події за правилами з YAML-файлу. Коли правило спрацьовує, він пише алерт, а якщо так сказано в правилі, вбиває процес.

Агент ловить reverse shell з веб-сервера, запуск програм з `/tmp`, читання `/etc/shadow`, підвищення привілеїв і криптомайнери.

Груповий проєкт з курсу «Процедурне програмування», НаУКМА. Команда: Микита Вельбовець, Томас Іванаускас, Назар Дяченко.

### Вимоги

Linux на x86-64 з BTF (має існувати `/sys/kernel/btf/vmlinux`) і права root. Ми перевіряли на ядрі 6.18 (WSL2, Ubuntu 26.04). Якщо в ядрі немає функції, до якої підключається агент, він вимикає тільки хуки, що від неї залежать, і пише попередження.

Ubuntu 25.04 і новіші, Debian:

```
sudo apt install clang llvm bpftool libbpf-dev libelf-dev libyaml-dev libncurses-dev zlib1g-dev pkg-config make gcc netcat-openbsd tmux python3
```

На Ubuntu 24.04 і 22.04 `bpftool` є віртуальним пакетом. Замість нього встановіть `linux-tools-common linux-tools-$(uname -r)`, як це робить CI.

Arch Linux (не перевірено):

```
sudo pacman -Syu --needed clang llvm bpf libbpf libelf libyaml ncurses zlib make gcc pkgconf openbsd-netcat tmux python
```

### Збірка і запуск

```
make
sudo ./falco-lite --config rules.yaml
```

```
[+] eBPF: 12 programs loaded (execve, fork, exit, connect, openat, setuid, ptrace)
[+] ring buffer attached, kernel 6.18.54.1-microsoft-standard-WSL2, CO-RE
[+] rules: 7 from rules.yaml
[+] watching...
18:34:20 kill  reverse_shell  killed         pid=341724 uid=1000 comm=bash connect 127.0.0.1:9001
         process tree: bash ← bash ← php-fpm ← runuser ← …   ·   SIGKILL 0.07 ms after the kernel event
18:34:43 alert shadow_read    alerted        pid=342432 uid=1000 comm=cat open /etc/shadow (denied)
         process tree: cat ← php-fpm ← runuser ← tmux: server ← …
```

Під кожним алертом агент друкує ланцюжок предків процесу. Для kill у тому ж рядку є час від події в ядрі до надісланого SIGKILL. У JSON-лозі ті самі дані лежать у полях `chain` і `reaction_us`.

| Опція | Що робить |
|---|---|
| `-c, --config FILE` | файл правил (за замовчуванням `rules.yaml`) |
| `-j, --json FILE` | дописувати алерти у файл, по одному JSON-об'єкту на рядок |
| `-s, --syslog` | надсилати алерти в syslog (`LOG_AUTHPRIV`) |
| `-t, --tui` | панель на ncurses з лічильниками подій і останніми алертами, `q` для виходу |
| `-n, --dry-run` | нікого не вбивати, лише писати `would_kill` |
| `-v, --verbose` | друкувати кожну подію |
| `-h, --help` | показати опції |

`--tui` і `--verbose` не можна вмикати разом.

`make static` збирає один статичний бінарник. Для цього потрібні статичні версії libbpf, libelf, zstd, zlib, libyaml і ncurses; CI збирає його на Ubuntu 24.04.

За замовчуванням агент вбиває процеси. На новій машині чи новому ядрі спершу запустіть `sudo ./falco-lite -n` і перевірте дві речі: `sudo -n true` не дає алерту, а запуск `cd /tmp && ./x` агент показує з повним шляхом `/tmp/x`. Лише після цього вмикайте бойовий режим.

### Правила

```yaml
- name: reverse_shell
  when:
    syscall: connect
    proc.comm: [bash, sh, dash, zsh, ksh]
    proc.ancestor: [php-fpm, php-fpm8.1, php-fpm8.2, php-fpm8.3, php-fpm8.4, nginx, apache2, httpd, cron]
  action: kill
```

`syscall` може бути `execve`, `connect`, `openat`, `setuid` або `ptrace`. `action` може бути `alert` або `kill`.

| Умова | Значення | Події |
|---|---|---|
| `proc.comm` | ім'я процесу, до 15 байтів | усі |
| `proc.ancestor` | ім'я будь-якого предка в дереві процесів, до 15 байтів | усі |
| `file.path` | точний шлях | execve, openat, setuid |
| `file.prefix` | початок шляху | execve, setuid |
| `net.port` | порт призначення | connect |

Значення може бути рядком або списком. Правило спрацьовує, коли виконуються всі умови, а умова виконується, коли збігається будь-яке з її значень. Суфікс `.not` інвертує умову, так пишуться allow-list: `proc.comm.not: [sshd]`. Правилу для `openat` потрібен список `file.path`, бо агент стежить саме за цими файлами за їхнім inode.

Агент не стартує, якщо у файлі правил є невідомий ключ чи умова або описка в назві, умова, що не підходить до `syscall` правила, повторений ключ, порожній список, ім'я довше за 15 байтів, неправильний порт, правило `kill` без жодної умови, правило `openat` без `file.path`, понад 64 відстежувані файли або кілька YAML-документів. Правило, яке непомітно означає щось інше, могло б убивати не ті процеси. Описку всередині шляху агент не помітить: такий файл просто ніколи не збіжиться.

### Що ловить `rules.yaml`

| Правило | Що бачить агент | Реакція |
|---|---|---|
| `reverse_shell` | shell робить `connect()`, а серед його предків є веб-сервер або cron, навіть якщо проміжний процес уже завершився (`&`, `setsid`) | SIGKILL |
| `exec_from_tmp` | запуск файлу з `/tmp`, `/dev/shm` або `/var/tmp`, зокрема через `cd /tmp && ./x` | SIGKILL |
| `shadow_read` | `/etc/shadow` або `/etc/gshadow` відкриває програма не з allow-list, зокрема невдала спроба | алерт |
| `setuid_root` | процес не-root отримує root не через sudo, su, passwd та інші системні setuid-програми зі списку | SIGKILL |
| `ptrace_attach` | `PTRACE_ATTACH` або `PTRACE_SEIZE` від програми, яка не є налагоджувачем | SIGKILL |
| `miner_exec`, `miner_pool` | запуск відомого майнера або підключення будь-якої програми до порту stratum-пулу | SIGKILL |

Агент ніколи не вбиває pid 1, себе і своїх предків.

### Тести і демо

```
make test
sudo bash demo/run.sh
```

`make test` запускає 128 юніт-перевірок парсера правил, дерева процесів, рушія правил і виводу. Root для цього не потрібен.

`demo/run.sh` запускає агента в бойовому режимі і від імені звичайного користувача (того, хто запустив sudo, або вказаного аргументом) виконує кожну атаку з таблиці вище. Для кожної він перевіряє реакцію і JSON-лог, а наприкінці перевіряє, що звичайні команди не дають алертів. Успішний запуск виводить рядок `passed: 9, failed: 0`. Файли демо лежать у `/var/lib/falco-lite-demo`.

GitHub Actions (`.github/workflows/ci.yml`) на кожен push і pull request збирає проєкт і запускає юніт-тести, статичну збірку і `demo/run.sh`.

### Живе демо

```
sudo bash demo/show.sh
```

Запускайте з кореня репозиторію. Кероване демо в tmux з підписами англійською. Верхня панель пояснює кожен крок. Посередині web shell атакувальника в php-fpm від імені звичайного користувача, поруч слухач атакувальника на `127.0.0.1:9001`. Унизу Falco-lite. Enter, пробіл або стрілка вправо запускають наступну сцену:

1. reverse shell без захисту: атакувальник отримує shell і виконує команди;
2. запуск Falco-lite;
3. той самий reverse shell убито;
4. shell, запущений через `setsid -f`, чий батько вже завершився, убито;
5. payload у `/tmp`, запущений як `./.kworker`, убито;
6. читання `/etc/shadow` ОС відхилила, і агент усе одно про нього повідомив;
7. SUID-root бінарник убито в момент отримання root;
8. «майнер» на Python убито, коли він підключається до порту пулу 3333;
9. підсумок: скільки атак зупинено, час реакції і приклад рядка JSON.

Термінал має бути щонайменше 160×45. Якщо скрипт скаже, що вікно замале, розгорніть його на весь екран і зменште шрифт (Ctrl+мінус у Windows Terminal). Перед першою сценою скрипт 5 секунд дивиться на машину в режимі dry-run; якщо агент зреагував би на вже запущені процеси, він спитає `[y/N]`, чи продовжувати. `q` завершує демо між сценами. На виході скрипт зупиняє агента і прибирає payload і SUID-файл. Робочі файли лежать у `/srv/falco-demo`.

У `presentation/index.html` лежить презентація для захисту: один HTML-файл, що працює без інтернету, зі скріншотами цього демо. Стрілки гортають слайди, F вмикає повний екран, N показує нотатки доповідача, M вимикає анімацію.

### Накладні витрати

Виміряно на нашому ноутбуці (WSL2, Ryzen 9 5900HS, ядро 6.18). Цикл із 5000 запусків `/bin/true` тривав 4,85 с без агента і 5,10 с з агентом (медіана трьох запусків), тобто приблизно на 5% довше в найгіршому випадку, коли система лише створює процеси. Агент витратив 0,57 с процесорного часу на 15 000 таких процесів, близько 38 мкс на процес (його fork, exec і exit), і 14 МБ пам'яті. У наших запусках демо від події в ядрі до SIGKILL минало від 0,03 до 0,11 мс.

### Wazuh і syslog

Wazuh може читати JSON-лог агента як `localfile`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/falco-lite.json</location>
</localfile>
```

```
sudo ./falco-lite -j /var/log/falco-lite.json -s
```

### Архітектура

```
ядро:       execve  fork  exit  connect  openat  setuid  ptrace
              │      │     │       │        │       │       │
              └──────┴─────┴── ring buffer (struct event) ──┘
userspace:  читач подій → дерево процесів → рушій правил → kill / JSON / syslog / TUI
```

| Модуль | Файли |
|---|---|
| eBPF-програми і завантажувач | `bpf/falco.bpf.c`, `src/event.h`, `src/loader.c` (завантаження, підключення хуків, відстежувані файли) |
| Рушій правил і дерево процесів | `src/rules/` (`rules.c` розбирає YAML, `engine.c` зіставляє події), `src/proctree/`, `rules.yaml` |
| Реакція та вивід | `src/response/` (`response.c`, `output.c`), `src/tui/`, `src/main.c`, `tests/`, `demo/`, `.github/` |

Хуки:

| Подія | Хук | Чому саме він |
|---|---|---|
| execve | `sched_process_exec` і `fentry/security_file_open` з `bpf_d_path`, скидання в `fentry/alloc_bprm` | повний шлях файлу навіть для `./x`, скриптів і 32-бітних викликів |
| fork, exit | `tp_btf/sched_process_fork`, `sched_process_exit` | дерево процесів без розривів, зокрема на воркерах, які не викликають exec |
| connect | `fentry/tcp_v4_connect`, `fentry/tcp_v6_connect` | TCP через IPv4 та IPv6, хоч би як створено з'єднання |
| openat | `fexit/may_open`, зіставлення за inode | видно результат перевірки доступу, відносні шляхи і hard link |
| setuid | `fentry/commit_creds`, шлях бінарника береться лише всередині `begin_new_exec` | процес не-root отримує root через setuid-бінарник або `setuid()`/`seteuid()` |
| ptrace | `fentry/ptrace_attach` | лише справжні спроби під'єднатися |

PID перераховуються в pid namespace агента, який під WSL і в контейнерах відрізняється від кореневого. Якщо в ядрі немає потрібної функції, агент вимикає тільки хуки, що від неї залежать, і пише попередження; без хуків шляху exec вимикається і хук setuid.

### Обмеження

- Шляхи, довші за 255 символів, записуються в тому вигляді, як їх передали в exec.
- chroot у user namespace може замаскувати шлях до файлу.
- Агент не бачить процесів у pid namespace вище за свій, тож запускайте його в найзовнішньому namespace, за яким треба стежити.
- Агент бачить лише TCP-з'єднання. `connect()` для UDP до нього не доходить.
- Kill надсилається з userspace, тому процес встигає завершити системний виклик, на який спрацювало правило. Теоретично між подією і kill PID може бути використаний повторно.
- Allow-list для `ptrace_attach` і `shadow_read` працюють за іменем процесу, яке процес може змінити сам собі.
- Запуск файлу з `/tmp` через динамічний завантажувач (`ld-linux.so /tmp/x`) не є exec цього файлу, тож `exec_from_tmp` його не ловить.
- Дерево процесів знає лише те, що бачило. Родовід, розірваний до старту агента, не відновлюється.
- Відстежувані файли (`openat`) перечитуються кожні 5 секунд, тож після заміни файлу перейменуванням є коротке вікно. Їх може бути не більше 64. Якщо два шляхи з правил ведуть до одного файлу (symlink або hard link), спрацьовує правило з першим шляхом, і агент попереджає про це під час запуску.
