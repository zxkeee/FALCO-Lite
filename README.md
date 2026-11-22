# Falco-lite

Агент runtime-захисту Linux на eBPF. Програма на C стежить за системними викликами в ядрі та в реальному часі виявляє підозрілу поведінку процесів: reverse shell, запуск файлів із `/tmp`, читання `/etc/shadow`, підвищення привілеїв, криптомайнери. Правила описуються в YAML-конфігу. Коли правило спрацьовує, агент пише алерт і може сам зупинити процес.

Груповий проєкт з курсу «Процедурне програмування», НаУКМА.

Команда: Микита Вельбовець, Томас Іванаускас, Назар Дяченко.

## Вимоги

Linux з BTF (`/sys/kernel/btf/vmlinux`), x86-64, права root. Перевірено на ядрі 6.18 (WSL2, Ubuntu 26.04). Якщо в іншому ядрі якоїсь функції немає, агент вимикає лише відповідний хук і пише попередження.

```
sudo apt install clang llvm bpftool libbpf-dev libelf-dev libyaml-dev libncurses-dev zlib1g-dev pkg-config make gcc netcat-openbsd
```

## Збірка і запуск

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

Під кожним алертом — ланцюжок предків процесу і, для kill, час від події в ядрі до надісланого SIGKILL. Ті самі дані є в JSON-лозі: поля `chain` і `reaction_us`.

| Опція | Що робить |
|---|---|
| `-c, --config FILE` | файл правил (за замовчуванням `rules.yaml`) |
| `-j, --json FILE` | дописувати алерти у файл, по одному JSON на рядок |
| `-s, --syslog` | надсилати алерти в syslog (`LOG_AUTHPRIV`) |
| `-t, --tui` | панель на ncurses: лічильники подій і останні алерти, `q` для виходу |
| `-n, --dry-run` | нікого не вбивати, лише писати `would_kill` |
| `-v, --verbose` | друкувати кожну подію |

`make static` збирає один статичний бінарник без залежностей.

За замовчуванням агент справді вбиває процеси. На новій машині чи ядрі спершу запустіть `sudo ./falco-lite -n` і перевірте, що `sudo -n true` не дає алерту, а `cd /tmp && ./x` показує повний шлях `/tmp/x`. Лише після цього вмикайте бойовий режим.

## Правила

```yaml
- name: reverse_shell
  when:
    syscall: connect
    proc.comm: [bash, sh, dash, zsh, ksh]
    proc.ancestor: [php-fpm, nginx, apache2, httpd, cron]
  action: kill
```

`syscall`: `execve`, `connect`, `openat`, `setuid`, `ptrace`. `action`: `alert` або `kill`.

| Умова | Значення | Події |
|---|---|---|
| `proc.comm` | ім'я процесу, до 15 символів | усі |
| `proc.ancestor` | ім'я будь-якого предка в дереві процесів, до 15 символів | усі |
| `file.path` | точний шлях | execve, openat, setuid |
| `file.prefix` | початок шляху | execve, setuid |
| `net.port` | порт призначення | connect |

Значення — рядок або список; правило спрацьовує, коли виконуються всі умови, а в межах умови — будь-яке зі значень. Суфікс `.not` інвертує умову: `proc.comm.not: [sshd]`. Правило `openat` обов'язково має список `file.path`: агент стежить саме за цими файлами за їхнім inode.

Невідома умова, помилка в назві, повторений ключ, порожній список, `kill` без жодної умови чи кілька YAML-документів у файлі зупиняють запуск: агент не стартує з правилом, яке означає не те, що написано.

## Атаки з `rules.yaml`

| Правило | Що бачить агент | Реакція |
|---|---|---|
| `reverse_shell` | shell робить `connect()`, а серед предків є веб-сервер або cron, навіть якщо проміжний процес уже завершився (`&`, `setsid`) | SIGKILL |
| `exec_from_tmp` | запуск файлу з `/tmp`, `/dev/shm`, `/var/tmp`, зокрема через `cd /tmp && ./x` | SIGKILL |
| `shadow_read` | відкриття `/etc/shadow` не з allow-list, зокрема невдала спроба | алерт |
| `setuid_root` | процес не-root отримує euid 0 не через sudo, su, passwd тощо | SIGKILL |
| `ptrace_attach` | `PTRACE_ATTACH` до іншого процесу не відладчиком | SIGKILL |
| `miner_exec`, `miner_pool` | запуск відомого майнера або `connect()` на порт stratum-пулу | SIGKILL |

Агент ніколи не вбиває pid 1, себе і своїх предків.

## Тести і демонстрація

```
make test
sudo bash demo/run.sh <звичайний користувач>
```

`make test` перевіряє парсер правил, дерево процесів, рушій і вивід без root. `demo/run.sh` запускає агент у бойовому режимі, від імені звичайного користувача виконує кожну атаку з таблиці та перевіряє реакцію й JSON-лог, а потім переконується, що звичайні команди не дають алертів. Файли демо лежать у `/var/lib/falco-lite-demo`.

CI на GitHub Actions (`.github/workflows/ci.yml`) збирає проєкт, запускає тести, статичну збірку і демо.

## Живе демо для презентації

```
sudo bash demo/show.sh
```

Кероване демо англійською в tmux: зверху ведучий із підписами, посередині web shell атакувальника в php-fpm (звичайний користувач) і його машина-приймач на `127.0.0.1:9001`, знизу Falco-lite. Доповідач натискає Enter, і сцени йдуть одна за одною:

1. reverse shell без захисту: атакувальник отримує shell і виконує команди;
2. запуск Falco-lite;
3. той самий reverse shell — убитий;
4. shell через `setsid -f`, батько вже завершився — убитий;
5. payload у `/tmp`, запущений як `./.kworker` — убитий;
6. читання `/etc/shadow` — алерт, хоча ОС відмовила;
7. SUID-root бінарник — убитий у момент отримання root;
8. «майнер» на Python до порту пулу 3333 — убитий;
9. підсумок: скільки атак зупинено, час реакції, приклад JSON.

Потрібен термінал щонайменше 160×45. Перед показом скрипт 5 секунд дивиться на машину в режимі dry-run і питає, чи продовжувати, якщо агент зреагував би на вже запущені процеси. Після виходу (`q` або остання сцена) він зупиняє агент і прибирає payload і SUID-файл. Робочі файли лежать у `/srv/falco-demo`.

## Накладні витрати

Виміряно на цьому ноутбуці (WSL2, Ryzen 9 5900HS, ядро 6.18): цикл із 5000 запусків `/bin/true` поспіль — 4,85 с без агента і 5,10 с з агентом (медіани трьох прогонів), тобто близько 5% у найгіршому випадку, коли система лише створює процеси. Процесорний час агента — 0,57 с на 15 000 таких процесів (близько 38 мкс на процес, тобто на fork, exec і exit), пам'ять — 14 МБ.

## Wazuh і syslog

Wazuh читає JSON-лог агента як `localfile`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/falco-lite.json</location>
</localfile>
```

```
sudo ./falco-lite -j /var/log/falco-lite.json -s
```

## Архітектура

```
ядро:       execve  fork  exit  connect  openat  setuid  ptrace
              │      │     │       │        │       │       │
              └──────┴─────┴── ring buffer (struct event) ──┘
userspace:  читач подій → дерево процесів → рушій правил → kill / JSON / syslog / TUI
```

| Модуль | Файли |
|---|---|
| eBPF-програми | `bpf/falco.bpf.c`, `src/event.h`, `src/loader.c` (завантаження, підключення хуків, відстежувані файли) |
| Рушій правил | `src/rules/` (`rules.c` — парсер, `engine.c` — зіставлення), `src/proctree/` |
| Реакція та вивід | `src/response/` (`response.c`, `output.c`), `src/tui/`, `src/main.c`, `tests/`, `demo/`, `.github/` |

Хуки:

| Подія | Хук | Чому саме він |
|---|---|---|
| execve | `sched_process_exec` + `fentry/security_file_open` з `bpf_d_path`, скидання в `fentry/alloc_bprm` | повний шлях файлу навіть для `./x`, скриптів і 32-бітних викликів |
| fork, exit | `tp_btf/sched_process_fork`, `sched_process_exit` | дерево процесів без розривів на воркерах без exec |
| connect | `fentry/tcp_v4_connect`, `fentry/tcp_v6_connect` | IPv4 та IPv6, будь-який спосіб виклику |
| openat | `fexit/may_open` за inode файлу | ловить відмову доступу, відносні шляхи та hard link |
| setuid | `fentry/commit_creds`, шлях бінарника лише всередині `begin_new_exec` | процес не-root отримує root: setuid-бінарник або `setuid()`/`seteuid()` |
| ptrace | `fentry/ptrace_attach` | лише реальні спроби під'єднатися |

PID перераховуються у pid namespace агента (у WSL і контейнерах він відрізняється від кореневого). Якщо якоїсь функції ядра немає, агент вимикає лише цей хук і пише попередження.

## Обмеження

- Шляхи довші за 255 символів записуються в тому вигляді, як їх передали в exec.
- chroot у user namespace може замаскувати шлях до файлу.
- Агент має працювати в основному pid namespace машини: процеси поза його namespace він не бачить.
- Kill виконується з userspace, тож процес встигає зробити сам системний виклик, на який спрацювало правило; між подією і kill PID теоретично може бути перевикористаний.
- Allow-list для `ptrace_attach` і `shadow_read` — за іменем процесу, яке процес може змінити собі сам.
- Запуск файлу з `/tmp` через динамічний завантажувач (`ld-linux.so /tmp/x`) не є exec цього файлу і правилом `exec_from_tmp` не ловиться.
- Дерево процесів знає лише те, що бачило: родовід, розірваний до старту агента, не відновлюється.
- Відстежувані файли (`openat`) перечитуються кожні 5 секунд, тож після заміни файлу перейменуванням є коротке вікно. Їх може бути не більше 64; якщо два шляхи з правил ведуть до одного файлу (symlink, hard link), спрацьовує правило з першим шляхом, а агент попереджає про це при старті.
