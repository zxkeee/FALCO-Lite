#!/usr/bin/env bash
# E2E: три атаки з демо проти живого агента.
#
#   make e2e        (потрібні root і ядро з BTF)
#
# Пройде повністю після MVP (тиждень 4): потрібні хуки connect/openat,
# рушій правил, дерево процесів, kill і JSON-лог. До того падіння цього
# скрипта очікуване: він показує, чого ще бракує.
set -u
cd "$(dirname "$0")/../.."

LOG=$(mktemp --suffix=.jsonl)
OUT=$(mktemp)
fail=0

./falco-lite -c rules/rules.yaml --json "$LOG" >"$OUT" 2>&1 &
AGENT=$!
trap 'kill -INT $AGENT 2>/dev/null; wait $AGENT 2>/dev/null; rm -f "$LOG" "$OUT"' EXIT
sleep 2

# 1. Reverse shell: bash під «php-fpm» підключається до 127.0.0.1:4444.
#    Слухач не потрібен: правило спрацьовує на сам connect().
timeout 5 .output/e2e/php-fpm 4444 >/dev/null 2>&1

# 2. Запуск із /tmp.
X=$(mktemp /tmp/.falco-e2e.XXXXXX)
cp /bin/true "$X" && chmod +x "$X" && "$X"
rm -f "$X"

# 3. Читання /etc/shadow (скрипт і так під root, але cat не в allow-list).
cat /etc/shadow >/dev/null

sleep 1

expect() { # expect <правило> <опис>
	if grep -q "\"rule\":\"$1\"" "$LOG"; then
		echo "  ok    $2"
	else
		echo "  FAIL  $2 (немає \"rule\":\"$1\" у JSON-лозі)"
		fail=1
	fi
}

echo "e2e:"
expect reverse_shell "reverse shell з-під php-fpm"
expect exec_from_tmp "запуск із /tmp"
expect shadow_read "читання /etc/shadow"

if [ "$fail" -ne 0 ]; then
	echo "--- вивід агента ---"
	cat "$OUT"
fi
exit "$fail"
