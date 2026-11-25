#!/bin/bash
set -u

cd "$(dirname "$0")/.."
DEMO=/var/lib/falco-lite-demo
LOG=$DEMO/alerts.json
TMP_PAYLOAD=/tmp/.falco-demo
USER_NAME=${1:-${SUDO_USER:-}}
PASS=0
FAIL=0

if [ "$(id -u)" != 0 ]; then
	echo "run as root: sudo bash demo/run.sh [user]"
	exit 1
fi
if [ -z "$USER_NAME" ] || [ "$USER_NAME" = root ]; then
	echo "usage: sudo bash demo/run.sh <non-root user>"
	exit 1
fi
if [ ! -x ./falco-lite ]; then
	echo "build first: make"
	exit 1
fi

as_user() {
	timeout 10 runuser -u "$USER_NAME" -- "$@" >/dev/null 2>&1
}

check() {
	local title=$1 rule=$2 result=$3 code=$4 want=$5
	sleep 0.3
	if grep -q "\"rule\":\"$rule\",\"action\":\"[a-z]*\",\"result\":\"$result\"" "$LOG" && [ "$code" = "$want" ]; then
		echo "[PASS] $title: $rule -> $result (exit $code)"
		PASS=$((PASS + 1))
	else
		echo "[FAIL] $title: expected $rule -> $result with exit $want, got exit $code"
		FAIL=$((FAIL + 1))
	fi
}

cleanup() {
	kill -INT "$AGENT" 2>/dev/null
	wait "$AGENT" 2>/dev/null
	kill $LISTENERS 2>/dev/null
	pkill -x ptrace_attach 2>/dev/null
	rm -f "$TMP_PAYLOAD" "$DEMO/rootsh"
}

rm -rf "$DEMO"
mkdir -p "$DEMO"
chmod 755 "$DEMO"
cp /usr/bin/bash "$DEMO/php-fpm"
cp /usr/bin/sleep "$DEMO/xmrig"
gcc -O2 -o "$DEMO/ptrace_attach" demo/ptrace_attach.c
cp /usr/bin/sleep "$TMP_PAYLOAD"
chmod 755 "$TMP_PAYLOAD"

nc -l 127.0.0.1 9001 >/dev/null 2>&1 &
LISTENERS=$!
nc -l 127.0.0.1 9002 >/dev/null 2>&1 &
LISTENERS="$LISTENERS $!"
nc -l 127.0.0.1 9003 >/dev/null 2>&1 &
LISTENERS="$LISTENERS $!"
nc -l 127.0.0.1 3333 >/dev/null 2>&1 &
LISTENERS="$LISTENERS $!"

./falco-lite -c rules.yaml -j "$LOG" > "$DEMO/agent.log" 2>&1 &
AGENT=$!
trap cleanup EXIT

for _ in $(seq 100); do
	grep -q "watching" "$DEMO/agent.log" && break
	sleep 0.1
done
if ! grep -q "watching" "$DEMO/agent.log"; then
	cat "$DEMO/agent.log"
	exit 1
fi

as_user "$DEMO/php-fpm" -c 'bash -c "bash -i >& /dev/tcp/127.0.0.1/9001 0>&1"; exit $?'
check "reverse shell" reverse_shell killed $? 137

as_user "$DEMO/php-fpm" -c 'bash -c "sleep 0.5; bash -i >& /dev/tcp/127.0.0.1/9003 0>&1" & exit 0'
sleep 1.5
if [ "$(grep -c '"rule":"reverse_shell","action":"kill","result":"killed"' "$LOG")" = 2 ]; then
	echo "[PASS] background reverse shell after parent exit: reverse_shell -> killed"
	PASS=$((PASS + 1))
else
	echo "[FAIL] background reverse shell after parent exit was not killed"
	FAIL=$((FAIL + 1))
fi

as_user bash -c "cd /tmp && ./.falco-demo 5"
check "exec from /tmp" exec_from_tmp killed $? 137

as_user bash -c "cd /etc && cat shadow"
check "read /etc/shadow" shadow_read alerted $? 1

install -o root -g root -m 4755 /usr/bin/sleep "$DEMO/rootsh"
as_user "$DEMO/rootsh" 5
check "setuid root" setuid_root killed $? 137
rm -f "$DEMO/rootsh"

as_user "$DEMO/ptrace_attach"
check "ptrace attach" ptrace_attach killed $? 137

as_user "$DEMO/xmrig" 5
check "miner exec" miner_exec killed $? 137

as_user bash -c "exec 3<>/dev/tcp/127.0.0.1/3333; sleep 5"
check "miner pool" miner_pool killed $? 137

BEFORE=$(wc -l < "$LOG")
as_user ls /tmp
as_user id
as_user bash -c "exec 3<>/dev/tcp/127.0.0.1/9002"
cat /etc/hostname >/dev/null
sleep 0.5
AFTER=$(wc -l < "$LOG")
if [ "$BEFORE" = "$AFTER" ]; then
	echo "[PASS] benign commands: no alerts"
	PASS=$((PASS + 1))
else
	echo "[FAIL] benign commands raised $((AFTER - BEFORE)) alert(s)"
	FAIL=$((FAIL + 1))
fi

echo
echo "passed: $PASS, failed: $FAIL"
echo "alerts: $LOG"
[ "$FAIL" = 0 ]
