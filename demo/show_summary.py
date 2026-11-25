import json
import os
import statistics
import sys


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else -1


path = sys.argv[1]
lines = []
if os.path.isfile(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [line.strip() for line in f if line.strip()]

rows = []
for line in lines:
    try:
        value = json.loads(line)
    except ValueError:
        continue
    if isinstance(value, dict):
        rows.append((line, value))

if not rows:
    print("  No alerts were recorded.")
    sys.exit(0)

kills = [(line, r) for line, r in rows if r.get("result") == "killed"]
reported = [r for _, r in rows if r.get("result") == "alerted"]
reactions = [number(r.get("reaction_us")) for _, r in kills]
reactions = [v for v in reactions if v >= 0]

print("  Attacks stopped:  %d killed, %d reported" % (len(kills), len(reported)))
if reactions:
    print("  Reaction:         median %.2f ms, max %.2f ms  (kernel event -> SIGKILL sent)"
          % (statistics.median(reactions) / 1000, max(reactions) / 1000))
print()
for _, r in rows:
    print("  %-14s %-9s %s" % (r.get("rule", "?"), r.get("result", "?"), r.get("chain", "")))
print()
print("  One alert, exactly as written to the log (one JSON object per line):")
print()
print("  " + (kills[0][0] if kills else rows[0][0]))
