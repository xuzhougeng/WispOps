#!/bin/sh
# The README's screenshots, from a debug build on macOS, against the fictional fleet of
# inventory.yml: fake-ssh.py answers for its servers and fake-model.py plays the assistant's
# side of one conversation. Nothing of this computer, its ~/.ssh or a real model is used.
#
#   scripts/screenshots/take.sh [out-dir]      (default docs/screenshots)
#
# A first run of the window fills a fresh data folder (probes, thirty inspections, two disk
# scans, the long-task check, the attack triage, three routine tasks); the records are then
# dated back over the past days, and a second run photographs the pages and the assistant.
# The window is 1400×880 points; the pictures are scaled to 1600 pixels wide.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:-$root/docs/screenshots}
work=$(mktemp -d "${TMPDIR:-/tmp}/wispops-shots.XXXXXX")
model=""
trap '[ -n "$model" ] && kill "$model" 2>/dev/null; rm -rf "$work"' EXIT

export WISP_OPS_HOME="$work/home" WISP_OPS_VAULT_KEY=file DEMO_STATE="$work/state"
mkdir -p "$WISP_OPS_HOME" "$out"
cp "$here/inventory.yml" "$WISP_OPS_HOME/inventory.yml"
printf '{"ssh":{"binary":"%s","loadProfile":false}}\n' "$here/fake-ssh.py" > "$WISP_OPS_HOME/config.json"

python3 -I "$here/fake-model.py" "$work/port" &
model=$!
while [ ! -s "$work/port" ]; do sleep 0.1; done
cat > "$WISP_OPS_HOME/settings.json" <<EOF
{"providers":[{"name":"示例模型","protocol":"openai","baseUrl":"http://127.0.0.1:$(cat "$work/port")/v1","apiKey":"demo","models":[{"id":"m1","model":"demo"}]}],"chatModel":"m1","autoUpdateCheck":false}
EOF

(cd "$root" && cargo build --features runtime_shaders --quiet 2>"$work/build.log") || { cat "$work/build.log"; exit 1; }
app="$root/target/debug/wisp_ops"

# 1. Fill the data folder: one inspection a second, then the scans and the routine tasks.
steps="probe:all"
i=1
while [ "$i" -le 30 ]; do steps="$steps,$i@inspect:all"; i=$((i + 1)); done
steps="$steps,33@disk-scan:gpu-02/full,36@disk-scan:gpu-02/again,38@long-check:all,40@attack-scan:all"
steps="$steps,42@run-task:morning-inspect,44@run-task:gpu-data-space,46@run-task:edge-security"
steps="$steps,48@toggle-task:morning-inspect,48@toggle-task:gpu-data-space,48@toggle-task:edge-security,48@toggle-task:weekly-inspect,50@quit"
WISP_OPS_DEV="$steps" "$app" >/dev/null 2>&1

# 2. Date the records back, as a month of daily inspections would have left them.
python3 -I "$here/age.py" "$WISP_OPS_HOME"

# 3. The overview in dark mode, for readers whose GitHub is dark.
WISP_OPS_DEV="dark,page:overview,3@shot:$out/overview-dark.png,4@quit" "$app" 2>&1 | grep '^shot' || true

# 4. The pages, then the assistant asked which disk is filling up: it inspects, diagnoses
#    and proposes a cleanup that waits for approval.
ask="哪台服务器的磁盘快满了？先巡检，再对最紧张的那台做磁盘诊断，告诉我是什么占用的、哪些可以清理。"
WISP_OPS_DEV="page:overview,3@shot:$out/overview.png,\
4@page:servers,5@host:gpu-02,7@shot:$out/servers.png,\
8@page:disk,9@disk-host:gpu-02,11@shot:$out/disk.png,\
12@page:jobs,14@shot:$out/long-jobs.png,\
15@page:security,16@open-attack:bastion,18@shot:$out/security.png,\
19@page:tasks,21@shot:$out/tasks.png,\
22@page:assistant,23@ask:$ask,30@shot:$out/assistant.png,\
31@quit" "$app" 2>&1 | grep '^shot' || true

# 5. 1600 pixels wide: sharp at the width GitHub gives a README, a third of the bytes.
for picture in "$out"/*.png; do sips --resampleWidth 1600 "$picture" >/dev/null; done
ls -l "$out"
