export LC_ALL=C
echo @@kv
echo "hostname=$(hostname 2>/dev/null)"
echo "kernel=$(uname -sr 2>/dev/null)"
echo "os=$( (. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME") )"
echo "cores=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
echo "uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)"
echo "loadavg=$(cat /proc/loadavg 2>/dev/null)"
echo "zombies=$(ps -eo stat= 2>/dev/null | grep -c '^Z')"
echo "reboot_required=$([ -f /var/run/reboot-required ] && echo yes || echo no)"
echo "ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
if command -v journalctl >/dev/null 2>&1 && journalctl -k -n 1 -q --no-pager >/dev/null 2>&1; then
  echo "oom_24h=$(journalctl -k --since -24h --no-pager -q 2>/dev/null | grep -ciE 'out of memory|oom-kill|killed process')"
  echo "kerr_24h=$(journalctl -k -p err --since -24h --no-pager -q 2>/dev/null | wc -l)"
fi
if command -v journalctl >/dev/null 2>&1 && [ -n "$(journalctl -u sshd -u ssh -n 1 -q --no-pager 2>/dev/null)" ]; then
  echo "sshfail_1h=$(journalctl -u sshd -u ssh --since -1h -q --no-pager 2>/dev/null | grep -ciE 'failed password|failed publickey|invalid user|authentication failure')"
fi
echo @@meminfo
grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
echo @@cpu
head -n 1 /proc/stat 2>/dev/null; n0=$(cat /proc/net/dev 2>/dev/null); t0=$(grep '^Tcp:' /proc/net/snmp 2>/dev/null); sleep 1; head -n 1 /proc/stat 2>/dev/null
echo @@netdev
printf '%s\n' "$n0"; echo --; cat /proc/net/dev 2>/dev/null
echo @@netphys
for i in /sys/class/net/*; do [ -e "$i/device" ] && echo "$i"; done 2>/dev/null
echo @@tcp
printf '%s\n' "$t0"; grep '^Tcp:' /proc/net/snmp 2>/dev/null
echo @@df
d=$(df -PkT -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null); [ "$(printf '%s\n' "$d" | wc -l)" -ge 2 ] || d=$(df -Pk 2>/dev/null); printf '%s\n' "$d"
echo @@dfi
d=$(df -Pi -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs 2>/dev/null); [ "$(printf '%s\n' "$d" | wc -l)" -ge 2 ] || d=$(df -Pi 2>/dev/null); printf '%s\n' "$d"
echo @@failed
systemctl list-units --state=failed --no-legend --plain --no-pager 2>/dev/null | awk '{print $1}'
echo @@topcpu
ps -eo pid=,user=,pcpu=,pmem=,etimes=,comm= --sort=-pcpu 2>/dev/null | head -n 5
echo @@topmem
ps -eo pid=,user=,pcpu=,pmem=,etimes=,comm= --sort=-pmem 2>/dev/null | head -n 5
echo @@gpu
nvidia-smi --query-gpu=index,uuid,name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>/dev/null
echo @@gpuapps
nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory,process_name --format=csv,noheader,nounits 2>/dev/null
echo @@slurm
command -v sinfo >/dev/null 2>&1 && sinfo -h -o '%T|%D' 2>/dev/null
echo @@slurmbad
command -v sinfo >/dev/null 2>&1 && sinfo -h -N -t drain,draining,down,fail,failing,not_responding -o '%N|%T|%E' 2>/dev/null | sort -u | head -n 50
echo @@squeue
command -v squeue >/dev/null 2>&1 && squeue -h -o '%T' 2>/dev/null | sort | uniq -c
echo @@listen
if command -v ss >/dev/null 2>&1; then ss -tln 2>/dev/null | awk 'NR>1{print $4}'; elif command -v netstat >/dev/null 2>&1; then netstat -tln 2>/dev/null | awk 'NR>2{print $4}'; fi
echo @@logins
last -i -w -n 100 2>/dev/null | awk 'NF>=3 && $1!="reboot" && $1!="shutdown" && $1!="wtmp" && $3!="0.0.0.0" {print $1" "$3}' | sort -u | head -n 32
echo @@kerr
if command -v journalctl >/dev/null 2>&1; then journalctl -k -p err --since -24h --no-pager -q 2>/dev/null | tail -n 5; fi
echo @@end
