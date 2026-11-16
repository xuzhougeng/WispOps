export LC_ALL=C
H=30
echo @@whoami
id -u
authlog() {
  j=""
  if command -v journalctl >/dev/null 2>&1; then
    j=$( { journalctl -q --no-pager --since "-$H h" _COMM=sshd; journalctl -q --no-pager --since "-$H h" -u ssh -u sshd; } 2>/dev/null )
  fi
  if [ -n "$j" ]; then printf '%s\n' "$j"; return; fi
  # Without a readable journal, fall back to the tail of the classic files (not windowed by time).
  for f in /var/log/auth.log /var/log/secure; do [ -r "$f" ] && tail -n 200000 "$f"; done
}
lines=$(authlog | grep -E 'sshd\[' | sort -u)
echo @@authsrc
if [ -n "$lines" ]; then echo readable; else echo unreadable; fi
echo @@failed
printf '%s\n' "$lines" | grep -E 'Failed (password|publickey)|Invalid user|authentication failure|Connection closed by authenticating user|Disconnected from invalid user' \
  | grep -oE '(from|rhost=) ?[0-9a-fA-F:.]+' | awk '{ print $NF }' | sed 's/^rhost=//' | sort | uniq -c | sort -rn | head -n 20
echo @@accepted
printf '%s\n' "$lines" | grep -E 'Accepted (password|publickey|keyboard-interactive)' \
  | sed -E 's/.*Accepted ([a-z-]+) for ([^ ]+) from ([^ ]+).*/\1 \2 \3/' | sort | uniq -c | sort -rn | head -n 30
echo @@who
who 2>/dev/null
echo @@listen
ss -H -lntup 2>/dev/null | awk '{ print $1 "\t" $5 "\t" $7 }' | head -n 100
echo @@estab
ss -H -tn state established 2>/dev/null | awk '{ print $4 }' | sed -E 's/:[0-9]+$//; s/^\[|\]$//g' | sort | uniq -c | sort -rn | head -n 15
echo @@synrecv
ss -H -tn state syn-recv 2>/dev/null | wc -l
echo @@outbound
ss -H -tnp state established 2>/dev/null | awk '{ print $4 "\t" $5 }' | head -n 2000
echo @@procs
ps -eo pid=,user=,pcpu=,etimes=,comm=,args= --sort=-pcpu 2>/dev/null | head -n 40 | cut -c1-240
echo @@badexe
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  # Kernel usermode helpers (children of kthreadd, e.g. bpfilter_umh) run from memory and show as "/ (deleted)".
  [ "$(awk '/^PPid:/ { print $2 }' "$p/status" 2>/dev/null)" = 2 ] && continue
  case "$e" in
    (*" (deleted)")
      # A binary replaced by an upgrade leaves a new file at the same path.
      f=${e% (deleted)}; r=missing; [ -n "$f" ] && [ "$f" != / ] && [ -e "$f" ] && r=replaced
      printf '%s\t%s\t%s\t%s\n' "${p#/proc/}" "$(cat "$p/comm" 2>/dev/null)" "$e" "$r" ;;
    (/tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*/tmp*) printf '%s\t%s\t%s\t-\n' "${p#/proc/}" "$(cat "$p/comm" 2>/dev/null)" "$e" ;;
  esac
done | head -n 50
echo @@uid0
awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null
echo @@keys
for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
  [ -f "$f" ] && find "$f" -mtime -2 -printf '%T@\t%u\t%p\n' 2>/dev/null
done
echo @@cron
find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /var/spool/cron/crontabs -xdev -type f -mtime -2 -printf '%T@\t%u\t%p\n' 2>/dev/null | head -n 50
echo @@units
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f -name '*.service' -mtime -2 -printf '%T@\t%u\t%p\n' 2>/dev/null | head -n 50
echo @@sshd
(sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null) | grep -iE '^(permitrootlogin|passwordauthentication|pubkeyauthentication|port) ' | head -n 10
echo @@fail2ban
command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd 2>/dev/null | grep -E 'Currently banned|Total banned' | tr -s ' \t' ' '
echo @@end
