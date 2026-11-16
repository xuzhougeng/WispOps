export LC_ALL=C
P={{shellQuote(o.path)}}; D={{o.depth}}; N={{o.top}}; MIN={{o.minFileMb}}; RMIN={{o.recentMinFileMb}}; REC={{o.recentMinutes}}
TO=""; TK=""
if command -v timeout >/dev/null 2>&1; then TO="timeout {{o.walkTimeoutSec}}"; TK="timeout {{knownTimeout}}"; fi
TAB=$(printf '\t')
echo @@whoami
id -u
echo @@gnufind
find / -maxdepth 0 -printf 'ok\n' 2>/dev/null
echo @@df
d=$(df -PkT "$P" 2>/dev/null); [ "$(printf '%s\n' "$d" | wc -l)" -ge 2 ] || d=$(df -Pk "$P" 2>/dev/null); printf '%s\n' "$d"
echo @@dfi
df -Pi "$P" 2>/dev/null
echo @@du
out=$($TO du -xk -d "$D" "$P" 2>/dev/null); rc=$?
printf '%s\n' "$out" | sort -rn | head -n $((N + 1))
echo @@du_rc
echo "$rc"
NOW=$(date +%s)
files=$($TO find "$P" -xdev -type f -size +"$RMIN"M -printf '%s\t%T@\t%u\t%p\n' 2>/dev/null); frc=$?
echo @@big
printf '%s\n' "$files" | awk -F'\t' -v m=$((MIN * 1048576)) '$1 >= m' | sort -rn | head -n "$N"
echo @@recent
printf '%s\n' "$files" | awk -F'\t' -v t=$((NOW - REC * 60)) '$2 >= t' | sort -rn | head -n "$N"
echo @@find_rc
echo "$frc"
echo @@now
echo "$NOW"
{{holdersScript('files')}}echo @@journal
command -v journalctl >/dev/null 2>&1 && journalctl --disk-usage 2>/dev/null
echo @@docker
command -v docker >/dev/null 2>&1 && $TK docker system df 2>/dev/null
echo @@known
for d in {{known}}; do
  [ -d "$d" ] || continue
  k=$($TK du -sxk "$d" 2>/dev/null | cut -f1)
  m=$(df -P "$d" 2>/dev/null | awk 'NR == 2 { print $NF }')
  printf '%s\t%s\t%s\n' "${k:--}" "$m" "$d"
done
echo @@rotated
find /var/log -xdev -type f \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.[0-9]' -o -name '*.old' \) -printf '%s\n' 2>/dev/null | awk '{ s += $1; n++ } END { print s + 0 "\t" n + 0 }'
echo @@end
