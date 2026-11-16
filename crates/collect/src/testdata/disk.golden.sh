export LC_ALL=C
P='/da'\''ta/x y'; D=2; N=10; MIN=100; RMIN=10; REC=1440
TO=""; TK=""
if command -v timeout >/dev/null 2>&1; then TO="timeout 60"; TK="timeout 15"; fi
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
opn=$( { printf '%s\n' "$files" | cut -f4; echo '@@SPLIT@@'; find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%p\t%l\n' 2>/dev/null; } \
  | awk -F'\t' 'phase == 0 { if ($0 == "@@SPLIT@@") { phase = 1; next } want[$0] = 1; next }
      (($2 in want) || index($2, "(deleted)") > 0) { split($1, a, "/"); print a[3] "\t" $1 "\t" $2 }' \
  | while IFS="$TAB" read -r pid fd target; do
      case "$target" in (*"(deleted)") s=$(stat -L -c %s "$fd" 2>/dev/null || echo 0) ;; (*) s=- ;; esac
      printf '%s\t%s\t%s\n' "$pid" "$s" "$target"
    done | sort -u | head -n 2000 )
echo @@open
printf '%s\n' "$opn"
echo @@procs
pids=$(printf '%s\n' "$opn" | cut -f1 | grep -E '^[0-9]+$' | sort -un | head -n 500 | tr '\n' ',' | sed 's/,$//')
[ -n "$pids" ] && ps -o pid=,user=,etimes=,comm= -p "$pids" 2>/dev/null

JT=''
command -v timeout >/dev/null 2>&1 && JT='timeout 15'
echo @@jobs
command -v squeue >/dev/null 2>&1 && $JT squeue -h -t R,CG,S -o '%i|%u|%Z' 2>/dev/null | head -n 500
echo @@pbs_jobs
if command -v qstat >/dev/null 2>&1; then
  $JT qstat -f 2>/dev/null | awk '
    function emit(  n,a,i,d,u) {
      if (state !~ /^(R|E|S|B)$/) return
      n=split(vars,a,","); d=""
      for(i=1;i<=n;i++) if(a[i] ~ /^PBS_O_WORKDIR=/) d=substr(a[i],15)
      u=owner; sub(/@.*/,"",u)
      if (d ~ /^\// && id != "") print id "|" u "|" d
    }
    /^Job Id:/ {emit(); id=$3; state=""; owner=""; vars=""; key=""; next}
    /^[ \t]+[A-Za-z_][A-Za-z0-9_.]* = / {
      line=$0; sub(/^[ \t]+/,"",line); key=line; sub(/ = .*/,"",key); sub(/^[^=]*= /,"",line)
      if(key=="job_state") state=line
      if(key=="Job_Owner") owner=line
      if(key=="Variable_List") vars=line
      next
    }
    key=="Variable_List" && /^[ \t]+/ {line=$0; sub(/^[ \t]+/,"",line); vars=vars line}
    END {emit()}' | head -n 500
fi
echo @@lsf_jobs
command -v bjobs >/dev/null 2>&1 && $JT bjobs -u all -noheader -o "jobid stat user exec_cwd sub_cwd delimiter='|'" 2>/dev/null | head -n 500

echo @@journal
command -v journalctl >/dev/null 2>&1 && journalctl --disk-usage 2>/dev/null
echo @@docker
command -v docker >/dev/null 2>&1 && $TK docker system df 2>/dev/null
echo @@known
for d in '/var/log' '/var/log/journal' '/var/cache/apt/archives' '/var/cache/yum' '/var/cache/dnf' '/var/lib/docker' '/var/lib/containerd' '/var/crash' '/var/lib/systemd/coredump' '/tmp' '/var/tmp' "$HOME/.cache/pip" "$HOME/.cache/huggingface" "$HOME/.conda/pkgs" "$HOME/miniconda3/pkgs" "$HOME/anaconda3/pkgs" '/opt/conda/pkgs' '/root/.cache'; do
  [ -d "$d" ] || continue
  k=$($TK du -sxk "$d" 2>/dev/null | cut -f1)
  m=$(df -P "$d" 2>/dev/null | awk 'NR == 2 { print $NF }')
  printf '%s\t%s\t%s\n' "${k:--}" "$m" "$d"
done
echo @@rotated
find /var/log -xdev -type f \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.[0-9]' -o -name '*.old' \) -printf '%s\n' 2>/dev/null | awk '{ s += $1; n++ } END { print s + 0 "\t" n + 0 }'
echo @@end
