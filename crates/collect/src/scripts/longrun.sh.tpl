export LC_ALL=C
MIN={{o.minSeconds}}; U={{o.minUid}}
if [ -z "$U" ]; then U=$(awk '$1 == "UID_MIN" { print $2; exit }' /etc/login.defs 2>/dev/null); fi
case "$U" in (''|*[!0-9]*) U=1000 ;; esac
JT=''
command -v timeout >/dev/null 2>&1 && JT='timeout 15'
echo @@whoami
id -u
echo @@uidmin
echo "$U"
echo @@ps_total
ps -A -o pid= 2>/dev/null | wc -l
echo @@procs
ps -A -o pid=,ppid=,uid=,user=,etime=,pcpu=,pmem=,rss=,stat=,args= 2>/dev/null | awk -v min="$MIN" -v umin="$U" '
  function secs(t,  d,n,a) {
    d = 0
    if (index(t, "-")) { d = substr(t, 1, index(t, "-") - 1); t = substr(t, index(t, "-") + 1) }
    n = split(t, a, ":")
    if (n == 3) return d * 86400 + a[1] * 3600 + a[2] * 60 + a[3]
    if (n == 2) return d * 86400 + a[1] * 60 + a[2]
    return d * 86400 + a[1]
  }
  $3 + 0 >= umin && $3 != 65534 { e = secs($5); if (e >= min) { $5 = e; print } }' | cut -c1-400 | head -n 3000
echo @@slurm
command -v squeue >/dev/null 2>&1 && $JT squeue -h -t R -o '%i|%u|%M|%D|%P|%j' 2>/dev/null | head -n 2000
echo @@end
