export LC_ALL=C
DAYS=7; D=3; N=20; LIST=$((10 * 1048576)); MAXF=5000
TO=""; TK=""
if command -v timeout >/dev/null 2>&1; then TO="timeout 300"; TK="timeout 30"; fi
TAB=$(printf '\t')
echo @@whoami
id -u
echo @@gnufind
find / -maxdepth 0 -printf 'ok\n' 2>/dev/null
echo @@now
date +%s
scan() {
  for R in '/data' '/it'\''s here'; do
    printf 'ROOT\t%s\n' "$R"
    $TO find "$R" -xdev -type f -mtime -"$DAYS" -printf '%s\t%T@\t%u\t%p\n' 2>/dev/null
    printf 'RC\t%s\t%s\n' "$?" "$R"
  done
}
agg=$(scan | awk -F'\t' -v depth="$D" -v list="$LIST" '
  $1 == "ROOT" { root = $2; next }
  $1 == "RC" { print "R\t" $2 "\t" $3; next }
  {
    size = $1; total += size; n++
    rel = substr($4, length(root) + 2); m = split(rel, parts, "/")
    k = root; for (i = 1; i <= depth && i < m; i++) k = k "/" parts[i]
    ds[k] += size; dn[k]++
    us[$3] += size; un[$3]++
    if (size >= list) print "F\t" $0
  }
  END {
    print "T\t" total + 0 "\t" n + 0
    for (k in ds) print "D\t" ds[k] "\t" dn[k] "\t" k
    for (u in us) print "U\t" us[u] "\t" un[u] "\t" u
  }')
echo @@total
printf '%s\n' "$agg" | awk -F'\t' '$1 == "T" { print $2 "\t" $3 }'
echo @@rc
printf '%s\n' "$agg" | awk -F'\t' '$1 == "R" { print $2 "\t" $3 }'
echo @@dirs
printf '%s\n' "$agg" | awk -F'\t' '$1 == "D" { print $2 "\t" $3 "\t" $4 }' | sort -rn | head -n "$N"
echo @@users
printf '%s\n' "$agg" | awk -F'\t' '$1 == "U" { print $2 "\t" $3 "\t" $4 }' | sort -rn | head -n 20
echo @@files
flist=$(printf '%s\n' "$agg" | awk -F'\t' '$1 == "F" { print $2 "\t" $3 "\t" $4 "\t" $5 }' | sort -rn | head -n "$MAXF")
printf '%s\n' "$flist"
opn=$( { printf '%s\n' "$flist" | cut -f4; echo '@@SPLIT@@'; find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%p\t%l\n' 2>/dev/null; } \
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

echo @@pipelines
for R in '/data' '/it'\''s here'; do
  $TO find "$R" -xdev -maxdepth 6 -type d \( -name work -o -name .snakemake -o -name _STARtmp -o -name 'SC_*_CS' -o -name '*_tmp' -o -name tmp \) -prune -print 2>/dev/null
done | head -n 100 | while IFS= read -r d; do
  base=$(basename "$d"); parent=$(dirname "$d"); state=-
  case "$base" in
    (work)
      ls "$d" 2>/dev/null | grep -qE '^[0-9a-f]{2}$' || continue
      if [ -f "$parent/.nextflow.log" ]; then
        if tail -n 50 "$parent/.nextflow.log" 2>/dev/null | grep -q 'Execution complete -- Goodbye'; then state=complete
        elif tail -n 300 "$parent/.nextflow.log" 2>/dev/null | grep -qiE 'Execution aborted|Session aborted|ERROR ~'; then state=failed
        else state=running-or-unknown; fi
      fi ;;
    (.snakemake)
      if [ -n "$(ls -A "$d/incomplete" 2>/dev/null)" ]; then state=incomplete-jobs; elif [ -d "$d/locks" ] && [ -n "$(ls -A "$d/locks" 2>/dev/null)" ]; then state=locked-running; else state=idle; fi ;;
    (SC_*_CS)
      if [ -f "$parent/outs/web_summary.html" ]; then state=complete; else state=no-outs; fi ;;
  esac
  k=$($TK du -sxk "$d" 2>/dev/null | cut -f1)
  m=$(find "$d" -maxdepth 0 -printf '%T@' 2>/dev/null)
  printf '%s\t%s\t%s\t%s\n' "${k:--}" "${m:-0}" "$state" "$d"
done
echo @@end
