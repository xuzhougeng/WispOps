export LC_ALL=C
DAYS={{o.days}}; D={{o.depth}}; N={{o.top}}; LIST=$(({{o.listMinMb}} * 1048576)); MAXF={{o.maxFiles}}
TO=""; TK=""
if command -v timeout >/dev/null 2>&1; then TO="timeout {{o.walkTimeoutSec}}"; TK="timeout {{pipelineTimeout}}"; fi
TAB=$(printf '\t')
echo @@whoami
id -u
echo @@gnufind
find / -maxdepth 0 -printf 'ok\n' 2>/dev/null
echo @@now
date +%s
scan() {
  for R in {{roots}}; do
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
{{holdersScript('flist')}}echo @@pipelines
for R in {{roots}}; do
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
