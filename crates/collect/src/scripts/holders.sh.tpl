opn=$( { printf '%s\n' "${{listVar}}" | cut -f4; echo '@@SPLIT@@'; find /proc/[0-9]*/fd -maxdepth 1 -type l -printf '%p\t%l\n' 2>/dev/null; } \
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
{{JOBS_SCRIPT}}
