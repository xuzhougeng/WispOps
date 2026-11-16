export LC_ALL=C
P='/da'\''ta'; D=5; N=4; MIN=1024
TO=""
if command -v timeout >/dev/null 2>&1; then TO="timeout 300"; fi
echo @@whoami
id -u
echo @@df
d=$(df -PkT "$P" 2>/dev/null); [ "$(printf '%s\n' "$d" | wc -l)" -ge 2 ] || d=$(df -Pk "$P" 2>/dev/null); printf '%s\n' "$d"
echo @@du
{ $TO du -xk -d "$D" "$P" 2>/dev/null; printf '@@rc\t%s\n' "$?"; } \
  | awk -F'\t' -v min="$MIN" '$1 == "@@rc" || $1 >= min' \
  | sort -rn \
  | awk -F'\t' -v n="$N" '$1 == "@@rc" { rc = $2; next } { c++ } c <= n { print } END { print "@@du_rc"; print rc + 0; print "@@du_count"; print c + 0 }'
echo @@end
