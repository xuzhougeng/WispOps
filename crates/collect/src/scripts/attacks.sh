echo @@attacks
printf '%s\n' "$lines" | awk '
  {
    if (match($0, /Failed [a-z\/-]+ for /)) {
      rest = substr($0, RSTART + RLENGTH); sub(/^invalid user /, "", rest)
      n = split(rest, a, " "); user = a[1]; ip = (a[2] == "from") ? a[3] : ""
    } else if (match($0, /(Connection closed by|Disconnected from) (invalid|authenticating) user /)) {
      rest = substr($0, RSTART + RLENGTH)
      n = split(rest, a, " "); user = a[1]; ip = a[2]
    } else next
    if (ip !~ /^[0-9a-fA-F:.]+$/) next
    key = ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? substr($1, 1, 13) : $1 " " $2 " " substr($3, 1, 2)
    total++; src[ip]++; usr[user]++; hr[key]++
    if (!(ip in seen)) { seen[ip] = 1; sources++ }
  }
  END {
    print "T\t" total + 0 "\t" sources + 0
    for (k in src) print "S\t" src[k] "\t" k
    for (k in usr) print "U\t" usr[k] "\t" k
    for (k in hr) print "H\t" hr[k] "\t" k
  }' | sort -t "$(printf '\t')" -k1,1 -k2,2nr | awk -F'\t' '{ c[$1]++ } $1 == "H" || c[$1] <= 30'
echo @@banned
command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status sshd 2>/dev/null | grep -E 'Banned IP list' | sed 's/.*Banned IP list:[ \t]*//' | tr -s ' \t' '\n\n' | head -n 200
echo @@end
