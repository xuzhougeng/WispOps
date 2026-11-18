echo @@tz
date +%z
date -u +%s
# Sessions from wtmp (no root needed): who logged in from where, and for how long.
if command -v last >/dev/null 2>&1 && w=$(last -i -w --time-format iso -n 2000 2>/dev/null); then
  echo @@sessions
  printf '%s\n' "$w"
fi
T=$(printf '\t')
# SSH logins accepted and refused, reduced on the host to counts by account, address and method:
#   A|F <tab> account <tab> count <tab> address <tab> method <tab> first <tab> last
#   G <tab> account <tab> failures <tab> addresses <tab> invalid <tab> first <tab> last
#   N <tab> - <tab> events <tab> earliest
# $1 = 1 reads lastb (newest first) instead of sshd's log lines (oldest first).
sshreduce() {
  awk -v rev="$1" -v T="$T" '
    rev == 1 {
      if (NF < 4 || $4 !~ /^[0-9][0-9][0-9][0-9]-/) next
      kind = "F"; u = $1; ip = $3; m = "-"; t = $4; bad = 0
    }
    rev != 1 {
      t = ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? $1 : $1 " " $2 " " $3
      if (match($0, /Accepted [a-z-]+ for [^ ]+ from [^ ]+/)) { s = substr($0, RSTART, RLENGTH); kind = "A"; bad = 0 }
      else if (match($0, /Failed [a-z-]+ for (invalid user )?[^ ]+ from [^ ]+/)) { s = substr($0, RSTART, RLENGTH); kind = "F"; bad = (s ~ / for invalid user /); sub(/ for invalid user /, " for ", s) }
      else next
      split(s, a, " "); m = a[2]; u = a[4]; ip = a[6]
    }
    {
      if (rev == 1 || total == 0) first = t
      total++
      k = kind T u T ip T m
      n[k]++
      if (rev == 1) { if (!(k in l)) l[k] = t; f[k] = t } else { if (!(k in f)) f[k] = t; l[k] = t }
      if (kind == "F") {
        g[u]++
        if (bad) inv[u] = 1
        if (!((u T ip) in seen)) { seen[u T ip] = 1; src[u]++ }
        if (rev == 1) { if (!(u in gl)) gl[u] = t; gf[u] = t } else { if (!(u in gf)) gf[u] = t; gl[u] = t }
      }
    }
    END {
      if (!total) exit
      print "N" T "-" T total T first
      for (k in n) { split(k, a, T); if (a[1] == "F" && (a[2] in inv)) continue; print a[1] T a[2] T n[k] T a[3] T a[4] T f[k] T l[k] }
      for (u in g) print "G" T u T g[u] T src[u] T ((u in inv) ? 1 : 0) T gf[u] T gl[u]
    }' | sort -t "$T" -k1,1 -k3,3nr | awk -F "$T" '$1 == "N" { print; next } $1 == "G" { if (++g <= 2000) print; next } ++c[$1 FS $2] <= 40 && ++all[$1] <= 4000'
}
src=none
r=""
if command -v journalctl >/dev/null 2>&1; then
  r=$(journalctl -q --no-pager -o short-iso --since "-720 h" -t sshd -t sshd-session -t sshd-auth 2>/dev/null | sshreduce 0)
  [ -n "$r" ] && src=journal
fi
if [ -z "$r" ]; then
  # The classic files, oldest first; compressed rotations are left alone.
  r=$(for f in $(ls -tr /var/log/auth.log /var/log/auth.log.[0-9] /var/log/secure /var/log/secure-[0-9]* 2>/dev/null | grep -v '\.gz$'); do [ -r "$f" ] && cat "$f"; done | grep -E 'sshd(-session|-auth)?\[' | sshreduce 0)
  [ -n "$r" ] && src=file
fi
if [ -z "$r" ] && command -v lastb >/dev/null 2>&1; then
  r=$(lastb -i -w --time-format iso 2>/dev/null | head -n 200000 | sshreduce 1)
  [ -n "$r" ] && src=btmp
fi
echo @@logsrc
echo "$src"
echo @@sshlog
printf '%s\n' "$r"
