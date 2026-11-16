umask 077
command -v timeout >/dev/null 2>&1 || { echo 'GNU timeout is required'; exit 20; }
command -v tar >/dev/null 2>&1 || { echo 'tar is required for directory backups'; exit 20; }
find '/var/tmp' -maxdepth 1 -name 'wispops-change.*' -type d -mtime +14 -exec rm -rf -- {} + 2>/dev/null
[ -f '/etc/app/config with spaces' ] && [ ! -L '/etc/app/config with spaces' ] || { echo 'Backup requires an existing regular non-symlink file: /etc/app/config with spaces'; exit 20; }
[ -f '/etc/it'\''s.conf' ] && [ ! -L '/etc/it'\''s.conf' ] || { echo 'Backup requires an existing regular non-symlink file: /etc/it'\''s.conf'; exit 20; }
[ ! -e '/etc/app/new.conf' ] && [ ! -L '/etc/app/new.conf' ] && [ -d '/etc/app' ] || { echo 'New file must not exist yet and its directory must exist: /etc/app/new.conf'; exit 20; }
[ -d '/etc/nginx/conf.d' ] && [ ! -L '/etc/nginx/conf.d' ] || { echo 'Backup requires an existing non-symlink directory: /etc/nginx/conf.d'; exit 20; }
[ -d '/srv' ] && [ ! -L '/srv' ] || { echo 'Backup requires an existing non-symlink directory: /srv'; exit 20; }
B=$(mktemp -d '/var/tmp/wispops-change.XXXXXXXX') || exit 20
echo "Backup directory: $B"
cp -a -- '/etc/app/config with spaces' "$B/f0" || exit 21
cp -a -- '/etc/it'\''s.conf' "$B/f1" || exit 21
tar -C '/etc/nginx' -cf "$B/d0.tar" -- 'conf.d' || exit 21
tar -C '/' -cf "$B/d1.tar" -- 'srv' || exit 21
{ printf 'file\t%s\n' '/etc/app/config with spaces'; printf 'file\t%s\n' '/etc/it'\''s.conf'; printf 'new\t%s\n' '/etc/app/new.conf'; printf 'dir\t%s\n' '/etc/nginx/conf.d'; printf 'dir\t%s\n' '/srv'; } > "$B/manifest"
started=0
rollback() {
  failed=0
  if [ -L '/etc/nginx/conf.d' ]; then failed=1
  else
    T=$(mktemp -d '/etc/nginx/conf.d.wispops-restore.XXXXXXXX') && tar -C "$T" -xpf "$B/d0.tar" && rm -rf -- '/etc/nginx/conf.d' && mv -- "$T/"'conf.d' '/etc/nginx/conf.d' && rmdir -- "$T" || failed=1
  fi
  if [ -L '/srv' ]; then failed=1
  else
    T=$(mktemp -d '/srv.wispops-restore.XXXXXXXX') && tar -C "$T" -xpf "$B/d1.tar" && rm -rf -- '/srv' && mv -- "$T/"'srv' '/srv' && rmdir -- "$T" || failed=1
  fi
  if [ -L '/etc/app/config with spaces' ] || [ -d '/etc/app/config with spaces' ]; then failed=1
  else
    T=$(mktemp '/etc/app/config with spaces.wispops-restore.XXXXXXXX') && cp -a -- "$B/f0" "$T" && mv -f -- "$T" '/etc/app/config with spaces' || failed=1
  fi
  if [ -L '/etc/it'\''s.conf' ] || [ -d '/etc/it'\''s.conf' ]; then failed=1
  else
    T=$(mktemp '/etc/it'\''s.conf.wispops-restore.XXXXXXXX') && cp -a -- "$B/f1" "$T" && mv -f -- "$T" '/etc/it'\''s.conf' || failed=1
  fi
  if [ -L '/etc/app/new.conf' ] || [ -f '/etc/app/new.conf' ]; then rm -f -- '/etc/app/new.conf' || failed=1
  elif [ -e '/etc/app/new.conf' ]; then failed=1
  fi
  timeout --signal=TERM --kill-after=2s 120s sh -ec 'systemctl reload app' || failed=1
  if [ "$failed" = 0 ]; then echo 'WISPOPS_CHANGE=rolled-back'; else echo 'WISPOPS_CHANGE=rollback-failed'; fi
  return "$failed"
}
finish() {
  rc=$?
  trap - EXIT HUP INT TERM
  if [ "$started" = 1 ]; then rollback || rc=24; fi
  exit "$rc"
}
trap finish EXIT
trap 'exit 25' HUP INT TERM
started=1
echo 'WISPOPS_STAGE=apply'
timeout --signal=TERM --kill-after=2s 120s sh -ec 'printf '\''x'\'' > /etc/app/new.conf; systemctl reload app' || exit 22
echo 'WISPOPS_STAGE=verify'
timeout --signal=TERM --kill-after=2s 120s sh -ec 'test -s /etc/app/new.conf' || exit 23
started=0
echo 'WISPOPS_CHANGE=verified'
