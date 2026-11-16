umask 077
command -v timeout >/dev/null 2>&1 || { echo 'GNU timeout is required'; exit 20; }
[ -f '/etc/motd' ] && [ ! -L '/etc/motd' ] || { echo 'Backup requires an existing regular non-symlink file: /etc/motd'; exit 20; }


B=$(mktemp -d '/var/tmp/wispops-change.XXXXXXXX') || exit 20
echo "Backup directory: $B"
cp -a -- '/etc/motd' "$B/f0" || exit 21

{ printf 'file\t%s\n' '/etc/motd'; } > "$B/manifest"
started=0
rollback() {
  failed=0

  if [ -L '/etc/motd' ] || [ -d '/etc/motd' ]; then failed=1
  else
    T=$(mktemp '/etc/motd.wispops-restore.XXXXXXXX') && cp -a -- "$B/f0" "$T" && mv -f -- "$T" '/etc/motd' || failed=1
  fi

  timeout --signal=TERM --kill-after=2s 30s sh -ec 'true' || failed=1
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
timeout --signal=TERM --kill-after=2s 30s sh -ec 'echo hi > /etc/motd' || exit 22
echo 'WISPOPS_STAGE=verify'
timeout --signal=TERM --kill-after=2s 30s sh -ec 'true' || exit 23
started=0
echo 'WISPOPS_CHANGE=verified'
