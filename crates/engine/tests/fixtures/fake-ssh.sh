#!/bin/sh
# Stand-in for OpenSSH: skips options up to `--`, takes the destination, and
# runs the remote command locally. Destinations starting with `down` or
# `locked` simulate an unreachable host and an authentication failure.
# With FAKE_SSH_LOGIN_PASSWORD set it asks $SSH_ASKPASS for the password first,
# as OpenSSH does for a password login, and refuses a wrong answer.
if [ "$1" = "-G" ]; then
  printf 'user %s\n' "${FAKE_SSH_USER:-fixture-user}"
  exit 0
fi
while [ $# -gt 0 ]; do
  if [ "$1" = "--" ]; then shift; break; fi
  shift
done
dest=$1; shift
[ -n "$FAKE_SSH_LOG" ] && echo "$dest" >> "$FAKE_SSH_LOG"
if [ -n "$FAKE_SSH_LOGIN_PASSWORD" ]; then
  answer=$("$SSH_ASKPASS" "alice@$dest's password: ")
  if [ "$answer" != "$FAKE_SSH_LOGIN_PASSWORD" ]; then
    echo "alice@$dest: Permission denied (password)." >&2
    exit 255
  fi
fi
case "$dest" in
  down*) echo "ssh: connect to host $dest port 22: Connection refused" >&2; exit 255 ;;
  locked*) echo "alice@$dest: Permission denied (publickey,password)." >&2; exit 255 ;;
esac
PATH="$FAKE_BIN:$PATH"
export PATH FAKE_HOST="$dest"
exec sh -c "$1"
