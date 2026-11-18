# Disk quotas: the filesystems on devices (mount point, device, type, options), which of them
# have user quotas switched on, and every user's usage and limits there (in KiB; grace as the
# epoch second it runs out, 0 without one). repquota needs root.
echo @@qmounts
awk '$1 ~ /^\// { print $2 "\t" $1 "\t" $3 "\t" $4 }' /proc/mounts 2>/dev/null | head -n 200
q=$(command -v repquota 2>/dev/null || ls /usr/sbin/repquota /sbin/repquota 2>/dev/null | head -n 1)
if [ -n "$q" ]; then
  echo @@qtools
  echo repquota
  echo @@quotaon
  "${q%/*}/quotaon" -pa 2>/dev/null | grep '^user quota on ' | head -n 200
  echo @@repquota
  "$q" -aupv 2>/dev/null | head -n 20000
fi
