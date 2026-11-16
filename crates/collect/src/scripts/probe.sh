export LC_ALL=C
echo @@kv
echo "os=$( (. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME") )"
echo "kernel=$(uname -sr 2>/dev/null)"
echo "arch=$(uname -m 2>/dev/null)"
echo "hostname=$(hostname 2>/dev/null)"
echo "cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null)"
echo "uid=$(id -u 2>/dev/null)"
echo "user=$(id -un 2>/dev/null)"
if command -v sudo >/dev/null 2>&1; then sudo -n true >/dev/null 2>&1 && echo "sudo=nopasswd" || echo "sudo=password"; else echo "sudo=absent"; fi
echo "gpus=$(nvidia-smi -L 2>/dev/null | grep -c '^GPU')"
if command -v sbatch >/dev/null 2>&1; then echo "scheduler=slurm"
elif command -v qsub >/dev/null 2>&1 && qsub --version 2>&1 | grep -qi pbs; then echo "scheduler=pbs"
elif [ -n "$SGE_ROOT" ] || command -v qconf >/dev/null 2>&1; then echo "scheduler=sge"
elif command -v bsub >/dev/null 2>&1; then echo "scheduler=lsf"
else echo "scheduler=none"; fi
echo "docker=$(command -v docker >/dev/null 2>&1 && (docker info >/dev/null 2>&1 && echo usable || echo no-permission) || echo absent)"
echo "systemd=$( [ -d /run/systemd/system ] && echo yes || echo no )"
echo @@end
