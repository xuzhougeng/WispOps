#!/usr/bin/env python3
"""Stand-in for OpenSSH that answers the collectors with made-up GNU/Linux output.

Only for the README's screenshots (see `take.sh`): eight fictional servers, the
addresses from the documentation ranges, and nothing read from this computer.
The script arrives on stdin (`sh -s`); which collector sent it is told by its
section markers, and `$DEMO_STATE` counts the runs so the fleet changes over time.
"""
import os
import re
import sys
import time

GiB = 1024 * 1024  # in KiB

HOSTS = {
    "gpu-01": dict(os="Ubuntu 22.04.4 LTS", kernel="Linux 5.15.0-112-generic", cores=128, mem=1031891604, gpus=8, ip="10.20.0.11"),
    "gpu-02": dict(os="Ubuntu 22.04.4 LTS", kernel="Linux 5.15.0-112-generic", cores=128, mem=1031891604, gpus=8, ip="10.20.0.12"),
    "gpu-03": dict(os="Rocky Linux 9.4 (Blue Onyx)", kernel="Linux 5.14.0-427.22.1.el9_4.x86_64", cores=64, mem=527892352, gpus=4, ip="10.20.0.13"),
    "web-01": dict(os="Debian GNU/Linux 12 (bookworm)", kernel="Linux 6.1.0-21-amd64", cores=8, mem=32791624, gpus=0, ip="10.20.1.21"),
    "web-02": dict(os="Debian GNU/Linux 12 (bookworm)", kernel="Linux 6.1.0-21-amd64", cores=8, mem=32791624, gpus=0, ip="10.20.1.22"),
    "db-01": dict(os="Ubuntu 24.04 LTS", kernel="Linux 6.8.0-35-generic", cores=32, mem=263842256, gpus=0, ip="10.20.1.31"),
    "bastion": dict(os="Ubuntu 24.04 LTS", kernel="Linux 6.8.0-35-generic", cores=4, mem=8119092, gpus=0, ip="10.20.9.1"),
    "storage-01": dict(os="Rocky Linux 9.4 (Blue Onyx)", kernel="Linux 5.14.0-427.22.1.el9_4.x86_64", cores=16, mem=131921128, gpus=0, ip="10.20.2.41"),
}

RUNS = 30  # inspections the overview shows


def state(name):
    folder = os.environ["DEMO_STATE"]
    os.makedirs(folder, exist_ok=True)
    return os.path.join(folder, name)


def count(host, kind):
    """How many times this host has answered this collector before."""
    path = state(f"{host}.{kind}")
    n = int(open(path).read()) if os.path.exists(path) else 0
    open(path, "w").write(str(n + 1))
    return n


def df_line(dev, fstype, size_kb, pct, mount):
    used = int(size_kb * pct / 100)
    return f"{dev:<15}{fstype:<6}{size_kb:>12} {used:>12} {size_kb - used:>12} {round(pct):>7}% {mount}"


def disks(host, k):
    """Filesystems: (device, type, size KiB, use %, mount)."""
    if host == "gpu-02":
        # /data fills up over the month: ok, then warn at 80 %, then crit at 90 %.
        return [("/dev/nvme0n1p2", "ext4", 1800 * GiB, 61.0, "/"), ("/dev/md0", "xfs", 28000 * GiB, 70.0 + k * 0.8, "/data")]
    if host.startswith("gpu"):
        return [("/dev/nvme0n1p2", "ext4", 1800 * GiB, 48.0 + (k % 5), "/"), ("/dev/md0", "xfs", 28000 * GiB, 56.0 + k * 0.1, "/data")]
    if host == "storage-01":
        return [("/dev/sda2", "xfs", 400 * GiB, 34.0, "/"), ("/dev/md127", "xfs", 120000 * GiB, 71.0 + k * 0.05, "/srv/nfs")]
    if host == "db-01":
        return [("/dev/sda2", "ext4", 400 * GiB, 41.0, "/"), ("/dev/nvme0n1", "xfs", 3500 * GiB, 63.0 + k * 0.1, "/var/lib/postgresql")]
    return [("/dev/vda1", "ext4", 100 * GiB, 37.0 + (k % 3), "/")]


def inspect(host, k):
    h = HOSTS[host]
    cores, gpus = h["cores"], h["gpus"]
    load = cores * {"gpu-01": 0.58, "gpu-02": 0.47, "gpu-03": 0.71, "web-01": 0.21, "web-02": 0.17, "db-01": 0.34, "bastion": 0.06, "storage-01": 0.4}[host]
    avail = {"gpu-01": 0.41, "gpu-02": 0.55, "gpu-03": 0.33, "web-01": 0.64, "web-02": 0.69, "db-01": 0.22, "bastion": 0.81, "storage-01": 0.7}[host]
    if host == "db-01" and (k % 7 in (3, 4) or k >= RUNS - 2):
        avail = 0.072  # memory pressure: warn
    sshfail = 4
    if host == "bastion" and k in (8, 9, 20, 21, RUNS - 2, RUNS - 1):
        sshfail = 340  # brute force: warn
    failed = "nginx.service" if host == "web-01" and k in (17, 18) else ""
    reboot = "yes" if host == "web-02" and k >= RUNS - 6 else "no"
    hot = host == "gpu-03" and k in (5, 6, RUNS - 3, RUNS - 2, RUNS - 1)
    busy = 0.82 if host.startswith("gpu") else 0.18
    idle0, idle1 = 8_000_000, 8_000_000 + int(100_000 * (1 - busy))
    user0, user1 = 2_000_000, 2_000_000 + int(100_000 * busy)
    out = [
        "@@kv",
        f"hostname={host}",
        f"kernel={h['kernel']}",
        f"os={h['os']}",
        f"cores={cores}",
        f"uptime={3_400_000 + k * 7200}.31",
        f"loadavg={load:.2f} {load * 0.97:.2f} {load * 0.93:.2f} 3/2100 51234",
        "zombies=0",
        f"reboot_required={reboot}",
        "ntp=yes",
        "oom_24h=0",
        "kerr_24h=0",
        f"sshfail_1h={sshfail}",
        "@@meminfo",
        f"MemTotal:       {h['mem']} kB",
        f"MemAvailable:   {int(h['mem'] * avail)} kB",
        "SwapTotal:        8388604 kB",
        "SwapFree:         8100000 kB",
        "@@cpu",
        f"cpu  {user0} 0 300000 {idle0} 0 0 0 0 0 0",
        f"cpu  {user1} 0 300000 {idle1} 0 0 0 0 0 0",
        "@@netdev",
    ]
    for second in (0, 1):
        out += [
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
            f"  eth0: {9_000_000_000 + second * 48_000_000} 900 0 0 0 0 0 0 {4_000_000_000 + second * 21_000_000} 800 0 0 0 0 0 0",
        ]
        if second == 0:
            out.append("--")
    out += ["@@netphys", "/sys/class/net/eth0", "@@tcp"]
    for segs in (10_000_000, 10_040_000):
        out += [
            "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors",
            f"Tcp: 1 200 120000 -1 100 200 0 0 {180 if host.startswith('web') else 42} {segs} {segs * 2} {segs // 1000} 0 0 0",
        ]
    out += ["@@df", "Filesystem     Type 1024-blocks      Used Available Capacity Mounted on"]
    out += [df_line(*d) for d in disks(host, k)]
    out += ["@@dfi", "Filesystem       Inodes   IUsed    IFree IUse% Mounted on"]
    out += [f"{d[0]:<15} 61054976 3000000 58054976    5% {d[4]}" for d in disks(host, k)]
    out += ["@@failed"] + ([failed] if failed else [])
    top = {"gpu": "alice  3190.0 12.5  86400 python", "web": "www-data 42.0 3.1 86400 nginx", "db-": "postgres 210.0 31.0 86400 postgres", "bas": "root 1.0 0.4 86400 sshd", "sto": "root 35.0 2.0 86400 nfsd"}[host[:3]]
    out += ["@@topcpu", f"  4242 {top}", "@@topmem", f"  4242 {top}"]
    out.append("@@gpu")
    for i in range(gpus):
        temp = 87 if hot and i == 2 else 61 + (i * 3) % 11
        out.append(f"{i}, GPU-{host}-{i}, NVIDIA A100-SXM4-80GB, {93 - (i * 7) % 30}, {62000 + i * 1500}, 81920, {temp}")
    out.append("@@gpuapps")
    for i in range(gpus):
        out.append(f"GPU-{host}-{i}, {4242 + i}, {62000 + i * 1500}, python")
    if host.startswith("gpu"):
        out += ["@@slurm", "mixed|2", "allocated|1", "@@slurmbad", "@@squeue", "     14 RUNNING", "      6 PENDING"]
    out += ["@@listen", "0.0.0.0:22", "[::]:22", "10.20.0.1%eth0:9100"]
    if host.startswith("web"):
        out += ["0.0.0.0:80", "0.0.0.0:443"]
    if host == "db-01":
        out += ["10.20.1.31:5432"]
    out += ["@@logins", "alice 10.20.9.1", "ops 10.20.9.1", "@@kerr", "@@end"]
    return "\n".join(out) + "\n"


def probe(host):
    h = HOSTS[host]
    return "\n".join([
        "@@kv", f"os={h['os']}", f"kernel={h['kernel']}", "arch=x86_64", f"hostname={host}", f"cores={h['cores']}",
        "uid=1000", "user=ops", "sudo=nopasswd", f"gpus={h['gpus']}",
        f"scheduler={'slurm' if host.startswith('gpu') else 'none'}",
        f"docker={'usable' if host.startswith(('gpu', 'web')) else 'absent'}", "systemd=yes", "@@end",
    ]) + "\n"


# Directory sizes of gpu-02 in KiB, the second scan grows some of them.
TREE = {
    "/data": [
        ("datasets", 9200), ("datasets/imagenet-1k", 2900), ("datasets/laion-subset", 3800), ("datasets/coco-2017", 980), ("datasets/openwebtext", 1520),
        ("projects", 7400), ("projects/alice", 3100), ("projects/alice/checkpoints", 2600), ("projects/alice/logs", 300), ("projects/bob", 2200),
        ("projects/bob/runs", 1900), ("projects/carol", 1400), ("projects/dave", 700),
        ("scratch", 3600), ("scratch/tmp-eval", 1700), ("scratch/carol-sweep", 1300),
        ("conda", 820), ("conda/pkgs", 610), ("containers", 1240), ("containers/apptainer", 1240), ("logs", 260),
    ],
    "/": [
        ("usr", 92), ("usr/local", 61), ("usr/lib", 28), ("var", 640), ("var/lib", 520), ("var/lib/docker", 470), ("var/log", 96),
        ("home", 210), ("home/alice", 88), ("home/bob", 64), ("home/carol", 41), ("opt", 120), ("opt/nvidia", 96),
    ],
}
GROWS = {"scratch/tmp-eval": 1.9, "projects/alice/checkpoints": 1.25, "var/log": 1.6}


def space(host, script, again):
    path = re.search(r"^P='([^']*)'", script, re.M).group(1)
    rows = TREE.get(path, [])
    sizes = {}
    for rel, gib in rows:
        grow = GROWS.get(rel, 1.0) if again else 1.0
        sizes[rel] = int(gib * GiB * grow)
    # A parent is at least the sum of what is listed under it.
    for rel in sorted(sizes, key=lambda r: -r.count("/")):
        parent = rel.rsplit("/", 1)[0] if "/" in rel else None
        if parent and parent in sizes:
            sizes[parent] = max(sizes[parent], sum(v for r, v in sizes.items() if r.rsplit("/", 1)[0] == parent and "/" in r) + GiB)
    total = sum(v for r, v in sizes.items() if "/" not in r) + 3 * GiB
    lines = [(total, path)] + [(v, f"{path.rstrip('/')}/{r}") for r, v in sizes.items()]
    lines.sort(reverse=True)
    dev = [d for d in disks(host, RUNS - 1) if d[4] == path]
    out = ["@@whoami", "0", "@@df", "Filesystem     Type 1024-blocks      Used Available Capacity Mounted on"]
    out += [df_line(*d) for d in dev]
    out += ["@@du"] + [f"{v}\t{p}" for v, p in lines] + ["@@du_rc", "0", "@@du_count", str(len(lines)), "@@end"]
    return "\n".join(out) + "\n"


def longrun(host):
    procs = {
        "gpu-01": [
            ("3101 1 1001 alice 1987200 1420.5 6.1 64000000 Sl python train.py --config configs/vit-l.yaml"),
            ("3102 3101 1001 alice 1987100 98.0 0.4 4000000 Rl python train.py --config configs/vit-l.yaml"),
            ("4410 1 1002 bob 612000 0.0 0.2 2100000 Sl jupyter-lab --no-browser --port 8890"),
            ("5120 1 1004 dave 262800 0.1 0.0 9000 S sleep infinity"),
        ],
        "gpu-02": [
            ("2201 1 1003 carol 1209600 380.2 2.0 21000000 Sl python sweep.py --trials 400"),
            ("2380 1 1001 alice 345600 0.0 0.1 800000 T python eval.py --ckpt step_90000"),
            ("2390 1 1002 bob 950400 0.3 0.4 4300000 Sl tensorboard --logdir runs --port 6006"),
        ],
        "gpu-03": [("7001 1 1005 erin 172800 96.4 1.1 5800000 Rl Rscript deseq2_batch.R")],
        "storage-01": [("880 1 1006 frank 2592000 12.1 0.2 300000 Sl rsync -a /srv/nfs/archive/ backup:/vault/")],
        "db-01": [("9120 1 1007 grace 129600 0.0 0.0 6000 S psql -h localhost analytics")],
    }.get(host, [])
    slurm = {
        "gpu-01": ["88231|alice|3-02:11:45|2|gpu|llama-ft"],
        "gpu-02": ["88102|bob|5-19:40:02|4|gpu|diffusion-xl", "88310|carol|1-04:12:09|1|gpu|sweep-7"],
    }.get(host, [])
    out = ["@@whoami", "1000", "@@uidmin", "1000", "@@ps_total", "380", "@@procs"] + [f" {p}" for p in procs] + ["@@slurm"] + slurm + ["@@end"]
    return "\n".join(out) + "\n"


# Exposure per host: (scale of the attack, sources, accounts tried).
EXPOSED = {
    "bastion": (1.0, [("203.0.113.47", 2410), ("198.51.100.23", 1630), ("192.0.2.180", 870), ("203.0.113.9", 540), ("198.51.100.201", 310), ("192.0.2.66", 190)], [("root", 3150), ("admin", 820), ("ubuntu", 610), ("test", 400), ("oracle", 260), ("postgres", 180), ("git", 120)]),
    "web-01": (0.08, [("198.51.100.23", 212), ("192.0.2.180", 96), ("203.0.113.120", 41)], [("root", 260), ("admin", 54), ("deploy", 35)]),
    "web-02": (0.06, [("198.51.100.23", 180), ("203.0.113.120", 52)], [("root", 190), ("www", 42)]),
}


def security(host):
    """The security triage with the attack tail: heavy on the bastion, some on the web servers, none inside."""
    now = time.time()
    scale, sources, users = EXPOSED.get(host, (0, [], []))
    hours = []
    if scale:
        for back in range(30, -1, -1):
            stamp = time.localtime(now - back * 3600)
            wave = 40 + int(260 * max(0, 1 - abs(back - 9) / 5)) + (back * 37) % 60
            hours.append(f"H\t{max(1, int(wave * scale))}\t{time.strftime('%b', stamp)} {stamp.tm_mday:>2} {stamp.tm_hour:02d}")
    total = sum(int(h.split("\t")[1]) for h in hours)
    out = [
        "@@whoami", "0", "@@authsrc", "readable", "@@failed",
        *[f"   {c:>5} {ip}" for ip, c in sources],
        "@@accepted", "     41 publickey ops 10.20.9.1", "      6 publickey alice 10.20.9.1",
        "@@who", "ops pts/0 2026-11-16 09:12 (10.20.9.1)",
        "@@listen", 'tcp\t0.0.0.0:22\tusers:(("sshd",pid=812,fd=3))',
        "@@estab", "      3 10.20.9.1", "@@synrecv", "0", "@@outbound", "@@procs", "@@badexe",
        "@@uid0", "root", "@@keys", "@@cron", "@@units", "@@sshd", "permitrootlogin no", "passwordauthentication no",
        "@@fail2ban",
        "@@attacks", f"T\t{total}\t{len(sources) + (11 if host == 'bastion' else 0)}",
        *[f"S\t{c}\t{ip}" for ip, c in sources],
        *[f"U\t{c}\t{u}" for u, c in users],
        *hours,
        "@@banned", *(["203.0.113.47", "198.51.100.23"] if host == "bastion" else []), "@@end",
    ]
    return "\n".join(out) + "\n"


def disk(host, script):
    """ops_disk on gpu-02:/data, as the assistant asks for it."""
    now = int(time.time())
    day = 86400
    rows = [(23_300, "/data"), (9_200, "/data/datasets"), (7_400, "/data/projects"), (4_400, "/data/scratch"), (3_200, "/data/scratch/tmp-eval"),
            (3_200, "/data/projects/alice"), (2_900, "/data/datasets/laion-subset"), (2_200, "/data/projects/bob"), (1_300, "/data/scratch/carol-sweep"), (1_240, "/data/containers"), (820, "/data/conda")]
    out = ["@@whoami", "0", "@@gnufind", "ok", "@@df", "Filesystem     Type 1024-blocks      Used Available Capacity Mounted on"]
    out += [df_line(*d) for d in disks(host, RUNS - 1) if d[4] == "/data"]
    out += ["@@dfi", "Filesystem       Inodes   IUsed    IFree IUse% Mounted on", "/dev/md0       1468006400 41000000 1427006400    3% /data"]
    out += ["@@du"] + [f"{gib * GiB}\t{path}" for gib, path in rows] + ["@@du_rc", "0"]
    out += ["@@big",
            f"{412 * GiB * 1024}\t{now - 19 * day}\tcarol\t/data/scratch/tmp-eval/run-1021/preds.parquet",
            f"{388 * GiB * 1024}\t{now - 2 * 3600}\talice\t/data/projects/alice/checkpoints/step_120000.pt",
            f"{301 * GiB * 1024}\t{now - 23 * day}\tcarol\t/data/scratch/tmp-eval/run-1014/preds.parquet",
            f"{96 * GiB * 1024}\t{now - 3 * day}\tbob\t/data/projects/bob/runs/diffusion-xl/latents.npy"]
    out += ["@@recent", f"{388 * GiB * 1024}\t{now - 2 * 3600}\talice\t/data/projects/alice/checkpoints/step_120000.pt"]
    out += ["@@find_rc", "0", "@@now", str(now)]
    out += ["@@open", "3101\t-\t/data/projects/alice/checkpoints/step_120000.pt", "@@procs", " 3101 alice 1987200 python"]
    out += ["@@jobs", "88102|bob|/data/projects/bob/runs/diffusion-xl"]
    out += ["@@journal", "@@docker", "@@known", f"{612 * GiB}\t/data\t/data/conda/pkgs", "@@rotated", "@@end"]
    return "\n".join(out) + "\n"


# People with accounts, by host: (name, uid, full name, extra groups, password state, sessions).
PEOPLE = [("alice", 1001, "Alice Liu", "sudo,docker", "set", 2), ("bob", 1002, "Bob Chen", "docker", "set", 1), ("carol", 1003, "Carol Wang", "docker", "set", 0), ("dave", 1004, "Dave Zhao", "", "locked", 0), ("erin", 1005, "Erin Sun", "", "set", 0), ("frank", 1006, "Frank Li", "", "set", 0), ("grace", 1007, "Grace Zhou", "", "set", 0)]


def accounts(host, rooted):
    """The account listing: the GPU servers have the researchers, the others a few operators."""
    people = PEOPLE if host.startswith("gpu") else [p for p in PEOPLE if p[0] in ("alice", "frank", "grace")]
    if host.startswith("gpu") and host != "gpu-01":
        people = [p for p in people if p[0] != "dave"] + [("intern01", 1010, "", "", "set" if host == "gpu-02" else "empty", 0)]
    passwd = ["root:x:0:0:root:/root:/bin/bash", "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin", "ops:x:900:900:operations:/home/ops:/bin/bash", "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"]
    passwd += [f"{name}:x:{uid}:{uid}:{full},,,:/home/{name}:/bin/bash" for name, uid, full, *_ in people]
    groups = ["root:x:0:", "daemon:x:1:", "nogroup:x:65534:", "ops:x:900:"]
    members = {}
    for name, _, _, extra, *_ in people:
        for group in filter(None, extra.split(",")):
            members.setdefault(group, []).append(name)
    members.setdefault("sudo", []).insert(0, "ops")
    groups += [f"sudo:x:27:{','.join(members['sudo'])}", f"docker:x:998:{','.join(members.get('docker', []))}"]
    groups += [f"{name}:x:{uid}:" for name, uid, *_ in people]
    out = ["@@whoami", "0" if rooted else "900", "@@login_uid_min", "1000", "@@passwd"] + passwd + ["@@group"] + groups
    if rooted:
        out += ["@@shadow", "root:locked:19800:", "daemon:none:19000:", "sshd:none:19000:", "ops:set:19900:", "nobody:none:19000:"]
        out += [f"{name}:{state}:{0 if name == 'erin' else 19950}:" for name, _, _, _, state, _ in people]
    out += ["@@who"] + [name for name, *_, sessions in people for _ in range(sessions if host.startswith("gpu") else 0)]
    out += logins(host, people, rooted) + quotas(host, people, rooted) + ["@@end"]
    return "\n".join(out) + "\n"


# Where each person logs in from (their desk or the VPN).
DESKS = {"alice": "10.8.0.21", "bob": "10.8.0.34", "carol": "10.8.0.17", "dave": "172.16.4.9", "erin": "10.8.0.52", "frank": "10.8.0.40", "grace": "10.8.0.45", "intern01": "10.8.0.88", "ops": "10.8.0.2"}


def iso(seconds_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%S+08:00", time.gmtime(time.time() + 8 * 3600 - seconds_ago))


def logins(host, people, rooted):
    """wtmp sessions, and sshd's log as the host reduces it: every person logs in daily; root and
    alice are tried from outside; a few names that do not exist are tried too."""
    names = [p[0] for p in people] + ["ops"]
    open_ = {name for name, *_, sessions in people if sessions and host.startswith("gpu")}
    out = ["@@tz", "+0800", str(int(time.time())), "@@sessions"]
    rows = []
    for day in range(12):
        for k, name in enumerate(names):
            if (day + k) % 3 == 2:
                continue
            start = day * 86400 + 3600 * (2 + k) + 600 * k
            ip = DESKS[name] if (day + k) % 5 else "10.8.0.99"
            if day == 0 and name in open_:
                rows.append((start, f"{name:<8} pts/{k}        {ip:<16} {iso(start)}   still logged in"))
            elif day == 6 and k == 1:
                rows.append((start, f"{name:<8} pts/{k}        {ip:<16} {iso(start)} - crash                     (03:10)"))
            else:
                rows.append((start, f"{name:<8} pts/{k}        {ip:<16} {iso(start)} - {iso(start - 3600 * (1 + k % 4) - 60 * (7 * k % 50))}  (0{1 + k % 4}:{7 * k % 50:02d})"))
    out += [line for _, line in sorted(rows)] + ["", f"wtmp begins {iso(40 * 86400)}"]
    if not rooted:
        return out + ["@@logsrc", "none", "@@sshlog"]
    log = [f"N\t-\t{4180 if host == 'bastion' else 640}\t{iso(30 * 86400)}"]
    for k, name in enumerate(names):
        log.append(f"A\t{name}\t{18 + 3 * k}\t{DESKS[name]}\tpublickey\t{iso(29 * 86400)}\t{iso(3600 * (2 + k))}")
        if k % 3 == 0:
            log.append(f"A\t{name}\t{2 + k}\t10.8.0.99\tpassword\t{iso(20 * 86400)}\t{iso(86400 * 2 + 3600 * k)}")
    attack = 3800 if host == "bastion" else 410
    log += [f"F\troot\t{attack // 2}\t203.0.113.7\tpassword\t{iso(25 * 86400)}\t{iso(1200)}", f"F\troot\t{attack // 4}\t198.51.100.23\tpassword\t{iso(9 * 86400)}\t{iso(5400)}", f"F\troot\t{attack // 8}\t192.0.2.140\tpublickey\t{iso(3 * 86400)}\t{iso(86400)}"]
    log += [f"G\troot\t{attack // 2 + attack // 4 + attack // 8}\t3\t0\t{iso(25 * 86400)}\t{iso(1200)}"]
    log += ["F\talice\t3\t10.8.0.99\tpassword\t" + iso(4 * 86400) + "\t" + iso(4 * 86400 - 50), "F\talice\t14\t203.0.113.7\tpassword\t" + iso(6 * 86400) + "\t" + iso(7200), "G\talice\t17\t2\t0\t" + iso(6 * 86400) + "\t" + iso(7200)]
    log += ["F\tbob\t1\t10.8.0.34\tpassword\t" + iso(86400 * 3) + "\t" + iso(86400 * 3), "G\tbob\t1\t1\t0\t" + iso(86400 * 3) + "\t" + iso(86400 * 3)]
    for name, tries in [("admin", 96), ("test", 41), ("oracle", 22), ("ubuntu", 19), ("postgres", 11)]:
        log.append(f"G\t{name}\t{tries}\t{tries // 6 + 1}\t1\t{iso(20 * 86400)}\t{iso(7000)}")
    return out + ["@@logsrc", "journal", "@@sshlog"] + log


def quotas(host, people, rooted):
    """The GPU servers keep /data under user quotas (and /scratch asks for them but has them off)."""
    mounts = ["@@qmounts", "/\t/dev/nvme0n1p2\text4\trw,relatime"]
    if not host.startswith("gpu"):
        return mounts
    mounts += ["/data\t/dev/md0\txfs\trw,relatime,usrquota", "/scratch\t/dev/nvme1n1\text4\trw,relatime,usrquota"]
    out = mounts + ["@@qtools", "repquota", "@@quotaon", "user quota on /data (/dev/md0) is on (enforced)", "user quota on /scratch (/dev/nvme1n1) is off", "@@repquota"]
    if not rooted:
        return out
    G = 1024 * 1024
    use = {"alice": (412, 500, 600), "bob": (515, 500, 600), "carol": (88, 500, 600), "dave": (600, 500, 600), "erin": (3, 500, 600), "frank": (0, 0, 0), "grace": (47, 200, 250), "intern01": (19, 100, 120)}
    out += ["*** Report for user quotas on device /dev/md0", "Block grace time: 7days; Inode grace time: 7days", "User            used    soft    hard  grace    used  soft  hard  grace", "-" * 70, "root      --    1024       0       0      0      12     0     0      0"]
    for name, *_ in people:
        used, soft, hard = use.get(name, (0, 0, 0))
        flags = "+-" if soft and used > soft else "--"
        grace = int(time.time()) + 3 * 86400 if flags == "+-" else 0
        out.append(f"{name:<9} {flags} {used * G:>9} {soft * G:>9} {hard * G:>9} {grace:>10} {used * 913:>7} 0 0 0")
    return out


def main():
    args = sys.argv[1:]
    if args[:1] == ["-G"]:
        print("user ops")
        return 0
    if "--" in args:
        args = args[args.index("--") + 1:]
    dest, command = args[0], " ".join(args[1:])
    address = dest.split("@")[-1]
    host = next((name for name, h in HOSTS.items() if h["ip"] == address), address)
    script = sys.stdin.read() if "sh -s" in command else command
    if host not in HOSTS:
        print(f"ssh: Could not resolve hostname {host}: nodename nor servname provided", file=sys.stderr)
        return 255
    # storage-01 stops answering for the last three inspections, and stays away.
    if "echo @@meminfo" in script:
        k = count(host, "inspect")
        if host == "storage-01" and k >= RUNS - 3:
            open(state("storage-01.down"), "w").close()
    if host == "storage-01" and os.path.exists(state("storage-01.down")):
        print(f"ssh: connect to host {HOSTS[host]['ip']} port 22: Connection timed out", file=sys.stderr)
        return 255
    if "echo @@meminfo" in script:
        sys.stdout.write(inspect(host, min(k, RUNS - 1)))
    elif "echo @@login_uid_min" in script:
        sys.stdout.write(accounts(host, "sudo" in command))
    elif "command -v useradd" in script:
        # Account creation: every name is new except those the listing already has.
        known = {p[0] for p in PEOPLE} | {"root", "ops"}
        for name in re.findall(r"^add '([^']+)'", script, re.M):
            print(f"exists\t{name}" if name in known else f"created\t{name}")
    elif "| chpasswd" in script:
        name = re.search(r"printf 'reset\\t%s\\n' '([^']+)'", script).group(1)
        print(f"reset\t{name}")
    elif "echo @@attacks" in script:
        sys.stdout.write(security(host))
    elif "echo @@uidmin" in script:
        sys.stdout.write(longrun(host))
    elif "echo @@big" in script:
        sys.stdout.write(disk(host, script))
    elif "echo @@du" in script:
        sys.stdout.write(space(host, script, count(host, "space") >= 2))
    elif "echo @@kv" in script:
        sys.stdout.write(probe(host))
    elif "df -PkT" in script and "echo @@" not in script:
        print("Filesystem     Type 1024-blocks      Used Available Capacity Mounted on")
        for d in disks(host, RUNS - 1):
            print(df_line(*d))
    elif "$HOME" in script:
        print("/home/ops")
    else:
        open(state("unanswered.log"), "a").write(f"{command!r}\n{script!r}\n\n")
        print(f"demo: no answer for {script[:60]!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
