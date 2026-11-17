"""Date the demo data back, as weeks of use would have left it (see take.sh)."""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

home = sys.argv[1]
now = datetime.now(timezone.utc)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def rewrite(path, stamp):
    rows = [json.loads(line) for line in open(path) if line.strip()]
    for at, row in enumerate(rows):
        stamp(row, at, len(rows))
    with open(path, "w") as file:
        file.writelines(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)


# Inspections: the newest a few minutes ago, the others a day apart before it.
folder = os.path.join(home, "inspections")
for name in os.listdir(folder):
    def inspection(row, at, total):
        row["at"] = iso(now - timedelta(minutes=6) - timedelta(days=total - 1 - at))
    rewrite(os.path.join(folder, name), inspection)

# Disk scans: the first a week ago, the follow-up this morning.
space = os.path.join(home, "space")
for name in os.listdir(space) if os.path.isdir(space) else []:
    def scan(row, at, total):
        row["at"] = iso(now - (timedelta(days=7) if at < total // 2 else timedelta(hours=3)))
    rewrite(os.path.join(space, name), scan)
plans = os.path.join(home, "disk-scans.json")
if os.path.exists(plans):
    data = json.load(open(plans))
    for plan in data.values():
        plan["firstAt"] = iso(now - timedelta(days=7))
        plan["lastAt"] = iso(now - timedelta(hours=3))
    json.dump(data, open(plans, "w"), ensure_ascii=False, indent=1)
