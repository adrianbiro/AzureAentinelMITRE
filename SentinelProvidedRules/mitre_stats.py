"""
TODO results looks of
"""
import csv
import os
import pathlib
import shutil
from collections import Counter, defaultdict

RULES_CSV = "MicrosoftSentinel.csv"
STATS_FOLDER = "stats"


def create_report(data, report_name: str, header: list):
    report_name = pathlib.PurePath(STATS_FOLDER, report_name) # type: ignore
    with open(report_name, "w", encoding="utf-8", newline="") as r:
        csv_out = csv.writer(r)
        csv_out.writerow(header)
        csv_out.writerows(data)

TacticTechniqes = defaultdict(list)
with open(RULES_CSV, encoding="utf-8-sig") as f:

    reader = csv.DictReader(f, delimiter=",")
    for row in reader:
        if row["Tactic"] in ("N.A.", "", None) or row["TechniqueId"] in (
            "N.A.",
            "",
            None,
        ):
            continue
        TacticTechniqes[row["Tactic"]].append(row["TechniqueId"])




techniques_counters = [(k, dict(Counter(v))) for k, v in TacticTechniqes.items()]

try:
    os.makedirs(STATS_FOLDER)
except OSError:
    shutil.rmtree(STATS_FOLDER)
    os.makedirs(STATS_FOLDER)

for t in techniques_counters:
    create_report(report_name=f"{t[0]}.csv",header=["Technique","Count"],data=t[1].items())

