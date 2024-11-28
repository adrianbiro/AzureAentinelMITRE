"""
Parse Sentinel Provided Rules From Microsoft Threat Intelligence
https://github.com/microsoft/mstic/blob/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv

curl -o MicrosoftSentinel.csv 'https://raw.githubusercontent.com/microsoft/mstic/refs/heads/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv'

"""

import csv

RULES_CSV = "MicrosoftSentinel.csv"
HAS_MITRE_RULES = f"HasRules{RULES_CSV}"

rules: list[dict] = []

with open(RULES_CSV, encoding="utf-8-sig") as f:

    reader = csv.DictReader(f, delimiter=",")
    for row in reader:
        if row["Tactic"] in ("N.A.", "", None) or row["TechniqueId"] in (
            "N.A.",
            "",
            None,
        ):

            continue
        rules.append(row)


with open(HAS_MITRE_RULES, "w", encoding="utf-8-sig") as f:  # utf-8 with BOOM
    writer = csv.DictWriter(f, fieldnames=rules[0].keys())
    writer.writeheader()
    writer.writerows(rules)
