"""
Parse Sentinel Provided Rules From Microsoft Threat Intelligence
https://github.com/microsoft/mstic/blob/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv

curl -o MicrosoftSentinel.csv 'https://raw.githubusercontent.com/microsoft/mstic/refs/heads/master/PublicFeeds/MITREATT%26CK/MicrosoftSentinel.csv'

"""
import csv
import os
import pathlib
import shutil

RULES_CSV = "MicrosoftSentinel.csv"
BATCH_SIZE = 20
STATS_FOLDER = "rules"


def format_rule(r: dict[str, str]):
    return f"""
## {r['DetectionName']}

{r['DetectionDescription']}
|Name | Value |
| --- | --- |
|Tactic | {r['Tactic']}|
|TechniqueId | {r['TechniqueId']}|
|Platform | {r['Platform']}|
|DetectionType | {r['DetectionType']} |
|ConnectorId | {r['ConnectorId']} |
|DetectionId | {r['DetectionId']} |
|DataTypes | {r['DataTypes']} |
|QueryFrequency | {r['QueryFrequency']} |
|QueryPeriod | {r['QueryPeriod']} |
|TriggerOperator | {r['TriggerOperator']} |
|TriggerThreshold | {r['TriggerThreshold']} |
|DetectionSeverity | {r['DetectionSeverity']} |
|DetectionUrl | {r['DetectionUrl']} |
|IngestedDate | {r['IngestedDate']} |

### KQL
```kql
{r['Query']}
```
"""


formated_rules: list[str] = []

with open(RULES_CSV, encoding="utf-8-sig") as f:

    reader = csv.DictReader(f, delimiter=",")
    for row in reader:
        if row["Query"] not in ("N.A.", "", None):
            formated_rules.append(format_rule(row))


try:
    os.makedirs(STATS_FOLDER)
except OSError:
    shutil.rmtree(STATS_FOLDER)
    os.makedirs(STATS_FOLDER)

start, stop = 0, BATCH_SIZE
while True:
    if not (rules := formated_rules[start:stop]):
        break

    rules_file = pathlib.PurePath(STATS_FOLDER, f"Rules_{start + 1}-{stop + 1}.md")
    with open(rules_file, "w", encoding="utf-8-sig") as f:  # utf-8 with BOOM
        f.write(f"# Rules: {start + 1}-{stop + 1}\n")
        for r in rules:
            f.write(r)
    start += BATCH_SIZE + 1
    stop += BATCH_SIZE + 1
