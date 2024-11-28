# Rules: 1-21

## PulseConnectSecure - CVE-2021-22893 Possible Pulse Connect Secure RCE Vulnerability Attack

'This query identifies exploitation attempts using Pulse Connect Secure(PCS) vulnerability (CVE-2021-22893) to the VPN server'

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1190|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | PulseConnectSecure |
|DetectionId | d0c82b7f-40b2-4180-a4d6-7aa0541b7599 |
|DataTypes | Syslog |
|QueryFrequency | 1h |
|QueryPeriod | 1h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/PulseConnectSecure/PulseConnectSecureVPN-CVE_2021_22893_Exploit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let threshold = 3;
PulseConnectSecure
| where Messages contains "Unauthenticated request url /dana-na/"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Source_IP
| where count_ > threshold
| extend timestamp = StartTime, IPCustomEntity = Source_IP

```

## PulseConnectSecure - CVE-2021-22893 Possible Pulse Connect Secure RCE Vulnerability Attack

'This query identifies exploitation attempts using Pulse Connect Secure(PCS) vulnerability (CVE-2021-22893) to the VPN server'

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1190|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | PulseConnectSecure |
|DetectionId | d0c82b7f-40b2-4180-a4d6-7aa0541b7599 |
|DataTypes | Syslog |
|QueryFrequency | 1h |
|QueryPeriod | 1h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/PulseConnectSecure/PulseConnectSecureVPN-CVE_2021_22893_Exploit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let threshold = 3;
PulseConnectSecure
| where Messages contains "Unauthenticated request url /dana-na/"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Source_IP
| where count_ > threshold
| extend timestamp = StartTime, IPCustomEntity = Source_IP

```

## PulseConnectSecure - CVE-2021-22893 Possible Pulse Connect Secure RCE Vulnerability Attack

'This query identifies exploitation attempts using Pulse Connect Secure(PCS) vulnerability (CVE-2021-22893) to the VPN server'

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1190|
|Platform | Linux|
|DetectionType | Analytics |
|ConnectorId | PulseConnectSecure |
|DetectionId | d0c82b7f-40b2-4180-a4d6-7aa0541b7599 |
|DataTypes | Syslog |
|QueryFrequency | 1h |
|QueryPeriod | 1h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/PulseConnectSecure/PulseConnectSecureVPN-CVE_2021_22893_Exploit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let threshold = 3;
PulseConnectSecure
| where Messages contains "Unauthenticated request url /dana-na/"
| summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), count() by Source_IP
| where count_ > threshold
| extend timestamp = StartTime, IPCustomEntity = Source_IP

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1195|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1195|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1059|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1059|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1546|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1546|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1195|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1195|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1059|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1059|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1546|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1546|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1195|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1195|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1059|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1059|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```

## SUNBURST and SUPERNOVA backdoor hashes

Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFileEvents
References:
- https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
- https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1546|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | a3c144f9-8051-47d4-ac29-ffb0c312c910 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/SolarWinds_SUNBURST_&_SUPERNOVA_File-IOCs.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c542b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc865","4f2eb62fa529c0283b28d05ddd311fae"]);
let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
DeviceFileEvents
| where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
| extend
    timestamp = TimeGenerated,
    AccountCustomEntity = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),
    HostCustomEntity = DeviceName,
    AlgorithmCustomEntity = "MD5",
    FileHashCustomEntity = MD5

```
