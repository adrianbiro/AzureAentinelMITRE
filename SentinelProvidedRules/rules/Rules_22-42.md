# Rules: 22-42

## PE file dropped in Color Profile Folder

'This query looks for writes of PE files to C:\Windows\System32\spool\drivers\color\.
  This is a common directory used by malware, as well as some legitimate programs, and writes of PE files to the folder should be monitored.
  Ref: https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/'

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1203|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | f68a5046-b7eb-4f69-9519-1e99708bb9e0 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/PEfiledroppedinColorDriversFolder.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
DeviceFileEvents
  | where ActionType =~ "FileCreated"
  | where FolderPath has "C:\\Windows\\System32\\spool\\drivers\\color\\" 
  | where FileName endswith ".exe" or FileName endswith ".dll"

```

## PE file dropped in Color Profile Folder

'This query looks for writes of PE files to C:\Windows\System32\spool\drivers\color\.
  This is a common directory used by malware, as well as some legitimate programs, and writes of PE files to the folder should be monitored.
  Ref: https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/'

|Name | Value |
| --- | --- |
|Tactic | Execution|
|TechniqueId | T1203|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | MicrosoftThreatProtection |
|DetectionId | f68a5046-b7eb-4f69-9519-1e99708bb9e0 |
|DataTypes | DeviceFileEvents |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/DeviceFileEvents/PEfiledroppedinColorDriversFolder.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
DeviceFileEvents
  | where ActionType =~ "FileCreated"
  | where FolderPath has "C:\\Windows\\System32\\spool\\drivers\\color\\" 
  | where FileName endswith ".exe" or FileName endswith ".dll"

```

## Suspicious application consent for offline access

'This will alert when a user consents to provide a previously-unknown Azure application with offline access via OAuth.
Offline access will provide the Azure App with access to the listed resources without requiring two-factor authentication.
Consent to applications with offline access and read capabilities should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 3533f74c-9207-4047-96e2-0eb9383be587 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Low |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/SuspiciousOAuthApp_OfflineAccess.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "offline"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "offline_access" and ConsentFull contains "Files.Read" or ConsentFull contains "Mail.Read" or ConsentFull contains "Notes.Read" or ConsentFull contains "ChannelMessage.Read" or ConsentFull contains "Chat.Read" or ConsentFull contains "TeamsActivity.Read" or ConsentFull contains "Group.Read" or ConsentFull contains "EWS.AccessAsUser.All" or ConsentFull contains "EAS.AccessAsUser.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = tostring(iff(isnotempty(InitiatedBy.user.userPrincipalName),InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend GrantUserAgent = tostring(iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, ""))
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent for offline access

'This will alert when a user consents to provide a previously-unknown Azure application with offline access via OAuth.
Offline access will provide the Azure App with access to the listed resources without requiring two-factor authentication.
Consent to applications with offline access and read capabilities should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 3533f74c-9207-4047-96e2-0eb9383be587 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Low |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/SuspiciousOAuthApp_OfflineAccess.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "offline"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "offline_access" and ConsentFull contains "Files.Read" or ConsentFull contains "Mail.Read" or ConsentFull contains "Notes.Read" or ConsentFull contains "ChannelMessage.Read" or ConsentFull contains "Chat.Read" or ConsentFull contains "TeamsActivity.Read" or ConsentFull contains "Group.Read" or ConsentFull contains "EWS.AccessAsUser.All" or ConsentFull contains "EAS.AccessAsUser.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = tostring(iff(isnotempty(InitiatedBy.user.userPrincipalName),InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName))
| extend GrantUserAgent = tostring(iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, ""))
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## NRT New access credential added to Application or Service Principal

'This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where a verify KeyCredential was already present for the app.
If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1550.001|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | e42e889a-caaf-4dbb-aec6-371b37d64298 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NRT_NewAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management")
| where Result =~ "success"
| mv-expand target = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set != "[]"
| extend diff = set_difference(new_value_set, old_value_set)
| where isnotempty(diff)
| parse diff with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify"  or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Microsoft Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away diff, new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId

```

## NRT New access credential added to Application or Service Principal

'This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where a verify KeyCredential was already present for the app.
If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1550.001|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | e42e889a-caaf-4dbb-aec6-371b37d64298 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NRT_NewAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management")
| where Result =~ "success"
| mv-expand target = TargetResources
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set != "[]"
| extend diff = set_difference(new_value_set, old_value_set)
| where isnotempty(diff)
| parse diff with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify"  or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Microsoft Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away diff, new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1136|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1136|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1068|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1068|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1136|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1136|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1068|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Rare application consent

'This will alert when the "Consent to application" operation occurs by a user that has not done this operation before or rarely does this.
This could indicate that permissions to access the listed Azure App were provided to a malicious actor. 
Consent to application, Add service principal and Add OAuth2PermissionGrant should typically be rare events. 
This may help detect the Oauth2 attack that can be initiated by this publicly available tool - https://github.com/fireeye/PwnAuth
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1068|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 83ba3057-9ea3-4759-bf6a-933f2e5bc7ee |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 3.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/RareApplicationConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

let current = 1d;
let auditLookback = 7d;
// Setting threshold to 3 as a default, change as needed.  
// Any operation that has been initiated by a user or app more than 3 times in the past 7 days will be excluded
let threshold = 3;
// Gather initial data from lookback period, excluding current, adjust current to more than a single day if no results
let AuditTrail = AuditLogs | where TimeGenerated >= ago(auditLookback) and TimeGenerated < ago(current)
// 2 other operations that can be part of malicious activity in this situation are 
// "Add OAuth2PermissionGrant" and "Add service principal", extend the filter below to capture these too
| where OperationName has "Consent to application"
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| summarize max(TimeGenerated), OperationCount = count() by OperationName, InitiatedBy, TargetResourceName
// only including operations by initiated by a user or app that is above the threshold so we produce only rare and has not occurred in last 7 days
| where OperationCount > threshold
;
// Gather current period of audit data
let RecentConsent = AuditLogs | where TimeGenerated >= ago(current)
| where OperationName has "Consent to application"
| extend IpAddress = case(
isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.user)).ipAddress), 
isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tostring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_json(tostring(InitiatedBy.app)).ipAddress),
'Not Available')
| extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)), 
tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(parse_json(tostring(InitiatedBy.app)).displayName))
| extend TargetResourceName = tolower(tostring(TargetResources.[0].displayName))
| parse TargetResources.[0].modifiedProperties with * "ConsentType: " ConsentType "]" *
| mv-expand AdditionalDetails
| extend UserAgent = iff(AdditionalDetails.key == "User-Agent",tostring(AdditionalDetails.value),"")
| project TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type;
// Exclude previously seen audit activity for "Consent to application" that was seen in the lookback period
// First for rare InitiatedBy
let RareConsentBy = RecentConsent | join kind= leftanti AuditTrail on OperationName, InitiatedBy 
| extend Reason = "Previously unseen user consenting";
// Second for rare TargetResourceName
let RareConsentApp = RecentConsent | join kind= leftanti AuditTrail on OperationName, TargetResourceName
| extend Reason = "Previously unseen app granted consent";
RareConsentBy | union RareConsentApp
| summarize Reason = makeset(Reason) by TimeGenerated, InitiatedBy, IpAddress, TargetResourceName, Category, OperationName, ConsentType, UserAgent, CorrelationId, Type
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatedBy, HostCustomEntity = TargetResourceName, IPCustomEntity = IpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1550|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1550|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1528|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1528|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | f948a32f-226c-4116-bddd-d95e91d97eb9 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_O365AttackToolkit.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let detectionTime = 1d;
let joinLookback = 14d;
AuditLogs
| where TimeGenerated > ago(detectionTime)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Consent to application"
| where TargetResources has "mailboxsettings"
| extend AppDisplayName = TargetResources.[0].displayName
| extend AppClientId = tolower(TargetResources.[0].id)
| where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayName:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv")))
| extend ConsentFull = TargetResources[0].modifiedProperties[4].newValue
| parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1 "]" *
| where ConsentFull contains "contacts.read" and ConsentFull contains "user.read" and ConsentFull contains "mail.read" and ConsentFull contains "notes.read.all" and ConsentFull contains "mailboxsettings.readwrite" and ConsentFull contains "Files.ReadWrite.All"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", tostring(AdditionalDetails[0].value), "")
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName, ConsentFull, CorrelationId
| join kind = leftouter (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add service principal"
| extend AppClientId = tolower(TargetResources[0].id)
| extend AppReplyURLs = iff(TargetResources[0].modifiedProperties[1].newValue has "AddressType", TargetResources[0].modifiedProperties[1].newValue, "")
| distinct AppClientId, tostring(AppReplyURLs)
)
on AppClientId
| join kind = innerunique (AuditLogs
| where TimeGenerated > ago(joinLookback)
| where LoggedByService =~ "Core Directory"
| where Category =~ "ApplicationManagement"
| where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~ "Add delegated permission grant"
| extend GrantAuthentication = tostring(TargetResources[0].displayName)
| extend GrantOperation = OperationName
| project GrantAuthentication, GrantOperation, CorrelationId
) on CorrelationId
| project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy, AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId, GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
| extend timestamp = TimeGenerated, AccountCustomEntity = GrantInitiatedBy, IPCustomEntity = GrantIpAddress

```
