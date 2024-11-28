# Rules: 43-63

## Suspicious application consent similar to O365 Attack Toolkit

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://github.com/mdsecactivebreach/o365-attack-toolkit).
The default permissions/scope for the MDSec O365 Attack toolkit are contacts.read, user.read, mail.read, notes.read.all, mailboxsettings.readwrite, and files.readwrite.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
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

## Service Principal Assigned Privileged Role

'Detects a privileged role being added to a Service Principal.
  Ensure that any assignment to a Service Principal is valid and appropriate - Service Principals should not be assigned to very highly privileged roles such as Global Admin.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 84cccc86-5c11-4b3a-aca6-7c8f738ed0f7 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ServicePrincipalAssignedPrivilegedRole.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
  | where OperationName has_all ("member to role", "add")
  | where Result =~ "Success"
  | extend type_ = tostring(TargetResources[0].type)
  | where type_ =~ "ServicePrincipal"
  | where isnotempty(TargetResources)
  | extend ServicePrincipal = tostring(TargetResources[0].displayName)
  | extend SPID = tostring(TargetResources[0].id)
  | mv-expand TargetResources[0].modifiedProperties
  | extend TargetResources_0_modifiedProperties = columnifexists("TargetResources_0_modifiedProperties", '')
  | where isnotempty(TargetResources_0_modifiedProperties)
  | where TargetResources_0_modifiedProperties.displayName =~ "Role.DisplayName"
  | extend TargetRole = parse_json(tostring(TargetResources_0_modifiedProperties.newValue))
  | where TargetRole contains "admin"
  | extend AddedByApp = iif(
  isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalName)),
  tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalName),
  tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  )
  | extend AddedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(AddedByApp), AddedByApp, AddedByUser)
  | extend IpAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
  | project-reorder TimeGenerated, ServicePrincipal, SPID, TargetRole, AddedBy, IpAddress
  | project-away AddedByApp, AddedByUser

```

## Service Principal Assigned Privileged Role

'Detects a privileged role being added to a Service Principal.
  Ensure that any assignment to a Service Principal is valid and appropriate - Service Principals should not be assigned to very highly privileged roles such as Global Admin.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 84cccc86-5c11-4b3a-aca6-7c8f738ed0f7 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ServicePrincipalAssignedPrivilegedRole.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
  | where OperationName has_all ("member to role", "add")
  | where Result =~ "Success"
  | extend type_ = tostring(TargetResources[0].type)
  | where type_ =~ "ServicePrincipal"
  | where isnotempty(TargetResources)
  | extend ServicePrincipal = tostring(TargetResources[0].displayName)
  | extend SPID = tostring(TargetResources[0].id)
  | mv-expand TargetResources[0].modifiedProperties
  | extend TargetResources_0_modifiedProperties = columnifexists("TargetResources_0_modifiedProperties", '')
  | where isnotempty(TargetResources_0_modifiedProperties)
  | where TargetResources_0_modifiedProperties.displayName =~ "Role.DisplayName"
  | extend TargetRole = parse_json(tostring(TargetResources_0_modifiedProperties.newValue))
  | where TargetRole contains "admin"
  | extend AddedByApp = iif(
  isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalName)),
  tostring(parse_json(tostring(InitiatedBy.app)).servicePrincipalName),
  tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  )
  | extend AddedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(AddedByApp), AddedByApp, AddedByUser)
  | extend IpAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
  | project-reorder TimeGenerated, ServicePrincipal, SPID, TargetRole, AddedBy, IpAddress
  | project-away AddedByApp, AddedByUser

```

## Authentication Method Changed for Privileged Account

'Identifies authentication methods being changed for a privileged account. This could be an indicated of an attacker adding an auth method to the account so they can have continued access.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | feb0a2fb-ae75-4343-8cbc-ed545f1da289 |
|DataTypes | AuditLogs |
|QueryFrequency | 2h |
|QueryPeriod | 2h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AuthenticationMethodChangedforPrivilegedAccount.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let VIPUsers = (IdentityInfo
| where AssignedRoles contains "Admin"
| summarize by tolower(AccountUPN));
AuditLogs
| where Category =~ "UserManagement"
| where ActivityDisplayName =~ "User registered security info"
| where LoggedByService =~ "Authentication Methods"
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where AccountCustomEntity in (VIPUsers)

```

## Authentication Method Changed for Privileged Account

'Identifies authentication methods being changed for a privileged account. This could be an indicated of an attacker adding an auth method to the account so they can have continued access.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | feb0a2fb-ae75-4343-8cbc-ed545f1da289 |
|DataTypes | AuditLogs |
|QueryFrequency | 2h |
|QueryPeriod | 2h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AuthenticationMethodChangedforPrivilegedAccount.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let VIPUsers = (IdentityInfo
| where AssignedRoles contains "Admin"
| summarize by tolower(AccountUPN));
AuditLogs
| where Category =~ "UserManagement"
| where ActivityDisplayName =~ "User registered security info"
| where LoggedByService =~ "Authentication Methods"
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where AccountCustomEntity in (VIPUsers)

```

## Authentication Method Changed for Privileged Account

'Identifies authentication methods being changed for a privileged account. This could be an indicated of an attacker adding an auth method to the account so they can have continued access.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | feb0a2fb-ae75-4343-8cbc-ed545f1da289 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 2h |
|QueryPeriod | 2h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AuthenticationMethodChangedforPrivilegedAccount.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let VIPUsers = (IdentityInfo
| where AssignedRoles contains "Admin"
| summarize by tolower(AccountUPN));
AuditLogs
| where Category =~ "UserManagement"
| where ActivityDisplayName =~ "User registered security info"
| where LoggedByService =~ "Authentication Methods"
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where AccountCustomEntity in (VIPUsers)

```

## Authentication Method Changed for Privileged Account

'Identifies authentication methods being changed for a privileged account. This could be an indicated of an attacker adding an auth method to the account so they can have continued access.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | feb0a2fb-ae75-4343-8cbc-ed545f1da289 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 2h |
|QueryPeriod | 2h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AuthenticationMethodChangedforPrivilegedAccount.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let VIPUsers = (IdentityInfo
| where AssignedRoles contains "Admin"
| summarize by tolower(AccountUPN));
AuditLogs
| where Category =~ "UserManagement"
| where ActivityDisplayName =~ "User registered security info"
| where LoggedByService =~ "Authentication Methods"
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where AccountCustomEntity in (VIPUsers)

```

## Authentication Method Changed for Privileged Account

'Identifies authentication methods being changed for a privileged account. This could be an indicated of an attacker adding an auth method to the account so they can have continued access.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#things-to-monitor-1'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | feb0a2fb-ae75-4343-8cbc-ed545f1da289 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 2h |
|QueryPeriod | 2h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AuthenticationMethodChangedforPrivilegedAccount.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let VIPUsers = (IdentityInfo
| where AssignedRoles contains "Admin"
| summarize by tolower(AccountUPN));
AuditLogs
| where Category =~ "UserManagement"
| where ActivityDisplayName =~ "User registered security info"
| where LoggedByService =~ "Authentication Methods"
| extend AccountCustomEntity = tostring(TargetResources[0].userPrincipalName), IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| where AccountCustomEntity in (VIPUsers)

```

## NRT PIM Elevation Request Rejected

'Identifies when a user is rejected for a privileged role elevation via PIM. Monitor rejections for indicators of attacker compromise of the requesting account.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-identity-management'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 5db427b2-f406-4274-b413-e9fcb29412f8 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NRT_PIMElevationRequestRejected.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where ActivityDisplayName =~'Add member to role completed (PIM activation)'
| where Result == "failure"
| extend Role = tostring(TargetResources[3].displayName)
| extend User = tostring(TargetResources[2].displayName)
| project-reorder TimeGenerated, User, Role, OperationName, Result, ResultDescription
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)

```

## NRT PIM Elevation Request Rejected

'Identifies when a user is rejected for a privileged role elevation via PIM. Monitor rejections for indicators of attacker compromise of the requesting account.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-identity-management'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 5db427b2-f406-4274-b413-e9fcb29412f8 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | High |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NRT_PIMElevationRequestRejected.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where ActivityDisplayName =~'Add member to role completed (PIM activation)'
| where Result == "failure"
| extend Role = tostring(TargetResources[3].displayName)
| extend User = tostring(TargetResources[2].displayName)
| project-reorder TimeGenerated, User, Role, OperationName, Result, ResultDescription
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)

```

## Conditional Access Policy Modified by New User

'Detects a Conditional Access Policy being modified by a user who has not modified a policy in the last 14 days.
  A threat actor may try to modify policies to weaken the security controls in place.
  Investigate any change to ensure they are approved.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-infrastructure#conditional-access'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 25a7f951-54b7-4cf5-9862-ebc04306c590 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ConditionalAccessPolicyModifiedbyNewUser.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let known_users = (AuditLogs
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where OperationName has "conditional access policy"
  | where Result =~ "success"
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | summarize by userPrincipalName);
  AuditLogs
  | where TimeGenerated > ago(1d)
  | where OperationName has "conditional access policy"
  | where Result =~ "success"
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend CAPolicyName = tostring(TargetResources[0].displayName)
  | extend ipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
  | where userPrincipalName !in (known_users)
  | extend NewPolicyValues = TargetResources[0].modifiedProperties[0].newValue
  | extend OldPolicyValues = TargetResources[0].modifiedProperties[0].oldValue
  | project-reorder TimeGenerated, OperationName, CAPolicyName, userPrincipalName, ipAddress, NewPolicyValues, OldPolicyValues

```

## Conditional Access Policy Modified by New User

'Detects a Conditional Access Policy being modified by a user who has not modified a policy in the last 14 days.
  A threat actor may try to modify policies to weaken the security controls in place.
  Investigate any change to ensure they are approved.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-infrastructure#conditional-access'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 25a7f951-54b7-4cf5-9862-ebc04306c590 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ConditionalAccessPolicyModifiedbyNewUser.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let known_users = (AuditLogs
  | where TimeGenerated between(ago(14d)..ago(1d))
  | where OperationName has "conditional access policy"
  | where Result =~ "success"
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | summarize by userPrincipalName);
  AuditLogs
  | where TimeGenerated > ago(1d)
  | where OperationName has "conditional access policy"
  | where Result =~ "success"
  | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend CAPolicyName = tostring(TargetResources[0].displayName)
  | extend ipAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
  | where userPrincipalName !in (known_users)
  | extend NewPolicyValues = TargetResources[0].modifiedProperties[0].newValue
  | extend OldPolicyValues = TargetResources[0].modifiedProperties[0].oldValue
  | project-reorder TimeGenerated, OperationName, CAPolicyName, userPrincipalName, ipAddress, NewPolicyValues, OldPolicyValues

```

## Mail.Read Permissions Granted to Application

'This query look for applications that have been granted (Delegated or App/Role) permissions to Read Mail (Permissions field has Mail.Read) and subsequently has been consented to. This can help identify applications that have been abused to gain access to mailboxes.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 2560515c-07d1-434e-87fb-ebe3af267760 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MailPermissionsAddedToApplication.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

AuditLogs
| where Category =~ "ApplicationManagement"
| where ActivityDisplayName has_any ("Add delegated permission grant","Add app role assignment to service principal")
| where Result =~ "success"
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend props = parse_json(tostring(TargetResources[0].modifiedProperties))
| mv-expand props
| extend UserAgent = tostring(AdditionalDetails[0].value)
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend UserIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend DisplayName = tostring(props.displayName)
| extend Permissions = tostring(parse_json(tostring(props.newValue)))
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
| extend PermissionsAddedTo = tostring(TargetResources[0].displayName)
| extend Type = tostring(TargetResources[0].type)
| project-away props
| join kind=leftouter(
  AuditLogs
  | where ActivityDisplayName has "Consent to application"
  | extend AppName = tostring(TargetResources[0].displayName)
  | extend AppId = tostring(TargetResources[0].id)
  | project AppName, AppId, CorrelationId) on CorrelationId
| project-reorder TimeGenerated, OperationName, InitiatingUser, UserIPAddress, UserAgent, PermissionsAddedTo, Permissions, AppName, AppId, CorrelationId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUser, IPCustomEntity = UserIPAddress

```

## Mail.Read Permissions Granted to Application

'This query look for applications that have been granted (Delegated or App/Role) permissions to Read Mail (Permissions field has Mail.Read) and subsequently has been consented to. This can help identify applications that have been abused to gain access to mailboxes.'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1098|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 2560515c-07d1-434e-87fb-ebe3af267760 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MailPermissionsAddedToApplication.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql

AuditLogs
| where Category =~ "ApplicationManagement"
| where ActivityDisplayName has_any ("Add delegated permission grant","Add app role assignment to service principal")
| where Result =~ "success"
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend props = parse_json(tostring(TargetResources[0].modifiedProperties))
| mv-expand props
| extend UserAgent = tostring(AdditionalDetails[0].value)
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend UserIPAddress = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)
| extend DisplayName = tostring(props.displayName)
| extend Permissions = tostring(parse_json(tostring(props.newValue)))
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
| extend PermissionsAddedTo = tostring(TargetResources[0].displayName)
| extend Type = tostring(TargetResources[0].type)
| project-away props
| join kind=leftouter(
  AuditLogs
  | where ActivityDisplayName has "Consent to application"
  | extend AppName = tostring(TargetResources[0].displayName)
  | extend AppId = tostring(TargetResources[0].id)
  | project AppName, AppId, CorrelationId) on CorrelationId
| project-reorder TimeGenerated, OperationName, InitiatingUser, UserIPAddress, UserAgent, PermissionsAddedTo, Permissions, AppName, AppId, CorrelationId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUser, IPCustomEntity = UserIPAddress

```

## Multiple admin membership removals from newly created admin.

'This query detects when newly created Global admin removes multiple existing global admins which can be an attempt by adversaries to lock down organization and retain sole access. 
 Investigate reasoning and intention of multiple membership removal by new Global admins and take necessary actions accordingly.'

|Name | Value |
| --- | --- |
|Tactic | Impact|
|TechniqueId | T1531|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | cda5928c-2c1e-4575-9dfa-07568bc27a4f |
|DataTypes | AuditLogs |
|QueryFrequency | 1h |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MultipleAdmin_membership_removals_from_NewAdmin.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let lookback = 7d; 
let timeframe = 1h; 
let GlobalAdminsRemoved = AuditLogs 
| where TimeGenerated > ago(timeframe) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Unassign", "RemoveEligibleRole") 
| where ActivityDisplayName has_any ("Remove member from role", "Remove eligible member from role") 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.oldValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize RemovedGlobalAdminTime = max(TimeGenerated), TargetAdmins = make_set(Target) by OperationName,  RoleName, Initiator, Result; 
let GlobalAdminsAdded = AuditLogs 
| where TimeGenerated > ago(lookback) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Assign", "AssignEligibleRole") 
| where ActivityDisplayName has_any ("Add eligible member to role", "Add member to role") and Result == "success" 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.newValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize AddedGlobalAdminTime = max(TimeGenerated) by OperationName,  RoleName, Target, Initiator, Result 
| extend AccountCustomEntity = Target; 
GlobalAdminsAdded 
| join kind= inner GlobalAdminsRemoved on $left.Target == $right.Initiator 
| where AddedGlobalAdminTime < RemovedGlobalAdminTime 
| extend NoofAdminsRemoved = array_length(TargetAdmins) 
| where NoofAdminsRemoved > 1
| project AddedGlobalAdminTime, Initiator, Target, AccountCustomEntity, RemovedGlobalAdminTime, TargetAdmins, NoofAdminsRemoved

```

## Multiple admin membership removals from newly created admin.

'This query detects when newly created Global admin removes multiple existing global admins which can be an attempt by adversaries to lock down organization and retain sole access. 
 Investigate reasoning and intention of multiple membership removal by new Global admins and take necessary actions accordingly.'

|Name | Value |
| --- | --- |
|Tactic | Impact|
|TechniqueId | T1531|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | cda5928c-2c1e-4575-9dfa-07568bc27a4f |
|DataTypes | AuditLogs |
|QueryFrequency | 1h |
|QueryPeriod | 7d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MultipleAdmin_membership_removals_from_NewAdmin.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let lookback = 7d; 
let timeframe = 1h; 
let GlobalAdminsRemoved = AuditLogs 
| where TimeGenerated > ago(timeframe) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Unassign", "RemoveEligibleRole") 
| where ActivityDisplayName has_any ("Remove member from role", "Remove eligible member from role") 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.oldValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize RemovedGlobalAdminTime = max(TimeGenerated), TargetAdmins = make_set(Target) by OperationName,  RoleName, Initiator, Result; 
let GlobalAdminsAdded = AuditLogs 
| where TimeGenerated > ago(lookback) 
| where Category =~ "RoleManagement" 
| where AADOperationType in ("Assign", "AssignEligibleRole") 
| where ActivityDisplayName has_any ("Add eligible member to role", "Add member to role") and Result == "success" 
| mv-expand TargetResources 
| mv-expand TargetResources.modifiedProperties 
| extend displayName_ = tostring(TargetResources_modifiedProperties.displayName) 
| where displayName_ =~ "Role.DisplayName" 
| extend RoleName = tostring(parse_json(tostring(TargetResources_modifiedProperties.newValue))) 
| where RoleName == "Global Administrator" // Add other Privileged role if applicable 
| extend InitiatingApp = tostring(parse_json(tostring(InitiatedBy.app)).displayName) 
| extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)) 
| where Initiator != "MS-PIM"  // Filtering PIM events 
| extend Target = tostring(TargetResources.userPrincipalName) 
| summarize AddedGlobalAdminTime = max(TimeGenerated) by OperationName,  RoleName, Target, Initiator, Result 
| extend AccountCustomEntity = Target; 
GlobalAdminsAdded 
| join kind= inner GlobalAdminsRemoved on $left.Target == $right.Initiator 
| where AddedGlobalAdminTime < RemovedGlobalAdminTime 
| extend NoofAdminsRemoved = array_length(TargetAdmins) 
| where NoofAdminsRemoved > 1
| project AddedGlobalAdminTime, Initiator, Target, AccountCustomEntity, RemovedGlobalAdminTime, TargetAdmins, NoofAdminsRemoved

```

## New access credential added to Application or Service Principal

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
|DetectionId | 79566f41-df67-4e10-a703-c38a6213afd8 |
|DataTypes | AuditLogs |
|QueryFrequency | 1h |
|QueryPeriod | 1h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NewAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
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
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress

```

## New access credential added to Application or Service Principal

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
|DetectionId | 79566f41-df67-4e10-a703-c38a6213afd8 |
|DataTypes | AuditLogs |
|QueryFrequency | 1h |
|QueryPeriod | 1h |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/NewAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
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
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress

```

## Account created or deleted by non-approved user

'Identifies accounts that were created or deleted by a defined list of non-approved user principal names. Add to this list before running the query for accurate results.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts'

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 6d63efa6-7c25-4bd4-a486-aa6bf50fde8a |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AccountCreatedDeletedByNonApprovedUser.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
// Add non-approved user principal names to the list below to search for their account creation/deletion activity
// ex: dynamic(["UPN1", "upn123"])
let nonapproved_users = dynamic([]);
AuditLogs
| where OperationName == "Add user" or OperationName == "Delete user"
| where Result == "success"
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| where InitiatingUser has_any (nonapproved_users)
| project-reorder TimeGenerated, ResourceId, OperationName, InitiatingUser, TargetResources
| extend AccountCustomEntity = InitiatingUser, IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)

```

## Account created or deleted by non-approved user

'Identifies accounts that were created or deleted by a defined list of non-approved user principal names. Add to this list before running the query for accurate results.
Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-user-accounts'

|Name | Value |
| --- | --- |
|Tactic | InitialAccess|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 6d63efa6-7c25-4bd4-a486-aa6bf50fde8a |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/AccountCreatedDeletedByNonApprovedUser.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
// Add non-approved user principal names to the list below to search for their account creation/deletion activity
// ex: dynamic(["UPN1", "upn123"])
let nonapproved_users = dynamic([]);
AuditLogs
| where OperationName == "Add user" or OperationName == "Delete user"
| where Result == "success"
| extend InitiatingUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| where InitiatingUser has_any (nonapproved_users)
| project-reorder TimeGenerated, ResourceId, OperationName, InitiatingUser, TargetResources
| extend AccountCustomEntity = InitiatingUser, IPCustomEntity = tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)

```
