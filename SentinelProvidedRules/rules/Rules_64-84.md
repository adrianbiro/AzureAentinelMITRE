# Rules: 64-84

## Changes to Application Logout URL

'Detects changes to an applications sign out URL.
  Look for any modifications to a sign out URL. Blank entries or entries to non-existent locations would stop a user from terminating a session.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-applications#logout-url-modified-or-removed'

|Name | Value |
| --- | --- |
|Tactic | Persistence|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 492fbe35-cbac-4a8c-9059-826782e6915a |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Low |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ChangestoApplicationLogoutURL.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
  | where Category =~ "ApplicationManagement"
  | where OperationName has_any ("Update Application", "Update Service principal")
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend UpdatedBy = iif(isnotempty(appName), appName, UPN)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend AppName = tostring(TargetResources[0].displayName)
  | mv-expand mod_props
  | extend Action = tostring(mod_props.displayName)
  | where Action contains "Url"
  | extend OldURL = tostring(mod_props.oldValue)
  | extend NewURL = tostring(mod_props.newValue)
  | project-reorder TimeGenerated, OperationName, Action, AppName, OldURL, NewURL, UpdatedBy

```

## Changes to Application Logout URL

'Detects changes to an applications sign out URL.
  Look for any modifications to a sign out URL. Blank entries or entries to non-existent locations would stop a user from terminating a session.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-applications#logout-url-modified-or-removed'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 492fbe35-cbac-4a8c-9059-826782e6915a |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Low |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ChangestoApplicationLogoutURL.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
  | where Category =~ "ApplicationManagement"
  | where OperationName has_any ("Update Application", "Update Service principal")
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend UpdatedBy = iif(isnotempty(appName), appName, UPN)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend AppName = tostring(TargetResources[0].displayName)
  | mv-expand mod_props
  | extend Action = tostring(mod_props.displayName)
  | where Action contains "Url"
  | extend OldURL = tostring(mod_props.oldValue)
  | extend NewURL = tostring(mod_props.newValue)
  | project-reorder TimeGenerated, OperationName, Action, AppName, OldURL, NewURL, UpdatedBy

```

## Changes to Application Logout URL

'Detects changes to an applications sign out URL.
  Look for any modifications to a sign out URL. Blank entries or entries to non-existent locations would stop a user from terminating a session.
  Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-applications#logout-url-modified-or-removed'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 492fbe35-cbac-4a8c-9059-826782e6915a |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 1d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Low |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ChangestoApplicationLogoutURL.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
  | where Category =~ "ApplicationManagement"
  | where OperationName has_any ("Update Application", "Update Service principal")
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend UpdatedBy = iif(isnotempty(appName), appName, UPN)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend AppName = tostring(TargetResources[0].displayName)
  | mv-expand mod_props
  | extend Action = tostring(mod_props.displayName)
  | where Action contains "Url"
  | extend OldURL = tostring(mod_props.oldValue)
  | extend NewURL = tostring(mod_props.newValue)
  | project-reorder TimeGenerated, OperationName, Action, AppName, OldURL, NewURL, UpdatedBy

```

## Privileged Account Permissions Changed

'Detects changes to permissions assigned to admin users. Threat actors may try and increase permission scope by adding additional roles to already privileged accounts.
Review any modifications to ensure they were made legitimately.
Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 0433c8a3-9aa6-4577-beef-2ea23be41137 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/PrivilegedAccountPermissionsChanged.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let admin_users = (IdentityInfo
  | where TimeGenerated > ago(2d)
  | summarize arg_max(TimeGenerated, *) by AccountUPN
  | where AssignedRoles contains "admin"
  | summarize by tolower(AccountUPN));
  AuditLogs
  | where Category =~ "RoleManagement"
  | where OperationName has "Add eligible member"
  | extend userPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | where tolower(userPrincipalName) in (admin_users)
  | extend Group = tostring(TargetResources[0].displayName)
  | extend AddedTo = iif(isnotempty(userPrincipalName), userPrincipalName, Group)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(appName), appName, UPN)
  | mv-expand mod_props
  | where mod_props.displayName == "Role.DisplayName"
  | extend RoleAdded = tostring(parse_json(tostring(mod_props.newValue)))
  | project-reorder TimeGenerated, OperationName, AddedTo, RoleAdded, AddedBy

```

## Privileged Account Permissions Changed

'Detects changes to permissions assigned to admin users. Threat actors may try and increase permission scope by adding additional roles to already privileged accounts.
Review any modifications to ensure they were made legitimately.
Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 0433c8a3-9aa6-4577-beef-2ea23be41137 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/PrivilegedAccountPermissionsChanged.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let admin_users = (IdentityInfo
  | where TimeGenerated > ago(2d)
  | summarize arg_max(TimeGenerated, *) by AccountUPN
  | where AssignedRoles contains "admin"
  | summarize by tolower(AccountUPN));
  AuditLogs
  | where Category =~ "RoleManagement"
  | where OperationName has "Add eligible member"
  | extend userPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | where tolower(userPrincipalName) in (admin_users)
  | extend Group = tostring(TargetResources[0].displayName)
  | extend AddedTo = iif(isnotempty(userPrincipalName), userPrincipalName, Group)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(appName), appName, UPN)
  | mv-expand mod_props
  | where mod_props.displayName == "Role.DisplayName"
  | extend RoleAdded = tostring(parse_json(tostring(mod_props.newValue)))
  | project-reorder TimeGenerated, OperationName, AddedTo, RoleAdded, AddedBy

```

## Privileged Account Permissions Changed

'Detects changes to permissions assigned to admin users. Threat actors may try and increase permission scope by adding additional roles to already privileged accounts.
Review any modifications to ensure they were made legitimately.
Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | 0433c8a3-9aa6-4577-beef-2ea23be41137 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/PrivilegedAccountPermissionsChanged.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let admin_users = (IdentityInfo
  | where TimeGenerated > ago(2d)
  | summarize arg_max(TimeGenerated, *) by AccountUPN
  | where AssignedRoles contains "admin"
  | summarize by tolower(AccountUPN));
  AuditLogs
  | where Category =~ "RoleManagement"
  | where OperationName has "Add eligible member"
  | extend userPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | where tolower(userPrincipalName) in (admin_users)
  | extend Group = tostring(TargetResources[0].displayName)
  | extend AddedTo = iif(isnotempty(userPrincipalName), userPrincipalName, Group)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(appName), appName, UPN)
  | mv-expand mod_props
  | where mod_props.displayName == "Role.DisplayName"
  | extend RoleAdded = tostring(parse_json(tostring(mod_props.newValue)))
  | project-reorder TimeGenerated, OperationName, AddedTo, RoleAdded, AddedBy

```

## Privileged Account Permissions Changed

'Detects changes to permissions assigned to admin users. Threat actors may try and increase permission scope by adding additional roles to already privileged accounts.
Review any modifications to ensure they were made legitimately.
Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | 0433c8a3-9aa6-4577-beef-2ea23be41137 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/PrivilegedAccountPermissionsChanged.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let admin_users = (IdentityInfo
  | where TimeGenerated > ago(2d)
  | summarize arg_max(TimeGenerated, *) by AccountUPN
  | where AssignedRoles contains "admin"
  | summarize by tolower(AccountUPN));
  AuditLogs
  | where Category =~ "RoleManagement"
  | where OperationName has "Add eligible member"
  | extend userPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | where tolower(userPrincipalName) in (admin_users)
  | extend Group = tostring(TargetResources[0].displayName)
  | extend AddedTo = iif(isnotempty(userPrincipalName), userPrincipalName, Group)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(appName), appName, UPN)
  | mv-expand mod_props
  | where mod_props.displayName == "Role.DisplayName"
  | extend RoleAdded = tostring(parse_json(tostring(mod_props.newValue)))
  | project-reorder TimeGenerated, OperationName, AddedTo, RoleAdded, AddedBy

```

## Privileged Account Permissions Changed

'Detects changes to permissions assigned to admin users. Threat actors may try and increase permission scope by adding additional roles to already privileged accounts.
Review any modifications to ensure they were made legitimately.
Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-operations-privileged-accounts#changes-to-privileged-accounts'

|Name | Value |
| --- | --- |
|Tactic | PrivilegeEscalation|
|TechniqueId | T1078.004|
|Platform | Windows|
|DetectionType | Analytics |
|ConnectorId | BehaviorAnalytics |
|DetectionId | 0433c8a3-9aa6-4577-beef-2ea23be41137 |
|DataTypes | BehaviorAnalytics |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/PrivilegedAccountPermissionsChanged.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let admin_users = (IdentityInfo
  | where TimeGenerated > ago(2d)
  | summarize arg_max(TimeGenerated, *) by AccountUPN
  | where AssignedRoles contains "admin"
  | summarize by tolower(AccountUPN));
  AuditLogs
  | where Category =~ "RoleManagement"
  | where OperationName has "Add eligible member"
  | extend userPrincipalName = tostring(TargetResources[0].userPrincipalName)
  | where tolower(userPrincipalName) in (admin_users)
  | extend Group = tostring(TargetResources[0].displayName)
  | extend AddedTo = iif(isnotempty(userPrincipalName), userPrincipalName, Group)
  | extend mod_props = TargetResources[0].modifiedProperties
  | extend appName = tostring(parse_json(tostring(InitiatedBy.app)).displayName)
  | extend UPN = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
  | extend AddedBy = iif(isnotempty(appName), appName, UPN)
  | mv-expand mod_props
  | where mod_props.displayName == "Role.DisplayName"
  | extend RoleAdded = tostring(parse_json(tostring(mod_props.newValue)))
  | project-reorder TimeGenerated, OperationName, AddedTo, RoleAdded, AddedBy

```

## Credential added after admin consented to Application

'This query will identify instances where Service Principal credentials were added to an application by one user after the application was granted admin consent rights by another user.
 If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
 Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow.
 For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | |
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 707494a5-8e44-486b-90f8-155d1797a8eb |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/CredentialAddedAfterAdminConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let auditLookbackStart = 2d;
let auditLookbackEnd = 1d;
AuditLogs
| where TimeGenerated >= ago(auditLookbackStart)
| where OperationName =~ "Consent to application" 
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetResourceType = tostring(target.type)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend isAdminConsent = targetModifiedProp[0].newValue
| extend Consent_ServicePrincipalNames = targetModifiedProp[5].newValue
| extend Consent_Permissions = targetModifiedProp[4].newValue
| extend Consent_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Consent_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| join ( 
AuditLogs
| where TimeGenerated  >= ago(auditLookbackEnd)
| where OperationName =~ "Add service principal credentials"
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend Credential_KeyDescription = targetModifiedProp[0].newValue
| extend UpdatedProperties = targetModifiedProp[1].newValue
| extend Credential_ServicePrincipalNames = targetModifiedProp[2].newValue
| extend Credential_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Credential_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
) on targetResourceName, targetResourceID
| extend TimeConsent = TimeGenerated, TimeCred = TimeGenerated1
| where TimeConsent > TimeCred 
| project TimeConsent, TimeCred, Consent_InitiatingUserOrApp, Credential_InitiatingUserOrApp, targetResourceName, targetResourceType, isAdminConsent, Consent_ServicePrincipalNames, Credential_ServicePrincipalNames, Consent_Permissions, Credential_KeyDescription, Consent_InitiatingIpAddress, Credential_InitiatingIpAddress
| extend timestamp = TimeConsent, AccountCustomEntity = Consent_InitiatingUserOrApp, IPCustomEntity = Consent_InitiatingIpAddress

```

## Credential added after admin consented to Application

'This query will identify instances where Service Principal credentials were added to an application by one user after the application was granted admin consent rights by another user.
 If a threat actor obtains access to an account with sufficient privileges and adds the alternate authentication material triggering this event, the threat actor can now authenticate as the Application or Service Principal using this credential.
 Additional information on OAuth Credential Grants can be found in RFC 6749 Section 4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow.
 For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | |
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 707494a5-8e44-486b-90f8-155d1797a8eb |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 2d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/CredentialAddedAfterAdminConsent.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
let auditLookbackStart = 2d;
let auditLookbackEnd = 1d;
AuditLogs
| where TimeGenerated >= ago(auditLookbackStart)
| where OperationName =~ "Consent to application" 
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetResourceType = tostring(target.type)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend isAdminConsent = targetModifiedProp[0].newValue
| extend Consent_ServicePrincipalNames = targetModifiedProp[5].newValue
| extend Consent_Permissions = targetModifiedProp[4].newValue
| extend Consent_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Consent_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| join ( 
AuditLogs
| where TimeGenerated  >= ago(auditLookbackEnd)
| where OperationName =~ "Add service principal credentials"
| where Result =~ "success"
| mv-expand target = TargetResources
| extend targetResourceName = tostring(target.displayName)
| extend targetResourceID = tostring(target.id)
| extend targetModifiedProp = TargetResources[0].modifiedProperties
| extend Credential_KeyDescription = targetModifiedProp[0].newValue
| extend UpdatedProperties = targetModifiedProp[1].newValue
| extend Credential_ServicePrincipalNames = targetModifiedProp[2].newValue
| extend Credential_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Credential_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
) on targetResourceName, targetResourceID
| extend TimeConsent = TimeGenerated, TimeCred = TimeGenerated1
| where TimeConsent > TimeCred 
| project TimeConsent, TimeCred, Consent_InitiatingUserOrApp, Credential_InitiatingUserOrApp, targetResourceName, targetResourceType, isAdminConsent, Consent_ServicePrincipalNames, Credential_ServicePrincipalNames, Consent_Permissions, Credential_KeyDescription, Consent_InitiatingIpAddress, Credential_InitiatingIpAddress
| extend timestamp = TimeConsent, AccountCustomEntity = Consent_InitiatingUserOrApp, IPCustomEntity = Consent_InitiatingIpAddress

```

## NRT First access credential added to Application or Service Principal where no credential was present

'This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where there was no previous verify KeyCredential associated.
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
|DetectionId | b6988c32-4f3b-4a45-8313-b46b33061a74 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/nrt_FirstAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
| where Result =~ "success"
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set == "[]"
| mv-expand new_value_set
| parse new_value_set with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify"  or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Microsoft Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress

```

## NRT First access credential added to Application or Service Principal where no credential was present

'This will alert when an admin or app owner account adds a new credential to an Application or Service Principal where there was no previous verify KeyCredential associated.
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
|DetectionId | b6988c32-4f3b-4a45-8313-b46b33061a74 |
|DataTypes | AuditLogs |
|QueryFrequency |  |
|QueryPeriod |  |
|TriggerOperator |  |
|TriggerThreshold |  |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/nrt_FirstAppOrServicePrincipalCredential.yaml |
|IngestedDate | 2022-08-07 |

### KQL
```kql
AuditLogs
| where OperationName has_any ("Add service principal", "Certificates and secrets management") // captures "Add service principal", "Add service principal credentials", and "Update application - Certificates and secrets management" events
| where Result =~ "success"
| where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(InitiatedBy.app.displayName) has "@"
| extend targetDisplayName = tostring(TargetResources[0].displayName)
| extend targetId = tostring(TargetResources[0].id)
| extend targetType = tostring(TargetResources[0].type)
| extend keyEvents = TargetResources[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend new_value_set = parse_json(tostring(keyEvents.newValue))
| extend old_value_set = parse_json(tostring(keyEvents.oldValue))
| where old_value_set == "[]"
| mv-expand new_value_set
| parse new_value_set with * "KeyIdentifier=" keyIdentifier:string ",KeyType=" keyType:string ",KeyUsage=" keyUsage:string ",DisplayName=" keyDisplayName:string "]" *
| where keyUsage == "Verify"  or keyUsage == ""
| extend UserAgent = iff(AdditionalDetails[0].key == "User-Agent",tostring(AdditionalDetails[0].value),"")
| extend InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrincipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
// The below line is currently commented out but Microsoft Sentinel users can modify this query to show only Application or only Service Principal events in their environment
//| where targetType =~ "Application" // or targetType =~ "ServicePrincipal"
| project-away new_value_set, old_value_set
| project-reorder TimeGenerated, OperationName, InitiatingUserOrApp, InitiatingIpAddress, UserAgent, targetDisplayName, targetId, targetType, keyDisplayName, keyType, keyUsage, keyIdentifier, CorrelationId, TenantId
| extend timestamp = TimeGenerated, AccountCustomEntity = InitiatingUserOrApp, IPCustomEntity = InitiatingIpAddress

```

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1528|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1550|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | CredentialAccess|
|TechniqueId | T1550|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1528|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1528|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1550|
|Platform | Azure|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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

## Suspicious application consent similar to PwnAuth

'This will alert when a user consents to provide a previously-unknown Azure application with the same OAuth permissions used by the FireEye PwnAuth toolkit (https://github.com/fireeye/PwnAuth).
The default permissions/scope for the PwnAuth toolkit are user.read, offline_access, mail.readwrite, mail.send, and files.read.all.
Consent to applications with these permissions should be rare, especially as the knownApplications list is expanded. Public contributions to expand this filter are welcome!
For further information on AuditLogs please see https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-audit-activities.'

|Name | Value |
| --- | --- |
|Tactic | DefenseEvasion|
|TechniqueId | T1550|
|Platform | Azure AD|
|DetectionType | Analytics |
|ConnectorId | AzureActiveDirectory |
|DetectionId | 39198934-62a0-4781-8416-a81265c03fd6 |
|DataTypes | AuditLogs |
|QueryFrequency | 1d |
|QueryPeriod | 14d |
|TriggerOperator | gt |
|TriggerThreshold | 0.0 |
|DetectionSeverity | Medium |
|DetectionUrl | https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/MaliciousOAuthApp_PwnAuth.yaml |
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
| where ConsentFull contains "user.read" and ConsentFull contains "offline_access" and ConsentFull contains "mail.readwrite" and ConsentFull contains "mail.send" and ConsentFull contains "files.read.all"
| where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth application was granted to all users via an admin - but admin due diligence should be audited occasionally
| extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
| extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend GrantUserAgent = iff(AdditionalDetails[0].key =~ "User-Agent", AdditionalDetails[0].value, "")
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
