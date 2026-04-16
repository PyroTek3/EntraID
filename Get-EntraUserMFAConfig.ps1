# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-02-05
# Last Update: 2026-02-06
# Script provided as-is

Param
 (
    [int]$TierLevel,
    [switch]$InstallPreReq,
    [string]$ExportCSVPath
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

# Import-Module Microsoft.Entra
Write-Host "Connecting to Entra..." -ForegroundColor Cyan
Connect-Entra

# Get Administration
Write-Host "Getting Directory Roles..." -ForegroundColor Cyan
$DirectoryRoleArray = Get-EntraDirectoryRole 

# Entra ID Tier Membership explained here: https://trustedsec.com/blog/managing-privileged-roles-in-microsoft-entra-id-a-pragmatic-approach
$Tier0RoleArray = @(
    'Application Administrator',
    'Cloud Application Administrator',
    'Conditional Access Administrator',
    'Global Administrator',
    'Hybrid Identity Administrator',
    'Partner Tier2 Support',  
    'Privileged Authentication Administrator',
    'Privileged Role Administrator',  
    'Security Administrator'                                                                  
  )

$Tier1RoleArray = @(
    'AI Administrator',
    'Attribute Provisioning Administrator',
    'Authentication Administrator',
    'Authentication Extensibility Administrator',
    'Authentication Policy Administrator',
    'B2C IEF Keyset Administrator',
    'Cloud App Security Administrator',
    'Compliance Administrator',
    'Directory Synchronization Accounts',
    'Directory Writers',
    'Domain Name Administrator',
    'Dynamics 365 Administrator',
    'Exchange Administrator',
    'External ID User Flow Administrator',
    'External Identity Provider Administrator',
    'Global Secure Access Administrator',
    'Groups Administrator',
    'Helpdesk Administrator',
    'Identity Governance Administrator',
    'Intune Administrator',
    'Knowledge Administrator',
    'Lifecycle Workflows Administrator',
    'Microsoft 365 Backup Administrator',
    'Microsoft 365 Migration Administrator',
    'On Premises Directory Sync Account',
    'Partner Tier1 Support',
    'Password Administrator',
    'Power Platform Administrator',
    'Security Operator',
    'SharePoint Administrator',
    'Skype for Business Administrator',
    'Teams Administrator',
    'Teams Telephony Administrator',
    'User Administrator',
    'Windows 365 Administrator',
    'Yammer Administrator'                                                              
  )

$Tier2RoleArray = @(
    'Application Developer',
    'Azure DevOps Administrator',
    'Azure Information Protection Administrator',
    'B2C IEF Policy Administrator',
    'Billing Administrator',
    'Cloud Device Administrator',
    'Customer Lockbox Access Approver',
    'Exchange Recipient Administrator',
    'External ID User Flow Attribute Administrator',
    'Global Reader',
    'License Administrator',
    'Microsoft Entra Joined Device Local Administrator',
    'Security Reader',
    'Teams Communications Administrator',
    'Teams Communications Support Engineer'                                                           
  )

SWITCH ($TierLevel)
 {
    '0' { $TierRoleArray = $Tier0RoleArray } 
    '1' { $TierRoleArray = $Tier1RoleArray } 
    '2' { $TierRoleArray = $Tier2RoleArray } 
    Default { $TierRoleArray = $Tier0RoleArray } 
 }

Write-Host "Enumerating Membership for Tier $TierLevel Roles..." -ForegroundColor Cyan

$HighlyPrivilegedMemberRoleArray = @()
$EntraRAGOwnerArray = @()
ForEach ($HighlyPrivilegedRoleArrayItem in $TierRoleArray)
 {  
   Write-Host "Gathering Membership Data for $HighlyPrivilegedRoleArrayItem" -ForegroundColor Cyan
   $RoleInfoArray = $DirectoryRoleArray | Where {$_.DisplayName -eq $HighlyPrivilegedRoleArrayItem}
   $EntraDirectoryRoleMemberArray = @()
   TRY { $EntraDirectoryRoleMemberArray = Get-EntraDirectoryRoleMember -DirectoryRoleId $RoleInfoArray.Id}
   CATCH { Write-host "Role $HighlyPrivilegedRoleArrayItem Not Found - it may not be activated (used) in the tenant" -ForegroundColor Yellow }
   
   # (Invoke-GraphRequest -Uri "Https://graph.microsoft.com/beta/DirectoryRoles").value | Sort DisplayName #  /$($RoleInfoArray.Id)/members" 
   IF ($EntraDirectoryRoleMemberArray)
    {
       # $EntraDirectoryRoleMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleInfoArray.DisplayName -Force 
       # [array]$HighlyPrivilegedMemberRoleArray += $EntraDirectoryRoleMemberArray

       ForEach ($EntraDirectoryRoleMemberArrayItem in $EntraDirectoryRoleMemberArray)
        {
           IF ($EntraDirectoryRoleMemberArrayItem.'@odata.type' -eq '#microsoft.graph.user')
             { 
                [array]$EntraUserInfoArray = Get-EntraUser -UserId $EntraDirectoryRoleMemberArrayItem.ID
                $EntraUserInfoRecord = New-Object PSObject
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $EntraUserInfoArray.DisplayName -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'UserPrincipalName' -Value $EntraUserInfoArray.UserPrincipalName -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'accountEnabled' -Value $EntraUserInfoArray.accountEnabled -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'User' -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $EntraUserInfoArray.ImmutableId -Force
                IF ($EntraUserInfoArray.ImmutableId)
                 { $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $True -Force }
                ELSE 
                 { $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $False -Force }
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ID' -Value $EntraUserInfoArray.ID -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $NULL -Force
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force   
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $HighlyPrivilegedRoleArrayItem -Force 
                $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
                
                [array]$HighlyPrivilegedMemberRoleArray += $EntraUserInfoRecord
             }

           IF ($EntraDirectoryRoleMemberArrayItem.'@odata.type' -eq '#microsoft.graph.group')
             { 
                $EntraGroupInfoArray = Get-EntraGroup -GroupId $EntraDirectoryRoleMemberArrayItem.Id

                $EntraGroupRecord = New-Object PSObject
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $EntraGroupInfoArray.DisplayName -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'UserPrincipalName' -Value $NULL -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'accountEnabled' -Value $NULL -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'Group' -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $EntraGroupInfoArray.ImmutableId -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'ID' -Value $EntraGroupInfoArray.ID -Force
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force   
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $HighlyPrivilegedRoleArrayItem -Force 
                $EntraGroupRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
                [array]$HighlyPrivilegedMemberRoleArray += $EntraGroupRecord

                $EntraGroupOwnerIDArray = (Get-EntraGroupOwner -GroupId $EntraDirectoryRoleMemberArrayItem.Id -ErrorAction SilentlyContinue).ID
                IF ($EntraGroupOwnerIDArray)
                 { 
                    ForEach ($EntraGroupOwnerIDArrayItem in $EntraGroupOwnerIDArray)
                     {
                        [array]$EntraGroupOwnerArray = Get-EntraUser -UserId $EntraGroupOwnerIDArrayItem

                        $EntraRAGOwnerRecord = New-Object PSObject
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerDisplayName' -Value $EntraGroupOwnerArray.DisplayName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerUPN' -Value $EntraGroupOwnerArray.UserPrincipalName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'RoleAssignableGroup' -Value $EntraGroupInfoArray.DisplayName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'User' -Force
                        $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $EntraGroupOwnerArray.ImmutableId -Force
                        IF ($EntraGroupOwnerArray.ImmutableId)
                         { $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $True -Force }
                        ELSE 
                         { $EntraUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $False -Force }
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerID' -Value $EntraGroupOwnerArray.ID -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
                        [array]$EntraRAGOwnerArray += $EntraRAGOwnerRecord
                     }
                 } 
                
                $GroupMemberArray = Get-EntraGroupMember -GroupId $EntraDirectoryRoleMemberArrayItem.Id  

                ForEach ($GroupMemberArrayItem in $GroupMemberArray)
                 {
                     [array]$EntraUserInfoArray = Get-EntraUser -UserId $GroupMemberArrayItem.ID
                    $EntraGroupUserInfoRecord = New-Object PSObject
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $EntraUserInfoArray.DisplayName -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'UserPrincipalName' -Value $EntraUserInfoArray.UserPrincipalName -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'accountEnabled' -Value $EntraUserInfoArray.accountEnabled -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'User' -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $EntraUserInfoArray.ImmutableId -Force
                    IF ($EntraUserInfoArray.ImmutableId)
                     { $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $True -Force }
                    ELSE 
                     { $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $False -Force }
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ID' -Value $EntraUserInfoArray.ID -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $EntraGroupInfoArray.DisplayName -Force
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force   
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $HighlyPrivilegedRoleArrayItem -Force 
                    $EntraGroupUserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
                    [array]$HighlyPrivilegedMemberRoleArray += $EntraGroupUserInfoRecord
                 }   
             } 
        }
    }
 }

Write-Host ""
# Write-Host "Current Active Tier $TierLevel Role Membership:" -ForegroundColor Cyan
# $HighlyPrivilegedMemberRoleArray | Sort MemberOfRole,'@odata.type' | Select MemberOfRole,accountEnabled,ObjectType,displayName,userPrincipalName,Synced,MemberOfGroup | Format-Table -AutoSize


## Get PIM
IF ($InstallPreReqs -eq $True)
 { Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber }

# Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "PrivilegedAccess.Read.AzureAD"

#[array]$EntraPIMRoleEligibleeArray = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
[array]$EntraPIMRoleEligibleArray = Get-mgrolemanagementdirectoryroleeligibilityscheduleinstance -All 

$EntraIDRoleArray = Get-MgRoleManagementDirectoryRoleDefinition | Sort DisplayName

$EntraPIMRoleEligibleRecordArray = @()
ForEach ($EntraPIMRoleEligibleArrayItem in $EntraPIMRoleEligibleArray)
 {
    ForEach ($EntraIDRoleArrayItem in $EntraIDRoleArray)
      {
        IF ($EntraIDRoleArrayItem.Id -eq $EntraPIMRoleEligibleArrayItem.RoleDefinitionID )
         { $RoleName = $EntraIDRoleArrayItem.DisplayName }
      }
    
    ForEach ( $HighlyPrivilegedRoleArrayItem in $TierRoleArray )
     { 
        IF ($RoleName -eq $HighlyPrivilegedRoleArrayItem) 
         {  
            $UserInfoArray = @()
            $GroupInfoArray = @()
            TRY
              { $UserInfoArray = Get-EntraUser -UserId $EntraPIMRoleEligibleArrayItem.PrincipalId -ErrorAction Stop }
            CATCH
              { $GroupInfoArray = Get-MgGroup -GroupId $EntraPIMRoleEligibleArrayItem.PrincipalId -ErrorAction SilentlyContinue }
    
            IF ($UserInfoArray)
             { 
                $EntraPIMRoleEligibleUserRecord = New-Object PSObject
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'User' -Force 
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $UserInfoArray.DisplayName -Force    
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'ID' -Value $UserInfoArray.ID -Force    
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'userPrincipalName' -Value $UserInfoArray.UserPrincipalName -Force
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'InfoArray' -Value $UserInfoArray -Force
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $UserInfoArray.ImmutableId -Force
                IF ($UserInfoArray.ImmutableId)
                 { $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $True -Force }
                ELSE 
                 { $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $False -Force }
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 
                $EntraPIMRoleEligibleUserRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $RoleName -Force
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleName -Force

                $EntraPIMRoleEligibleRecordArray += $EntraPIMRoleEligibleUserRecord
             } 
            IF ($GroupInfoArray)
             { 
                $EntraPIMRoleEligibleGroupRecord = New-Object PSObject
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'Group' -Force 
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $GroupInfoArray.DisplayName -Force  
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'ID' -Value $GroupInfoArray.ID -Force  
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'InfoArray' -Value $GroupInfoArray -Force  
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $RoleName -Force
                $EntraPIMRoleEligibleGroupRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleName -Force

                $EntraPIMRoleEligibleRecordArray += $EntraPIMRoleEligibleGroupRecord

                $GroupMembersArray = @()
                $GroupMembersArray = Get-MgGroupMember -GroupId $EntraPIMRoleEligibleArrayItem.PrincipalId
                ForEach ($GroupMembersArrayItem in $GroupMembersArray)
                 {
                    $UserInfoArray = Get-EntraUser -UserId $GroupMembersArrayItem.Id 
                    
                    $UserInfoRecord = New-Object PSObject
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleName -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $RoleName -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'CreatedDateTime' -Value $EntraPIMRoleEligibleArrayItem.CreatedDateTime -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ModifiedDateTime' -Value $EntraPIMRoleEligibleArrayItem.ModifiedDateTime -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'PIMStatus' -Value $EntraPIMRoleEligibleArrayItem.Status -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ImmutableId' -Value $UserInfoArray.ImmutableId -Force
                    IF ($UserInfoArray.ImmutableId)
                     { $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $True -Force }
                    ELSE 
                     { $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Synced' -Value $False -Force }
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'ObjectType' -Value 'User' -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'Id' -Value $UserInfoArray.Id -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'accountEnabled' -Value $UserInfoArray.accountEnabled -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $GroupInfoArray.DisplayName -Force 
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'DisplayName' -Value $UserInfoArray.DisplayName -Force    
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'userPrincipalName' -Value $UserInfoArray.UserPrincipalName -Force
                    $UserInfoRecord | Add-Member -MemberType NoteProperty -Name 'InfoArray' -Value $UserInfoArray -Force        
                    [array]$EntraPIMRoleEligibleRecordArray += $UserInfoRecord
                 }
             } 
           }            
        }
   }

[array]$TierAdminArray = $HighlyPrivilegedMemberRoleArray + $EntraPIMRoleEligibleRecordArray
#  $TierAdminArray | Select MemberOfRole,accountEnabled,ObjectType,displayName,userPrincipalName,Synced,MemberOfGroup,Status

$EntraUserMFAConfigArray = @()
ForEach ($TierAdminArrayItem in $TierAdminArray)
 {
    $EntraUserMFARecord = [PSCustomObject]@{
        UserDisplayName = $TierAdminArrayItem.DisplayName
        UserUPN = $TierAdminArrayItem.UserPrincipalName
        ObjectType = $TierAdminArrayItem.ObjectType
        LastPasswordChangeDate = $NULL
        MFAPhoneNumber = $NULL
        MFAPhoneType = $NULL
        MFAsmsSignInState = $NULL
        MFAEmailAddress = $NULL
        MFADeviceDisplayName = $NULL
        MFADeviceTag = $NULL
        MFAPhoneAppVersion = $NULL      
    }

    $EntraUserMFAArray = Get-EntraUserAuthenticationMethod -UserId $TierAdminArrayItem.ID  | Select * 
    
    ForEach ($EntraUserMFAArrayItem in $EntraUserMFAArray)
     {
        IF ($EntraUserMFAArrayItem.CreatedDateTime)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'LastPasswordChangeDate' -Value $EntraUserMFAArrayItem.CreatedDateTime -Force }
 
        IF ($EntraUserMFAArrayItem.PhoneNumber)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFAPhoneNumber' -Value $EntraUserMFAArrayItem.PhoneNumber -Force }

        IF ($EntraUserMFAArrayItem.PhoneType)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFAPhoneType' -Value $EntraUserMFAArrayItem.PhoneType -Force }  

        IF ($EntraUserMFAArrayItem.SmsSignInState)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFAsmsSignInState' -Value $EntraUserMFAArrayItem.SmsSignInState -Force }  

        IF ($EntraUserMFAArrayItem.EmailAddress )
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFAEmailAddress' -Value $EntraUserMFAArrayItem.EmailAddress  -Force }  

        IF ($EntraUserMFAArrayItem.DisplayName)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFADeviceDisplayName' -Value $EntraUserMFAArrayItem.DisplayName -Force }  

        IF ($EntraUserMFAArrayItem.DeviceTag)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFADeviceTag' -Value $EntraUserMFAArrayItem.DeviceTag -Force }  

        IF ($EntraUserMFAArrayItem.PhoneAppVersion)
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFAPhoneAppVersion' -Value $EntraUserMFAArrayItem.PhoneAppVersion -Force }  
     
        IF ($EntraUserMFAArrayItem.AuthenticationMethodType -eq '#microsoft.graph.softwareOathAuthenticationMethod')
         { $EntraUserMFARecord | Add-Member -MemberType NoteProperty -Name 'MFASoftwareOathAuthentication' -Value 'SoftwareOathAuthentication' -Force } 
     }
                      
   [array]$EntraUserMFAConfigArray += $EntraUserMFARecord
 }

$EntraUserMFAConfigArray = $EntraUserMFAConfigArray | Sort-Object UserDisplayName 
Write-Host "All Direct Tier 0 Admins and Their Registered MFA Methods:" -ForegroundColor Cyan
$EntraUserMFAConfigArray | Where {$_.ObjectType -eq '#microsoft.graph.user'} | Select UserDisplayName,UserUPN,MFAPhoneNumber,MFAPhoneType,MFAEmailAddress,MFADeviceDisplayName,MFADeviceTag,MFAPhoneAppVersion,MFASoftwareOathAuthentication,LastPasswordChangeDate | Format-Table -AutoSize

[array]$UsersWithNoMFA = $EntraUserMFAConfigArray | Where { !($_.MFAPhoneNumber) -AND !($_.MFAPhoneNumber) -AND !($_.MFAEmailAddress) -AND !($_.MFADeviceTag) }
[array]$UsersWithMFAPhoneNumberAndType = $EntraUserMFAConfigArray | Where {($_.MFAPhoneNumber) -AND ($_.MFAPhoneType -eq 'Mobile')}
[array]$UsersWithMFAsmsSignInStateDisabled = $EntraUserMFAConfigArray | Where {$_.MFAsmsSignInState -eq 'notAllowedByPolicy'}
[array]$UsersWithMFADeviceTagActivated = $EntraUserMFAConfigArray | Where {$_.MFADeviceTag -eq 'SoftwareTokenActivated'}
[array]$UsersWithMFASoftwareOathAuthentication = $EntraUserMFAConfigArray | Where {$_.MFASoftwareOathAuthentication -eq 'SoftwareOathAuthentication'}
[array]$UsersWithMFAPhoneAppVersion = $EntraUserMFAConfigArray | Where {$_.MFAPhoneAppVersion}

Write-Host "Total Tier 0 Admins: $($Tier0dminArray.Count)" -ForegroundColor Cyan
Write-Host "  Admins with No MFA: $($UsersWithNoMFA.Count)" -ForegroundColor Red
Write-Host "  Admins with Phone Number (Mobile): $($UsersWithMFAPhoneNumberAndType.Count)" -ForegroundColor Cyan
IF ($UsersWithMFAsmsSignInStateDisabled)
 { Write-Host "  SMS is disabled"  -ForegroundColor Cyan }
Write-Host "  Total Admins with Microsoft Authenticator App: $($UsersWithMFADeviceTagActivated.Count)" -ForegroundColor Cyan
Write-Host "  Total Admins with a different Authenticator app: $($UsersWithMFASoftwareOathAuthentication.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "$($UsersWithNoMFA.Count) Admins with No MFA Configured:" -ForegroundColor Cyan
$UsersWithNoMFA = $UsersWithNoMFA | sort-object UserDisplayName
ForEach ($UsersWithNoMFAItem in $UsersWithNoMFA)
 {
    IF ($UsersWithNoMFAItem.ObjectType -eq '#microsoft.graph.user')
     { Write-Host " * $($UsersWithNoMFAItem.UserDisplayName) ($($UsersWithNoMFAItem.UserUPN))" }
 }