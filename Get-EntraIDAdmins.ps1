# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-01-12
# Last Update: 2026-04-09
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
       $EntraDirectoryRoleMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleInfoArray.DisplayName -Force 
       [array]$HighlyPrivilegedMemberRoleArray += $EntraDirectoryRoleMemberArray

       ForEach ($EntraDirectoryRoleMemberArrayItem in $EntraDirectoryRoleMemberArray)
        {
           IF ($EntraDirectoryRoleMemberArrayItem.'@odata.type' -eq '#microsoft.graph.group')
             { 
                $EntraGroupName = (Get-EntraGroup -GroupId $EntraDirectoryRoleMemberArrayItem.Id).DisplayName
                $EntraGroupOwnerIDArray = (Get-EntraGroupOwner -GroupId $EntraDirectoryRoleMemberArrayItem.Id -ErrorAction SilentlyContinue).ID
                IF ($EntraGroupOwnerIDArray)
                 { 
                    ForEach ($EntraGroupOwnerIDArrayItem in $EntraGroupOwnerIDArray)
                     {
                        [array]$EntraGroupOwnerArray = Get-EntraUser -UserId $EntraGroupOwnerIDArrayItem

                        $EntraRAGOwnerRecord = New-Object PSObject
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerDisplayName' -Value $EntraGroupOwnerArray.DisplayName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerUPN' -Value $EntraGroupOwnerArray.UserPrincipalName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'RoleAssignableGroup' -Value $EntraGroupName -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force
                        $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerID' -Value $EntraGroupOwnerArray.ID -Force
                        [array]$EntraRAGOwnerArray += $EntraRAGOwnerRecord
                     }
                 } 
                $GroupMemberArray = Get-EntraGroupMember -GroupId $EntraDirectoryRoleMemberArrayItem.Id     
                $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $EntraGroupName -Force    
                $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem -Force   
                $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $HighlyPrivilegedRoleArrayItem -Force 
                $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
               [array]$HighlyPrivilegedMemberRoleArray += $GroupMemberArray
             } 
        }
    }
 }

Write-Host ""
Write-Host "Current Active Tier $TierLevel Role Membership:" -ForegroundColor Cyan
$HighlyPrivilegedMemberRoleArray | Sort MemberOfRole,'@odata.type' | Select MemberOfRole,accountEnabled,'@odata.type',displayName,userPrincipalName,MemberOfGroup | Format-Table -AutoSize
Write-Host ""

Write-Host ""
Write-Host "Tier $TierLevel Role Assignable Group Owners:" -ForegroundColor Cyan
$EntraRAGOwnerArray | Sort MemberOfRole | Format-Table -AutoSize
Write-Host ""

IF ($ExportCSVPath)
 {
   $HighlyPrivilegedMemberRoleArray | Sort MemberOfRole,'@odata.type' | Select MemberOfRole,accountEnabled,'@odata.type',displayName,userPrincipalName,MemberOfGroup | Export-CSV $($ExportCSVPath + '\Tier' + $TierLevel + '-HighlyPrivilegedRoleMembers.csv') -NoTypeInformation -Force
   $EntraRAGOwnerArray | Sort MemberOfRole | Export-CSV $($ExportCSVPath + '\Tier' + $TierLevel + '-EntraRAGOwners.csv')  -NoTypeInformation -Force
 }


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
              { $UserInfoArray = Get-MgUser -UserId $EntraPIMRoleEligibleArrayItem.PrincipalId -ErrorAction Stop }
            CATCH
              { $GroupInfoArray = Get-MgGroup -GroupId $EntraPIMRoleEligibleArrayItem.PrincipalId -ErrorAction SilentlyContinue }

            $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $RoleName -Force 
    
            IF ($UserInfoArray)
             { 
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalObjectType' -Value 'User' -Force 
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalDisplayName' -Value $UserInfoArray.DisplayName -Force    
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalUPN' -Value $UserInfoArray.UserPrincipalName -Force
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalInfoArray' -Value $UserInfoArray -Force
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 
             } 
            IF ($GroupInfoArray)
             { 
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalObjectType' -Value 'Group' -Force 
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalDisplayName' -Value $GroupInfoArray.DisplayName -Force  
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'PrincipalInfoArray' -Value $GroupInfoArray -Force  
                $EntraPIMRoleEligibleArrayItem | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 

                $GroupMembersArray = @()
                $GroupMembersArray = Get-MgGroupMember -GroupId $EntraPIMRoleEligibleArrayItem.PrincipalId
                ForEach ($GroupMembersArrayItem in $GroupMembersArray)
                 {
                    $UserInfoArray = Get-MgUser -UserId $GroupMembersArrayItem.Id -ErrorAction Stop
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleName -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $RoleName -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'CreatedDateTime' -Value $EntraPIMRoleEligibleArrayItem.CreatedDateTime -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'ModifiedDateTime' -Value $EntraPIMRoleEligibleArrayItem.ModifiedDateTime -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PIMStatus' -Value $EntraPIMRoleEligibleArrayItem.Status -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Eligible' -Force 

                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PrincipalObjectType' -Value 'User' -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'Id' -Value $UserInfoArray.Id -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'accountEnabled' -Value $UserInfoArray.accountEnabled -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $GroupInfoArray.DisplayName -Force 
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PrincipalDisplayName' -Value $UserInfoArray.DisplayName -Force    
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PrincipalUPN' -Value $UserInfoArray.UserPrincipalName -Force
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PrincipalInfoArray' -Value $UserInfoArray -Force        
                    [array]$EntraPIMRoleEligibleRecordArray += $UserInfoArray
                 }
             } 

            $EntraPIMRoleEligibleRecordArray += $EntraPIMRoleEligibleArrayItem
           }            
        }
   }

Write-Host ""
Write-Host "PIM Eligible Tier $TierLevel Roles:" -ForegroundColor Cyan
$EntraPIMRoleEligibleRecordArray | Sort RoleName,PrincipalObjectType,PrincipalDisplayName | Select RoleName,PrincipalObjectType,PrincipalDisplayName,PrincipalUPN,Status,MemberOfGroup,StartDateTime,EndDateTime | Format-Table -AutoSize
##

IF ($ExportCSVPath)
 {
   $EntraPIMRoleEligibleRecordArray | Sort RoleName,PrincipalObjectType,PrincipalDisplayName | Select RoleName,PrincipalObjectType,PrincipalDisplayName,PrincipalUPN,Status,MemberOfGroup,StartDateTime,EndDateTime | Export-CSV $($ExportCSVPath + '\Tier' + $TierLevel + '-EntraPIMRoleEligible.csv') -NoTypeInformation -Force
 }