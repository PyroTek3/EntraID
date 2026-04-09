# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-01-12
# Last Update: 2026-04-09
# Script provided as-is

Param
 (
    [switch]$InstallPreReqs = $True,
    [string]$ExportCSVPath = 'C:\Users\CONSBLM\OneDrive - Capital Group\Retest\Data',
    [switch]$ExportCSV = $True
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

# Import-Module Microsoft.Entra
Connect-Entra

# Get Administration
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

$HighlyPrivilegedMemberRoleArray = @()
$EntraRAGOwnerArray = @()
ForEach ( $HighlyPrivilegedRoleArrayItem in $Tier0RoleArray )
 {  
   $RoleInfoArray = $DirectoryRoleArray | Where {$_.DisplayName -eq $HighlyPrivilegedRoleArrayItem}
   $EntraDirectoryRoleMemberArray = Get-EntraDirectoryRoleMember -DirectoryRoleId $RoleInfoArray.Id
   
   # Invoke-GraphRequest -Uri "Https://graph.microsoft.com/beta/DirectoryRoles/$($RoleInfoArray.Id)/members" 

   $EntraDirectoryRoleMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $RoleInfoArray.DisplayName -Force 
   [array]$HighlyPrivilegedMemberRoleArray += $EntraDirectoryRoleMemberArray

   ForEach ($EntraDirectoryRoleMemberArrayItem in $EntraDirectoryRoleMemberArray)
    {
       IF ($EntraDirectoryRoleMemberArrayItem.'@odata.type' -eq '#microsoft.graph.group')
         { 
            $EntraGroupName = (Get-EntraGroup -GroupId $EntraDirectoryRoleMemberArrayItem.Id).DisplayName
            $EntraGroupOwnerIDArray = (Get-EntraGroupOwner -GroupId $EntraDirectoryRoleMemberArrayItem.Id).ID
            IF ($EntraGroupOwnerIDArray)
             { 
                ForEach ($EntraGroupOwnerIDArrayItem in $EntraGroupOwnerIDArray)
                 {
                    [array]$EntraGroupOwnerArray = Get-EntraUser -UserId $EntraGroupOwnerIDArrayItem

                    $EntraRAGOwnerRecord = New-Object PSObject
                    $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerDisplayName' -Value $EntraGroupOwnerArray.DisplayName -Force
                    $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerUPN' -Value $EntraGroupOwnerArray.UserPrincipalName -Force
                    $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'RoleAssignableGroup' -Value $EntraGroupName -Force
                    $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem.Name -Force
                    $EntraRAGOwnerRecord | Add-Member -MemberType NoteProperty -Name 'OwnerID' -Value $EntraGroupOwnerArray.ID -Force
                    [array]$EntraRAGOwnerArray += $EntraRAGOwnerRecord
                 }
             } 
            $GroupMemberArray = Get-EntraGroupMember -GroupId $EntraDirectoryRoleMemberArrayItem.Id     
            $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfGroup' -Value $EntraGroupName -Force    
            $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem.Name -Force   
            $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'RoleName' -Value $HighlyPrivilegedRoleArrayItem.Name -Force 
            $GroupMemberArray | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Active' -Force 
           [array]$HighlyPrivilegedMemberRoleArray += $GroupMemberArray
         } 
    }
 }
Write-Host ""
Write-Host "Current Active Tier 0 Role Membership:" -ForegroundColor Cyan
$HighlyPrivilegedMemberRoleArray | Sort MemberOfRole | Select MemberOfRole,accountEnabled,'@odata.type',displayName,userPrincipalName,MemberOfGroup | Format-Table -AutoSize
Write-Host ""

Write-Host ""
Write-Host "Tier 0 Role Assignable Group Owners:" -ForegroundColor Cyan
$EntraRAGOwnerArray | Sort MemberOfRole | Format-Table -AutoSize
Write-Host ""


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
    
    ForEach ( $HighlyPrivilegedRoleArrayItem in $Tier0RoleArray )
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
                    $UserInfoArray | Add-Member -MemberType NoteProperty -Name 'PrincipalInfoArray' -Value $UserInfoArray -Force        
                    [array]$EntraPIMRoleEligibleRecordArray += $UserInfoArray
                    }
                } 

            $EntraPIMRoleEligibleRecordArray += $EntraPIMRoleEligibleArrayItem
           }            
        }
   }

Write-Host ""
Write-Host "PIM Eligible Tier 0 Roles:" -ForegroundColor Cyan
$EntraPIMRoleEligibleRecordArray | Sort RoleName,PrincipalDisplayName | Select RoleName,PrincipalObjectType,PrincipalDisplayName,Status,MemberOfGroup,StartDateTime,EndDateTime | Format-Table -AutoSize
##

