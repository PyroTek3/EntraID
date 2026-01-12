# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-01-12
# Script provided as-is

Param
 (
    [switch]$InstallPreReqs
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

Import-Module Microsoft.Entra
Connect-Entra
#  Get-Command -Module Microsoft.Entra* -verb get

# Get Administration
$DirectoryRoleArray = Get-EntraDirectoryRole

# Entra ID Tier Membership explained here: https://trustedsec.com/blog/managing-privileged-roles-in-microsoft-entra-id-a-pragmatic-approach
$Tier0RoleArray = @{
    'Application Administrator' = '3f92f59a-8d14-4a54-8527-54a22b3d7353' 
    'Cloud Application Administrator' = 'b8f22551-9c37-48d6-bb28-78c5734dc131'
    'Conditional Access Administrator' = '0faee40b-3a9a-4f79-8637-8ccf2fed37ea'
    'Global Administrator' = 'c7b78838-819c-4322-ab9e-b0f8e95c8dac'   
    'Hybrid Identity Administrator' = '1e2248cd-869b-45ba-a7c4-0e88af6861f2' 
    'Partner Tier2 Support' = 'f7a48fc0-76ed-41ee-9df5-54f5468815b4'     
    'Privileged Authentication Administrator' = '59af1245-2aff-4d20-8c9f-7708193fda5e' 
    'Privileged Role Administrator' = '23e215c3-a6c9-4a57-a883-49d953cdba62'  
    'Security Administrator' = 'dddfb8b9-6206-4123-8836-eac62c4d569e'                                                                  
  }

$HighlyPrivilegedMemberRoleArray = @()
ForEach ( $HighlyPrivilegedRoleArrayItem in $Tier0RoleArray.GetEnumerator() )
 {  
   $EntraDirectoryRoleMemberArray = Get-EntraDirectoryRoleMember $HighlyPrivilegedRoleArrayItem.Value -ErrorAction SilentlyContinue

   $EntraDirectoryRoleMemberArray | Add-Member -MemberType NoteProperty -Name 'MemberOfRole' -Value $HighlyPrivilegedRoleArrayItem.Name -Force 
   [array]$HighlyPrivilegedMemberRoleArray += $EntraDirectoryRoleMemberArray

   ForEach ($EntraDirectoryRoleMemberArrayItem in $EntraDirectoryRoleMemberArray)
    {
       IF ($EntraDirectoryRoleMemberArrayItem.'@odata.type' -eq '#microsoft.graph.group')
         { 
            $EntraGroupName = (Get-EntraGroup -GroupId $EntraDirectoryRoleMemberArrayItem.Id).DisplayName
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
Write-Host "Tier 0 Role Membership:" -ForegroundColor Cyan
$HighlyPrivilegedMemberRoleArray | Sort MemberOfRole | Select MemberOfRole,accountEnabled,'@odata.type',displayName,userPrincipalName,MemberOfGroup,id | Format-Table -AutoSize


## Get PIM

IF ($InstallPreReqs -eq $True)
 { Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber }

Import-Module Microsoft.Graph
Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "PrivilegedAccess.Read.AzureAD"

[array]$EntraPIMRoleEligibleArray = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All

$EntraIDRoleArray = Get-MgRoleManagementDirectoryRoleDefinition | Sort DisplayName

$EntraPIMRoleEligibleRecordArray = @()
ForEach ($EntraPIMRoleEligibleArrayItem in $EntraPIMRoleEligibleArray)
 {
    ForEach ($EntraIDRoleArrayItem in $EntraIDRoleArray)
      {
        IF ($EntraIDRoleArrayItem.Id -eq $EntraPIMRoleEligibleArrayItem.RoleDefinitionID )
         { $RoleName = $EntraIDRoleArrayItem.DisplayName }
      }
    
    ForEach ( $HighlyPrivilegedRoleArrayItem in $Tier0RoleArray.GetEnumerator() )
     { 
        IF ($RoleName -eq $HighlyPrivilegedRoleArrayItem.Name) 
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
$EntraPIMRoleEligibleRecordArray | Sort RoleName | Select RoleName,PrincipalObjectType,PrincipalDisplayName,Status,MemberOfGroup,CreatedDateTime,ModifiedDateTime | Format-Table -AutoSize
##


