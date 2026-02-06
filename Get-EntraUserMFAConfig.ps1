# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-02-05
# Last Update: 2026-02-06
# Script provided as-is

Param
 (
    [switch]$InstallPreReqs
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

# Import-Module Microsoft.Entra
Connect-Entra


# Entra ID Tier Membership explained here: https://trustedsec.com/blog/managing-privileged-roles-in-microsoft-entra-id-a-pragmatic-approach
$Tier0RoleHashTable = @{
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

$Tier0dminArray = @()
ForEach ($Tier0RoleHashTableItem in $Tier0RoleHashTable.GetEnumerator())
 {
    $Tier0dminArray += Get-EntraDirectoryRoleMember -DirectoryRoleId $Tier0RoleHashTableItem.Value
 }

ForEach ($Tier0dminArrayItem in $Tier0dminArray)
 {
    IF ($Tier0dminArrayItem.'@odata.type' -eq '#microsoft.graph.group')
     {
        $GroupMemberArray = Get-EntraGroupMember -GroupId $Tier0dminArrayItem.Id 
        $Tier0dminArray += $GroupMemberArray
     }
 }

$Tier0dminArray = $Tier0dminArray | Sort-Object ID -Unique

$EntraUserMFAConfigArray = @()
ForEach ($Tier0dminArrayItem in $Tier0dminArray)
 {
    $EntraUserMFARecord = [PSCustomObject]@{
        UserDisplayName = $Tier0dminArrayItem.DisplayName
        UserUPN = $Tier0dminArrayItem.UserPrincipalName
        LastPasswordChangeDate = $NULL
        MFAPhoneNumber = $NULL
        MFAPhoneType = $NULL
        MFAsmsSignInState = $NULL
        MFAEmailAddress = $NULL
        MFADeviceDisplayName = $NULL
        MFADeviceTag = $NULL
        MFAPhoneAppVersion = $NULL      
    }

    $EntraUserMFAArray = Get-EntraUserAuthenticationMethod -UserId $Tier0dminArrayItem.ID -ErrorAction SilentlyContinue | Select * 
    
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
     }
                      
   [array]$EntraUserMFAConfigArray += $EntraUserMFARecord
 }

$EntraUserMFAConfigArray = $EntraUserMFAConfigArray | Sort-Object UserDisplayName 
Write-Host "All Direct Tier 0 Admins and Their Registered MFA Methods:" -ForegroundColor Cyan
$EntraUserMFAConfigArray | Format-Table -AutoSize

$UsersWithNoMFA = $EntraUserMFAConfigArray | Where { !($_.MFAPhoneNumber) -AND !($_.MFAPhoneNumber) -AND !($_.MFAEmailAddress) -AND !($_.MFADeviceTag) }
$UsersWithMFAPhoneNumberAndType = $EntraUserMFAConfigArray | Where {($_.MFAPhoneNumber) -AND ($_.MFAPhoneType -eq 'Mobile')}
$UsersWithMFAsmsSignInStateDisabled = $EntraUserMFAConfigArray | Where {$_.MFAsmsSignInState -eq 'notAllowedByPolicy'}
$UsersWithMFADeviceTagActivated = $EntraUserMFAConfigArray | Where {$_.MFADeviceTag -eq 'SoftwareTokenActivated'}
$UsersWithMFAPhoneAppVersion = $EntraUserMFAConfigArray | Where {$_.MFAPhoneAppVersion}

Write-Host "Total Tier 0 Admins: $($Tier0dminArray.Count)" -ForegroundColor Cyan
Write-Host "  Admins with No MFA: $($UsersWithNoMFA.Count)" -ForegroundColor Cyan
Write-Host "  Admins with Phone Number (Mobile): $($UsersWithMFAPhoneNumberAndType.Count)" -ForegroundColor Cyan
IF ($UsersWithMFAsmsSignInStateDisabled)
 { Write-Host "  SMS is disabled"  -ForegroundColor Cyan }
Write-Host "  Total Admins with Microsoft App: $($UsersWithMFADeviceTag.Count)" -ForegroundColor Cyan
Write-Host ""
Write-Host "$($UsersWithNoMFA.Count) Admins with No MFA Configured:" -ForegroundColor Cyan
$UsersWithNoMFA = $UsersWithNoMFA | sort-object UserDisplayName
ForEach ($UsersWithNoMFAItem in $UsersWithNoMFA)
 {
    Write-Host " * $($UsersWithNoMFAItem.UserDisplayName) ($($UsersWithNoMFAItem.UserUPN))"
 }
