# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-02-23
# Last Update: 2026-02-23
# Script provided as-is

Param
 (
    [switch]$InstallPreReqs
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

Connect-Entra

# Setting Lookup table for Tier 0 Application Permissions
# From: https://learn.microsoft.com/en-us/graph/permissions-reference
$Tier0PermissionHashTable = @{}
$Tier0PermissionHashTable.Add("ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9","ADSynchronization.ReadWrite.All")
$Tier0PermissionHashTable.Add("1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9","Application.ReadWrite.All")
$Tier0PermissionHashTable.Add("06b708a9-e830-4db3-a914-8e69da51d44f","AppRoleAssignment.ReadWrite.All")
$Tier0PermissionHashTable.Add("8e8e4742-1d95-4f68-9d56-6ee75648c72a","DelegatedPermissionGrant.ReadWrite.All")
$Tier0PermissionHashTable.Add("19dbc75e-c2e2-444c-a770-ec69d8559fc7","Directory.ReadWrite.All")
$Tier0PermissionHashTable.Add("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","RoleManagement.ReadWrite.Directory")
$Tier0PermissionHashTable.Add("025d3225-3f02-4882-b4c0-cd5b541a4e80","RoleManagement.ReadWrite.Exchange")
$Tier0PermissionHashTable.Add("31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad","RoleManagementPolicy.ReadWrite.Directory")


<#
$PermissionHashTable.Add("e006e431-a65b-4f3e-8808-77d29d4c5f1a","PasswordWriteback.RegisterClientVersion.All")
$PermissionHashTable.Add("69201c67-737b-4a20-8f16-e0c8c64e0b0e","PasswordWriteback.OffboardClient.All")
$PermissionHashTable.Add("fc7e8088-95b5-453e-8bef-b17ecfec5ba3","PasswordWriteback.RefreshClient.All")
#>

Write-Host "Getting All Service Principals for the Entra Tenant (this could take a while)..." -ForegroundColor Cyan
[array]$EntraServicePrincipalArray = Get-EntraServicePrincipal -All

Write-Host "Checking Service Principals for Tier 0 application permissions..." -ForegroundColor Cyan 
$ApplicationPermissionDataArray = @()
$Tier0ApplicationHashTable = @{}
ForEach ($EntraServicePrincipalArrayItem in $EntraServicePrincipalArray)
 {
    [array]$ServicePrincipalAppRoleArray = Get-EntraServicePrincipalAppRoleAssignment -ServicePrincipalID $EntraServicePrincipalArrayItem.Id -All
    ForEach ($ServicePrincipalAppRoleArrayItem in $ServicePrincipalAppRoleArray)
     {
        $AppPermissionName = $NULL
        $AppPermissionName = $Tier0PermissionHashTable.Get_Item($ServicePrincipalAppRoleArrayItem.AppRoleId)
        IF ($AppPermissionName)
          { 
             $ApplicationPermissionDataRecord = [PSCustomObject]@{
                AppName           = $EntraServicePrincipalArrayItem.DisplayName
                AppId             = $EntraServicePrincipalArrayItem.Id
                ResourceId        = $resourceSp.Id
                AppPermission     = $AppPermissionName
                AppPermissionId   = $ServicePrincipalAppRoleArrayItem.AppRoleId
              }
            [array]$ApplicationPermissionDataArray += $ApplicationPermissionDataRecord
            
            $AppPermissions = $NULL
            $AppPermissions = $Tier0ApplicationHashTable.Get_Item($EntraServicePrincipalArrayItem.DisplayName)
            IF ($AppPermissions)
             { 
                $AppPermissionsAddendum = $AppPermissions + ", " + $AppPermissionName
                $Tier0ApplicationHashTable.Remove($EntraServicePrincipalArrayItem.DisplayName)
                $Tier0ApplicationHashTable.Add($EntraServicePrincipalArrayItem.DisplayName,$AppPermissionsAddendum) 
             }
            ELSE
             { $Tier0ApplicationHashTable.Add($EntraServicePrincipalArrayItem.DisplayName,$AppPermissionName) }

          }      
     }
 }

Write-Host "Getting Entra ID Applications..." -ForegroundColor Cyan
[array]$ApplicationArray = Get-EntraApplication -All
$ApplicationArray = $ApplicationArray | Sort-Object DisplayName

Write-Host "Identifying Entra ID Application Owners..." -ForegroundColor Cyan
$AppOwnerInfoArray = @()
ForEach ($ApplicationArrayItem in $ApplicationArray)
 {
    [array]$AppOwnerArray = Get-EntraApplicationOwner -ApplicationId $ApplicationArrayItem.Id
    
    ForEach ($AppOwnerArrayItem in $AppOwnerArray)
     {
        [array]$AppOwnerUserInfo = Get-EntraUser -UserID $AppOwnerArrayItem.Id
        $AppOwnerUserInfo | Add-Member -MemberType NoteProperty -Name 'ApplicationName' -Value $ApplicationArrayItem.DisplayName -Force 
        $Tier0AppPermissions = $NULL
        $Tier0AppPermissions = $Tier0ApplicationHashTable.Get_Item($ApplicationArrayItem.DisplayName)
        IF ($Tier0AppPermissions)
         { 
            $AppOwnerUserInfo | Add-Member -MemberType NoteProperty -Name 'TierLevel' -Value 0 -Force
            $AppOwnerUserInfo | Add-Member -MemberType NoteProperty -Name 'TierPermissions' -Value $Tier0AppPermissions -Force
         }
        ELSE
         {
            $AppOwnerUserInfo | Add-Member -MemberType NoteProperty -Name 'TierLevel' -Value $NULL -Force
            $AppOwnerUserInfo | Add-Member -MemberType NoteProperty -Name 'TierPermissions' -Value $NULL -Force
         }
        
        [array]$AppOwnerInfoArray += $AppOwnerUserInfo
     }  
 }

 Write-Host ""
 Write-Host "Application Owners:" -ForegroundColor Cyan
 $AppOwnerInfoArray | Select TierLevel,ApplicationName,DisplayName,UserPrincipalName,TierPermissions | Format-Table

 

