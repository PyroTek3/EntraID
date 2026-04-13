# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2026-02-23
# Last Update: 2026-04-13
# Script provided as-is

Param
 (
    [int]$TierLevel,
    [switch]$InstallPreReqs,
    [string]$ExportCSVPath
 )

IF ($InstallPreReqs -eq $True)
 { Install-Module Microsoft.Entra -Repository PSGallery -Scope CurrentUser -Force -AllowClobber }

Connect-Entra

# Setting Lookup table for Tier 0 Application Permissions
# From: https://learn.microsoft.com/en-us/graph/permissions-reference
$Tier0PermissionHashTable = @{}
#$Tier0PermissionHashTable.Add("ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9","ADSynchronization.ReadWrite.All")
$Tier0PermissionHashTable.Add("1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9","Application.ReadWrite.All")
$Tier0PermissionHashTable.Add("06b708a9-e830-4db3-a914-8e69da51d44f","AppRoleAssignment.ReadWrite.All")
$Tier0PermissionHashTable.Add("8e8e4742-1d95-4f68-9d56-6ee75648c72a","DelegatedPermissionGrant.ReadWrite.All")
$Tier0PermissionHashTable.Add("19dbc75e-c2e2-444c-a770-ec69d8559fc7","Directory.ReadWrite.All")
$Tier0PermissionHashTable.Add("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","RoleManagement.ReadWrite.Directory")
#$Tier0PermissionHashTable.Add("025d3225-3f02-4882-b4c0-cd5b541a4e80","RoleManagement.ReadWrite.Exchange")
$Tier0PermissionHashTable.Add("31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad","RoleManagementPolicy.ReadWrite.Directory")

# Setting Lookup table for Tier 1 Application Permissions
# From: https://learn.microsoft.com/en-us/graph/permissions-reference
$Tier1PermissionHashTable = @{}
$Tier1PermissionHashTable.Add("3b4349e1-8cf5-45a3-95b7-69d1751d3e6a",'CloudPC.ReadWrite.All')
$Tier1PermissionHashTable.Add("9f1b81a7-0223-4428-bfa4-0bcb5535f27d",'ConsentRequest.ReadWrite.All')
$Tier1PermissionHashTable.Add("8e8e4742-1d95-4f68-9d56-6ee75648c72a",'DelegatedPermissionGrant.ReadWrite.All')
$Tier1PermissionHashTable.Add("1138cb37-bd11-4084-a2b7-9f71582aeddb",'Device.ReadWrite.All')
$Tier1PermissionHashTable.Add("78145de6-330d-4800-a6ce-494ff2d33d07",'DeviceManagementApps.ReadWrite.All')
$Tier1PermissionHashTable.Add("9241abd9-d0e6-425a-bd4f-47ba86e767a4",'DeviceManagementConfiguration.ReadWrite.All')
$Tier1PermissionHashTable.Add("5b07b0dd-2377-4e44-a38d-703f09a0dc3c",'DeviceManagementManagedDevices.PrivilegedOperations.All')
$Tier1PermissionHashTable.Add("243333ab-4d21-40cb-a475-36241daa0842",'DeviceManagementManagedDevices.ReadWrite.All')
$Tier1PermissionHashTable.Add("e330c4f0-4170-414e-a55a-2f022ec2b57b",'DeviceManagementRBAC.ReadWrite.All')
$Tier1PermissionHashTable.Add("5ac13192-7ace-4fcf-b828-1a26f28068ee",'DeviceManagementServiceConfig.ReadWrite.All')
$Tier1PermissionHashTable.Add("7e05723c-0bb0-42da-be95-ae9f08a6e53c",'Domain.ReadWrite.All')
$Tier1PermissionHashTable.Add("62a82d76-70ea-41e2-9197-370581804d09",'Group.ReadWrite.All')
$Tier1PermissionHashTable.Add("dbaae8cf-10b5-4b86-a4a1-f871c94c6695",'GroupMember.ReadWrite.All')
$Tier1PermissionHashTable.Add("90db2b9a-d928-4d33-a4dd-8442ae3d41e4",'IdentityProvider.ReadWrite.All')
$Tier1PermissionHashTable.Add("e2a3a72e-5f79-4c64-b1b1-878b674786c9",'Mail.ReadWrite')
$Tier1PermissionHashTable.Add("6931bccd-447a-43d1-b442-00a195474933",'MailboxSettings.ReadWrite')
$Tier1PermissionHashTable.Add("292d869f-3427-49a8-9dab-8c70152b74e9",'Organization.ReadWrite.All')
$Tier1PermissionHashTable.Add("be74164b-cff1-491c-8741-e671cb536e13",'Policy.ReadWrite.ApplicationConfiguration')
$Tier1PermissionHashTable.Add("25f85f3c-f66c-4205-8cd5-de92dd7f0cec",'Policy.ReadWrite.AuthenticationFlows')
$Tier1PermissionHashTable.Add("29c18626-4985-4dcd-85c0-193eef327366",'Policy.ReadWrite.AuthenticationMethod' )
$Tier1PermissionHashTable.Add("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",'RoleManagement.ReadWrite.Directory')
$Tier1PermissionHashTable.Add("a82116e5-55eb-4c41-a434-62fe8a61c773",'Sites.FullControl.All')
$Tier1PermissionHashTable.Add("0c0bf378-bf22-4481-8f81-9e89a9b4960a",'Sites.Manage.All')
$Tier1PermissionHashTable.Add("9492366f-7969-46a4-8d15-ed1a20078fff",'Sites.ReadWrite.All')
$Tier1PermissionHashTable.Add("741f803b-c850-494e-b5df-cde7c675a1ca",'User.ReadWrite.All')
$Tier1PermissionHashTable.Add("50483e42-d915-4231-9639-7fdb7fd190e5",'UserAuthenticationMethod.ReadWrite.All')

<#
$PermissionHashTable.Add("e006e431-a65b-4f3e-8808-77d29d4c5f1a","PasswordWriteback.RegisterClientVersion.All")
$PermissionHashTable.Add("69201c67-737b-4a20-8f16-e0c8c64e0b0e","PasswordWriteback.OffboardClient.All")
$PermissionHashTable.Add("fc7e8088-95b5-453e-8bef-b17ecfec5ba3","PasswordWriteback.RefreshClient.All")
#>

Write-Host "Getting All Service Principals for the Entra Tenant (this could take a while)..." -ForegroundColor Cyan
[array]$EntraServicePrincipalArray = Get-EntraServicePrincipal -All

Write-Host "Checking Service Principals for Tier $TierLevel application permissions..." -ForegroundColor Cyan 
$ApplicationPermissionDataArray = @()
ForEach ($EntraServicePrincipalArrayItem in $EntraServicePrincipalArray)
 {
    $ServicePrincipalAppRoleArray = Get-EntraServicePrincipalAppRoleAssignment -ServicePrincipalID $EntraServicePrincipalArrayItem.Id -All
    ForEach ($ServicePrincipalAppRoleArrayItem in $ServicePrincipalAppRoleArray)
     {
        $AppPermissionName = $NULL
        SWITCH ($TierLevel)
         {
            '0' { $AppPermissionName = $Tier0PermissionHashTable.Get_Item($ServicePrincipalAppRoleArrayItem.AppRoleId) } 
            '1' { $AppPermissionName = $Tier1PermissionHashTable.Get_Item($ServicePrincipalAppRoleArrayItem.AppRoleId) } 
            Default { $AppPermissionName = $Tier0PermissionHashTable.Get_Item($ServicePrincipalAppRoleArrayItem.AppRoleId) } 
         }

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
          }      
     }
 }

Write-Host ""
Write-Host "Applications with Tier $TierLevel Application Permissions:" -ForegroundColor Cyan
$ApplicationPermissionDataArray | Select-Object AppName,AppPermission,AppID,AppPermissionId | Format-Table -AutoSize

IF ($ExportCSVPath)
 {
   $ApplicationPermissionDataArray | Select-Object AppName,AppPermission,AppID,AppPermissionId | Export-CSV $($ExportCSVPath + '\Tier' + $TierLevel + '-ApplicationPermissions.csv') -NoTypeInformation -Force
 }

