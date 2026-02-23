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

Write-Host "Get Entra ID Applications..." -ForegroundColor Cyan
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
        [array]$AppOwnerInfoArray += $AppOwnerUserInfo
     }  
    
 }

 Write-Host ""
 Write-Host "Application Owners:" -ForegroundColor Cyan
 $AppOwnerInfoArray | Select ApplicationName,DisplayName,UserPrincipalName | Format-Table


