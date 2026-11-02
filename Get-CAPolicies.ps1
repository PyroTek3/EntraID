<#
.SYNOPSIS
    Enumerate Entra ID Conditional Access policies via Microsoft Graph REST,
    resolve object GUIDs to display names, and flatten to CSV + HTML.
    No Microsoft.Graph module required — pure Invoke-RestMethod.
    Authentication: OAuth 2.0 device code flow (interactive, delegated).

.NOTES
    Permissions (delegated): Policy.Read.All + Directory.Read.All,
    or a directory role that covers them (Security Reader / Global Reader).
    The signed-in user must be able to consent to those scopes, or they must
    be pre-consented on the public client.

    Endpoint: v1.0 by default; flip -GraphVersion beta for authenticationStrength
    / templateId / newer condition fields.

.EXAMPLE
    .\Get-CAPolicies.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
    .\Get-CAPolicies.ps1 -TenantId <guid> -GraphVersion beta -OutputPath .\ca_audit
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,

    # Public client used for the device code flow. Defaults to the well-known
    # Microsoft Graph PowerShell first-party client (no app registration needed).
    [string] $ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e',

    [ValidateSet('v1.0','beta')] [string] $GraphVersion = 'v1.0',
    [string] $OutputPath = (Join-Path (Get-Location) 'CAPolicies'),

    # Ignore any cached/refreshable token and force a fresh device code sign-in.
    [switch] $ForceLogin
)

$ErrorActionPreference = 'Stop'
$GraphBase = "https://graph.microsoft.com/$GraphVersion"

# ---------------------------------------------------------------------------
# 0. Normalize / validate the tenant identifier
#    Entra requires a tenant GUID or a routable domain (foo.onmicrosoft.com or
#    a verified custom domain). A bare label like 'bigmegacorp' is rejected with
#    AADSTS900023, so promote it to <label>.onmicrosoft.com.
# ---------------------------------------------------------------------------
$guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
if ($TenantId -notmatch $guidPattern -and $TenantId -notmatch '\.') {
    Write-Warning "TenantId '$TenantId' is a bare label; using '$TenantId.onmicrosoft.com'. Pass the tenant GUID or a verified domain to be explicit."
    $TenantId = "$TenantId.onmicrosoft.com"
}

# ---------------------------------------------------------------------------
# 1. Authentication — OAuth 2.0 device code flow
# ---------------------------------------------------------------------------
function Get-GraphToken {
    param([string] $TenantId, [string] $ClientId)

    $scope = 'https://graph.microsoft.com/Policy.Read.All ' +
             'https://graph.microsoft.com/Directory.Read.All offline_access'

    # Request a device code
    $dc = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -Body @{ client_id = $ClientId; scope = $scope }

    Write-Host "`n$($dc.message)`n" -ForegroundColor Yellow

    # Poll the token endpoint until the user completes sign-in
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    do {
        Start-Sleep -Seconds ([int]$dc.interval)
        if ((Get-Date) -gt $deadline) { throw 'Device code expired before sign-in completed.' }
        try {
            $tok = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body @{
                    grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                    client_id   = $ClientId
                    device_code = $dc.device_code
                }
        } catch {
            $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error
            switch ($err) {
                'authorization_pending' { }                         # keep polling
                'slow_down'             { Start-Sleep -Seconds 5 }  # back off
                default                 { throw }                   # declined / expired / bad request
            }
        }
    } until ($tok.access_token)

    $tok.access_token
}

$token   = Get-GraphToken -TenantId $TenantId -ClientId $ClientId
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }

# ---------------------------------------------------------------------------
# 2. Generic paged GET
# ---------------------------------------------------------------------------
function Get-GraphAll {
    param([string] $Uri)
    $items = [System.Collections.Generic.List[object]]::new()
    do {
        $resp = Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
        if ($resp.value) { $items.AddRange([object[]]$resp.value) }
        $Uri = $resp.'@odata.nextLink'
    } while ($Uri)
    ,$items
}

# ---------------------------------------------------------------------------
# 3. Pull policies + reference data for name resolution
# ---------------------------------------------------------------------------
Write-Host 'Fetching Conditional Access policies...' -ForegroundColor Cyan
$policies = Get-GraphAll "$GraphBase/identity/conditionalAccess/policies"

Write-Host 'Fetching named locations, role templates, service principals...' -ForegroundColor Cyan
$namedLocations = Get-GraphAll "$GraphBase/identity/conditionalAccess/namedLocations"
$roleTemplates  = Get-GraphAll "$GraphBase/directoryRoleTemplates"

# Build lookup tables
$locMap = @{}; foreach ($l in $namedLocations) { $locMap[$l.id] = $l.displayName }
$roleMap = @{}; foreach ($r in $roleTemplates)  { $roleMap[$r.id] = $r.displayName }

# Service principals keyed by appId — includeApplications/excludeApplications use appId, not objectId.
$spByAppId = @{}
foreach ($sp in (Get-GraphAll "$GraphBase/servicePrincipals?`$select=appId,displayName")) {
    if ($sp.appId) { $spByAppId[$sp.appId] = $sp.displayName }
}

# Well-known application constants that are not GUIDs
$appConstants = @{
    'All'                   = 'All cloud apps'
    'None'                  = 'None'
    'Office365'             = 'Office 365 (bundle)'
    'MicrosoftAdminPortals' = 'Microsoft Admin Portals'
}

# ---------------------------------------------------------------------------
# 4. Resolve user/group directory-object GUIDs in bulk via getByIds
# ---------------------------------------------------------------------------
$objMap = @{ 'All' = 'All users'; 'None' = 'None'; 'GuestsOrExternalUsers' = 'Guests / external users' }

$guidRegex = '^[0-9a-fA-F-]{36}$'
$idsToResolve = [System.Collections.Generic.HashSet[string]]::new()
foreach ($p in $policies) {
    $u = $p.conditions.users
    foreach ($set in @($u.includeUsers, $u.excludeUsers, $u.includeGroups, $u.excludeGroups)) {
        foreach ($id in $set) { if ($id -match $guidRegex) { [void]$idsToResolve.Add($id) } }
    }
}

# getByIds accepts up to 1000 ids per call.
# NOTE: build the JSON body by hand. ConvertTo-Json in Windows PowerShell 5.1
# collapses a single-element array to a scalar ("ids":"guid"), which Graph
# rejects with 400. Explicit array construction is count-safe on every version.
$idList = @($idsToResolve)
for ($i = 0; $i -lt $idList.Count; $i += 1000) {
    $chunk = @($idList[$i..([Math]::Min($i + 999, $idList.Count - 1))])
    $idsJson  = '[' + (($chunk | ForEach-Object { '"' + $_ + '"' }) -join ',') + ']'
    $bodyJson = '{"ids":' + $idsJson + ',"types":["user","group","servicePrincipal"]}'
    $resolved = Invoke-RestMethod -Method Post -Uri "$GraphBase/directoryObjects/getByIds" `
        -Headers $headers -Body $bodyJson
    foreach ($o in $resolved.value) {
        $name = if ($o.displayName) { $o.displayName }
                elseif ($o.userPrincipalName) { $o.userPrincipalName }
                else { $o.id }
        $objMap[$o.id] = $name
    }
}

# ---------------------------------------------------------------------------
# 5. Resolver helpers
# ---------------------------------------------------------------------------
function Resolve-Objects { param($ids)
    if (-not $ids) { return '' }
    ($ids | ForEach-Object { if ($objMap.ContainsKey($_)) { $objMap[$_] } else { $_ } }) -join '; '
}
function Resolve-Apps { param($ids)
    if (-not $ids) { return '' }
    ($ids | ForEach-Object {
        if ($appConstants.ContainsKey($_)) { $appConstants[$_] }
        elseif ($spByAppId.ContainsKey($_)) { $spByAppId[$_] }
        else { $_ }
    }) -join '; '
}
function Resolve-Roles { param($ids)
    if (-not $ids) { return '' }
    ($ids | ForEach-Object { if ($roleMap.ContainsKey($_)) { $roleMap[$_] } else { $_ } }) -join '; '
}
function Resolve-Locations { param($ids)
    if (-not $ids) { return '' }
    ($ids | ForEach-Object {
        switch ($_) {
            'All'        { 'All locations' }
            'AllTrusted' { 'All trusted locations' }
            default      { if ($locMap.ContainsKey($_)) { $locMap[$_] } else { $_ } }
        }
    }) -join '; '
}

# ---------------------------------------------------------------------------
# 6. Flatten to a report row per policy
# ---------------------------------------------------------------------------
$rows = foreach ($p in $policies) {
    $c = $p.conditions
    [pscustomobject][ordered]@{
        DisplayName            = $p.displayName
        State                  = $p.state
        Id                     = $p.id
        CreatedDateTime        = $p.createdDateTime
        ModifiedDateTime       = $p.modifiedDateTime
        IncludeUsers           = Resolve-Objects   $c.users.includeUsers
        ExcludeUsers           = Resolve-Objects   $c.users.excludeUsers
        IncludeGroups          = Resolve-Objects   $c.users.includeGroups
        ExcludeGroups          = Resolve-Objects   $c.users.excludeGroups
        IncludeRoles           = Resolve-Roles     $c.users.includeRoles
        ExcludeRoles           = Resolve-Roles     $c.users.excludeRoles
        IncludeApps            = Resolve-Apps      $c.applications.includeApplications
        ExcludeApps            = Resolve-Apps      $c.applications.excludeApplications
        UserActions            = ($c.applications.includeUserActions) -join '; '
        ClientAppTypes         = ($c.clientAppTypes) -join '; '
        IncludePlatforms       = ($c.platforms.includePlatforms) -join '; '
        ExcludePlatforms       = ($c.platforms.excludePlatforms) -join '; '
        IncludeLocations       = Resolve-Locations $c.locations.includeLocations
        ExcludeLocations       = Resolve-Locations $c.locations.excludeLocations
        SignInRiskLevels       = ($c.signInRiskLevels) -join '; '
        UserRiskLevels         = ($c.userRiskLevels) -join '; '
        GrantOperator          = $p.grantControls.operator
        GrantControls          = ($p.grantControls.builtInControls) -join '; '
        AuthStrength           = $p.grantControls.authenticationStrength.displayName
        TermsOfUse             = ($p.grantControls.termsOfUse) -join '; '
        SessionControls        = (@(
                                    if ($p.sessionControls.applicationEnforcedRestrictions.isEnabled) { 'AppEnforcedRestrictions' }
                                    if ($p.sessionControls.cloudAppSecurity.isEnabled)                 { "MCAS:$($p.sessionControls.cloudAppSecurity.cloudAppSecurityType)" }
                                    if ($p.sessionControls.persistentBrowser.isEnabled)               { "PersistentBrowser:$($p.sessionControls.persistentBrowser.mode)" }
                                    if ($p.sessionControls.signInFrequency.isEnabled)                  { "SignInFreq:$($p.sessionControls.signInFrequency.value)$($p.sessionControls.signInFrequency.type)" }
                                  ) -join '; ')
    }
}

# ---------------------------------------------------------------------------
# 7. Output — console, CSV, HTML, raw JSON
# ---------------------------------------------------------------------------
$rows | Sort-Object State, DisplayName |
    Format-Table DisplayName, State, GrantControls, AuthStrength -AutoSize

$csvPath  = "$OutputPath.csv"
$htmlPath = "$OutputPath.html"
$jsonPath = "$OutputPath.json"

$rows | Sort-Object State, DisplayName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
$policies | ConvertTo-Json -Depth 25 | Out-File $jsonPath -Encoding UTF8

$style = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;font-size:12px;margin:20px;}
 h1{font-size:18px;}
 table{border-collapse:collapse;width:100%;}
 th,td{border:1px solid #ccc;padding:4px 6px;vertical-align:top;text-align:left;}
 th{background:#0078d4;color:#fff;position:sticky;top:0;}
 tr:nth-child(even){background:#f4f7fb;}
 .enabled{color:#107c10;font-weight:600;}
 .disabled{color:#a80000;}
 .reportonly{color:#8661c5;}
</style>
'@
$html = $rows | Sort-Object State, DisplayName |
    ConvertTo-Html -Title 'Conditional Access Policies' -PreContent "<h1>Conditional Access Policies</h1><p>Tenant: $TenantId &middot; Generated $(Get-Date -Format 'u') &middot; $($rows.Count) policies</p>" -Head $style
# lightweight state coloring
$html = $html -replace '<td>enabled</td>','<td class="enabled">enabled</td>' `
              -replace '<td>disabled</td>','<td class="disabled">disabled</td>' `
              -replace '<td>enabledForReportingButNotEnforced</td>','<td class="reportonly">report-only</td>'
$html | Out-File $htmlPath -Encoding UTF8

Write-Host "`nWrote:" -ForegroundColor Green
Write-Host "  $csvPath"
Write-Host "  $htmlPath"
Write-Host "  $jsonPath"