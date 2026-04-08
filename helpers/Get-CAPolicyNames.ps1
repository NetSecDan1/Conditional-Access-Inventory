<#
.SYNOPSIS
    Phase 2 helper — resolves GUIDs in a CA policy export to display names.

.DESCRIPTION
    Connects to Microsoft Graph, fetches display names for all user GUIDs,
    group GUIDs, service principal GUIDs, and named location GUIDs referenced
    in a CA policy JSON export, then writes a resolved-names.json sidecar file.
    The Python parser automatically picks up resolved-names.json if it is
    present in the same directory as the policy export.

.PARAMETER PolicyFile
    Path to the Graph CA policy JSON export  (e.g. policies.json).

.PARAMETER OutputFile
    Where to write the resolved names  (default: resolved-names.json next to PolicyFile).

.PARAMETER TenantId
    Optional tenant ID — passed to Connect-MgGraph when not already connected.

.EXAMPLE
    .\Get-CAPolicyNames.ps1 -PolicyFile .\policies.json

.EXAMPLE
    .\Get-CAPolicyNames.ps1 -PolicyFile .\policies.json -TenantId "contoso.onmicrosoft.com"

.NOTES
    Requires: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns,
              Microsoft.Graph.Groups, Microsoft.Graph.Applications
    Install :  Install-Module Microsoft.Graph -Scope CurrentUser
    Phase 2 feature — not required for the core analysis tool.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $PolicyFile,

    [string] $OutputFile,

    [string] $TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Resolve output path ───────────────────────────────────────────────────────
if (-not $OutputFile) {
    $OutputFile = Join-Path (Split-Path $PolicyFile -Parent) 'resolved-names.json'
}

# ── Connect ───────────────────────────────────────────────────────────────────
$connectParams = @{ Scopes = @('Directory.Read.All') }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

try {
    $ctx = Get-MgContext
    if (-not $ctx) { Connect-MgGraph @connectParams }
} catch {
    Connect-MgGraph @connectParams
}

Write-Host "Connected as: $((Get-MgContext).Account)"

# ── Load policy JSON ──────────────────────────────────────────────────────────
$raw     = Get-Content $PolicyFile -Raw | ConvertFrom-Json
$policies = if ($raw.value) { $raw.value } else { $raw }

Write-Host "Loaded $($policies.Count) policies from $PolicyFile"

# ── Collect all GUIDs ─────────────────────────────────────────────────────────
$userGuids     = [System.Collections.Generic.HashSet[string]]::new()
$groupGuids    = [System.Collections.Generic.HashSet[string]]::new()
$appGuids      = [System.Collections.Generic.HashSet[string]]::new()
$locationGuids = [System.Collections.Generic.HashSet[string]]::new()
$roleGuids     = [System.Collections.Generic.HashSet[string]]::new()

$SKIP = @('All','None','GuestsOrExternalUsers')

foreach ($p in $policies) {
    $u = $p.conditions.users
    if ($u) {
        foreach ($id in ($u.includeUsers + $u.excludeUsers)   | Where-Object { $_ -and $_ -notin $SKIP }) { $null = $userGuids.Add($id) }
        foreach ($id in ($u.includeGroups + $u.excludeGroups) | Where-Object { $_ })                       { $null = $groupGuids.Add($id) }
        foreach ($id in ($u.includeRoles + $u.excludeRoles)   | Where-Object { $_ })                       { $null = $roleGuids.Add($id) }
    }
    $apps = $p.conditions.applications
    if ($apps) {
        foreach ($id in ($apps.includeApplications + $apps.excludeApplications) | Where-Object { $_ -and $_ -notin $SKIP }) { $null = $appGuids.Add($id) }
    }
    $locs = $p.conditions.locations
    if ($locs) {
        foreach ($id in ($locs.includeLocations + $locs.excludeLocations) | Where-Object { $_ -and $_ -notin $SKIP }) { $null = $locationGuids.Add($id) }
    }
}

Write-Host ("Found: {0} user GUIDs, {1} group GUIDs, {2} app GUIDs, {3} location GUIDs, {4} role GUIDs" -f
    $userGuids.Count, $groupGuids.Count, $appGuids.Count, $locationGuids.Count, $roleGuids.Count)

# ── Resolve helper ────────────────────────────────────────────────────────────
$resolved = @{}

function Resolve-Batch {
    param([string[]] $Ids, [scriptblock] $Fetcher, [string] $Label)
    $i = 0
    foreach ($id in $Ids) {
        $i++
        try {
            $obj = & $Fetcher $id
            $resolved[$id] = $obj.DisplayName
        } catch {
            Write-Warning "  Could not resolve $Label $id : $_"
            $resolved[$id] = $id   # fall back to the raw GUID
        }
        if ($i % 20 -eq 0) { Write-Host "  Resolved $i / $($Ids.Count) $Label GUIDs" }
    }
}

if ($userGuids.Count)     { Resolve-Batch -Ids $userGuids     -Fetcher { param($id) Get-MgUser              -UserId $id }            -Label 'user' }
if ($groupGuids.Count)    { Resolve-Batch -Ids $groupGuids    -Fetcher { param($id) Get-MgGroup             -GroupId $id }           -Label 'group' }
if ($appGuids.Count)      { Resolve-Batch -Ids $appGuids      -Fetcher { param($id) Get-MgServicePrincipal  -Filter "appId eq '$id'" | Select-Object -First 1 } -Label 'app' }
if ($locationGuids.Count) { Resolve-Batch -Ids $locationGuids -Fetcher { param($id) Get-MgIdentityConditionalAccessNamedLocation -NamedLocationId $id } -Label 'location' }
if ($roleGuids.Count)     { Resolve-Batch -Ids $roleGuids     -Fetcher { param($id) Get-MgDirectoryRoleTemplate -DirectoryRoleTemplateId $id }          -Label 'role' }

# ── Write sidecar ─────────────────────────────────────────────────────────────
$resolved | ConvertTo-Json -Depth 2 | Set-Content -Path $OutputFile -Encoding UTF8
Write-Host ""
Write-Host "Resolved $($resolved.Count) GUIDs -> $OutputFile"
Write-Host "The Python parser will pick this up automatically on next run."
