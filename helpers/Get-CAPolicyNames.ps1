<#
.SYNOPSIS
    Phase 2 helper - resolves GUIDs in a CA policy export to human-readable display names.

.DESCRIPTION
    Graph API returns GUIDs for users, groups, named locations, apps, and roles inside
    CA policy JSON.  This script resolves each unique GUID and writes resolved-names.json
    alongside the export.  parser.py picks it up automatically when present.

.PARAMETER PolicyFile
    Path to the raw Graph CA policy JSON export (e.g. policies.json).

.PARAMETER OutputFile
    Output path. Defaults to resolved-names.json next to PolicyFile.

.EXAMPLE
    Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"
    .\Get-CAPolicyNames.ps1 -PolicyFile .\policies.json

.NOTES
    Requires: Microsoft.Graph PowerShell SDK  (Install-Module Microsoft.Graph)
    Phase 2 feature - the tool works fine without this; GUIDs display as-is.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyFile,
    [string]$OutputFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutputFile) {
    $OutputFile = Join-Path (Split-Path $PolicyFile -Parent) 'resolved-names.json'
}

Write-Host "Loading $PolicyFile..."
$raw  = Get-Content $PolicyFile -Raw | ConvertFrom-Json
$pols = if ($raw.value) { $raw.value } else { $raw }
Write-Host "  $($pols.Count) policies loaded"

# Collect unique GUIDs
$guids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$guidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
foreach ($p in $pols) {
    $c = $p.conditions
    $lists = @(
        $c.users.includeUsers,   $c.users.excludeUsers,
        $c.users.includeGroups,  $c.users.excludeGroups,
        $c.users.includeRoles,   $c.users.excludeRoles,
        $c.applications.includeApplications, $c.applications.excludeApplications,
        $c.locations.includeLocations,       $c.locations.excludeLocations
    )
    foreach ($list in $lists) {
        if ($list) { $list | Where-Object { $_ -match $guidPattern } | ForEach-Object { $null = $guids.Add($_) } }
    }
}
Write-Host "  $($guids.Count) unique GUIDs to resolve"

# Resolve via Graph
$resolved = @{}
$i = 0
foreach ($guid in $guids) {
    $i++
    Write-Progress -Activity "Resolving GUIDs" -Status "$i / $($guids.Count)" -PercentComplete (($i / $guids.Count) * 100)

    $candidates = @(
        "users/$guid`?`$select=id,displayName,userPrincipalName",
        "groups/$guid`?`$select=id,displayName",
        "identity/conditionalAccess/namedLocations/$guid",
        "directoryRoles?`$filter=roleTemplateId eq '$guid'&`$select=id,displayName",
        "servicePrincipals?`$filter=appId eq '$guid'&`$select=appId,displayName"
    )

    foreach ($path in $candidates) {
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/$path" -ErrorAction SilentlyContinue
            $obj  = if ($resp.value) { $resp.value | Select-Object -First 1 } else { $resp }
            if ($obj) {
                $name = $obj.userPrincipalName ?? $obj.displayName
                if ($name) {
                    $resolved[$guid] = @{ displayName = $name; type = ($path -split '/')[0] }
                    break
                }
            }
        } catch { }
    }
}
Write-Progress -Activity "Resolving GUIDs" -Completed

$resolved | ConvertTo-Json -Depth 4 | Set-Content $OutputFile -Encoding UTF8
Write-Host ""
Write-Host "Resolved: $($resolved.Count) / $($guids.Count)"
Write-Host "Output:   $OutputFile"
Write-Host "The CA inventory tool picks this up automatically on next run."
