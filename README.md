# CA Policy Inventory & Gap Analysis Tool

A local Python tool that ingests a Microsoft Graph Conditional Access policy export,
runs an opinionated gap analysis against Zero Trust best practice, and produces a
polished self-contained HTML report.  No server required — open the report file
directly in any browser.

---

## Quick Start

```bash
# 1. Export your CA policies from Graph
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
  > policies.json

# 2. Run the tool
python analyze.py --input policies.json --tenant "Contoso"

# The report opens automatically in your default browser.
# Output: output/ca-report-YYYYMMDD-HHMMSS.html
```

---

## Requirements

Python 3.10+ — **no pip dependencies**.  Everything is stdlib + inline HTML/JS.

---

## CLI Reference

```
python analyze.py --input FILE [--tenant NAME] [--config FILE] [--output-dir DIR] [--no-open]

  --input        Path to Graph JSON export (required)
  --tenant       Tenant name for report branding
  --config       Rule config file (default: config.json)
  --output-dir   Where to write reports (default: ./output)
  --no-open      Skip auto-opening the browser
```

### Examples

```bash
# Basic
python analyze.py --input policies.json

# Branded report
python analyze.py --input policies.json --tenant "Nationwide"

# Custom rule config, no auto-open
python analyze.py --input policies.json --config custom.json --no-open

# Save to a specific output folder
python analyze.py --input policies.json --output-dir /tmp/reports
```

---

## Getting the Policy JSON

### Azure CLI

```bash
az login
az rest --method GET \
  --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' \
  > policies.json
```

### PowerShell (Microsoft.Graph)

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 > policies.json
```

### Graph Explorer

1. Navigate to `https://developer.microsoft.com/graph/graph-explorer`
2. Sign in with appropriate permissions (`Policy.Read.All`)
3. `GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`
4. Copy the response JSON and save as `policies.json`

---

## Report Sections

| Tab | Contents |
|-----|----------|
| **Policy Inventory** | Searchable, sortable table of all policies. Click any row to expand full detail. Filter by state (Enabled / Disabled / Report-Only). |
| **Gap Analysis** | Gap cards grouped by severity (Critical → Low), each with description, recommendation, and effort estimate. Export to CSV button. |
| **Visualizations** | Policy state donut · Gap severity bar · Control adoption chart · Scope breakdown chart. All rendered with vanilla Canvas — no external deps. |

---

## Gap Rules

| Rule | Severity | Category |
|------|----------|----------|
| No MFA policy covering all users + all apps | Critical | MFA |
| No MFA policy targeting admin roles | Critical | MFA |
| Legacy authentication not blocked | Critical | Legacy Auth |
| No sign-in risk policy | High | Risk |
| No user risk policy | High | Risk |
| No device compliance requirement | High | Device |
| No guest/external user policy | High | Guest Access |
| No break-glass exclusion group detected | High | Break Glass |
| All-Users policies with no exclusions | Medium | Break Glass |
| Policies stuck in report-only mode | Medium | Policy Hygiene |
| No session controls configured | Medium | Session |
| Enabled policies applying no controls | Medium | Policy Hygiene |
| Disabled policies (stale audit) | Low | Policy Hygiene |
| Broad policy overlap | Low | Policy Hygiene |

---

## Tuning Rules (`config.json`)

Disable a rule or override its severity without touching code:

```json
{
  "rules": {
    "SIGN_IN_RISK":  { "enabled": false },
    "DEVICE_COMPLIANCE": { "severity": "Critical" }
  }
}
```

Set `"licensed_for_p2": false` under `"org"` to suppress P2-dependent rule
recommendations.

---

## File Structure

```
.
├── analyze.py          Main entry point (CLI)
├── parser.py           Graph JSON ingestion + normalisation
├── gap_engine.py       Gap analysis rules
├── recommender.py      Gap sorting and grouping
├── visualizer.py       Self-contained HTML report builder
├── models.py           Data classes
├── config.json         Tunable rule configuration
├── output/             Generated reports land here
└── helpers/
    └── Get-CAPolicyNames.ps1   Phase 2: GUID → display name resolver
```

---

## Phase 2 Roadmap

| Feature | Description |
|---------|-------------|
| **GUID resolution** | `helpers/Get-CAPolicyNames.ps1` resolves user/group/app GUIDs to display names. Drop `resolved-names.json` alongside the policy export and the tool picks it up automatically. |
| **Live Graph mode** | Swap file input for a live Graph token — pull policies in real time without an export step. |
| **Delta / drift mode** | Compare two JSON exports and surface what changed between runs. |
| **Scheduled mode** | Run on a schedule; email the report if new Critical gaps appear. |

---

## Troubleshooting

**`Error: Unexpected JSON structure`**
The JSON must be a list of policy objects or a Graph response with a `value` array.
Re-export using one of the methods above.

**Report shows GUIDs instead of display names**
Run `helpers/Get-CAPolicyNames.ps1` to generate `resolved-names.json`.
Place it in the same directory as your policy export file.

**Charts are blank**
Charts render only when you click the **Visualizations** tab (lazy init).
If still blank, check that JavaScript is enabled in your browser.
