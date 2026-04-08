"""Build the self-contained HTML report."""

import json
from datetime import datetime
from typing import Dict, List

from models import Gap, Policy, Stats


class ReportBuilder:

    def __init__(self, tenant_name: str = ""):
        self.tenant = tenant_name or "Unknown Tenant"

    def build(self, policies: List[Policy], gaps: List[Gap], stats: Stats) -> str:
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            _HTML
            .replace("__DATA_POLICIES__",  json.dumps(self._policy_rows(policies),     separators=(",", ":")))
            .replace("__DATA_GAPS__",       json.dumps(self._gap_rows(gaps),            separators=(",", ":")))
            .replace("__DATA_STATS__",      json.dumps(self._stat_dict(stats),          separators=(",", ":")))
            .replace("__DATA_CONDITIONS__", json.dumps(self._condition_stats(policies), separators=(",", ":")))
            .replace("__DATA_TENANT__",     json.dumps(self.tenant))
            .replace("__DATA_GENERATED__",  json.dumps(generated))
        )

    # ── Serialisers ───────────────────────────────────────────────────────

    def _stat_dict(self, s: Stats) -> Dict:
        return {
            "total": s.total, "enabled": s.enabled,
            "disabled": s.disabled, "reportOnly": s.report_only,
            "critical": s.critical_gaps, "high": s.high_gaps,
            "medium": s.medium_gaps, "low": s.low_gaps,
            "posture": s.posture, "exportDate": s.export_date or "Unknown",
        }

    def _policy_rows(self, policies: List[Policy]) -> List[Dict]:
        return [{
            "id":           p.id,
            "name":         p.display_name,
            "state":        p.state_display,
            "stateRaw":     p.state,
            "userScope":    self._user_scope(p),
            "appScope":     self._app_scope(p),
            "conditions":   self._conditions_str(p),
            "grant":        self._grant_str(p),
            "session":      self._session_str(p),
            "modified":     (p.modified_datetime or "")[:10],
            "created":      (p.created_datetime  or "")[:10],
            "hasMFA":       p.requires_mfa,
            "hasDevice":    p.requires_compliant_device or p.requires_domain_joined,
            "blocks":       p.blocks_access,
            "hasSignInRisk": bool(p.conditions.sign_in_risk_levels),
            "hasUserRisk":   bool(p.conditions.user_risk_levels),
            "hasLocations":  bool(p.conditions.locations_include),
            "hasPlatforms":  bool(p.conditions.platforms_include),
        } for p in policies]

    def _gap_rows(self, gaps: List[Gap]) -> List[Dict]:
        return [{
            "ruleId":         g.rule_id,
            "severity":       g.severity,
            "category":       g.category,
            "title":          g.title,
            "description":    g.description,
            "affected":       g.affected_policies,
            "recommendation": g.recommendation,
            "effort":         g.effort,
        } for g in gaps]

    def _condition_stats(self, policies: List[Policy]) -> Dict[str, int]:
        en = [p for p in policies if p.is_enabled]
        return {
            "MFA":          sum(1 for p in en if p.requires_mfa),
            "Block":        sum(1 for p in en if p.blocks_access),
            "Device":       sum(1 for p in en if p.requires_compliant_device or p.requires_domain_joined),
            "Sign-in Risk": sum(1 for p in en if p.conditions.sign_in_risk_levels),
            "User Risk":    sum(1 for p in en if p.conditions.user_risk_levels),
            "Location":     sum(1 for p in en if p.conditions.locations_include),
            "Platform":     sum(1 for p in en if p.conditions.platforms_include),
            "Session Ctrl": sum(1 for p in en if p.session_controls),
        }

    # ── Field formatters ──────────────────────────────────────────────────

    def _user_scope(self, p: Policy) -> str:
        c = p.conditions
        if "All" in c.users_include:                   return "All Users"
        if "GuestsOrExternalUsers" in c.users_include: return "Guests/External"
        if "None" in c.users_include:                  return "None"
        parts = []
        if c.users_include:  parts.append(f"{len(c.users_include)} user(s)")
        if c.groups_include: parts.append(f"{len(c.groups_include)} group(s)")
        if c.roles_include:  parts.append(f"{len(c.roles_include)} role(s)")
        return ", ".join(parts) or "None"

    def _app_scope(self, p: Policy) -> str:
        ai = p.conditions.apps_include
        if "All" in ai:            return "All Cloud Apps"
        if not ai or "None" in ai: return "None"
        return f"{len(ai)} app(s)"

    def _conditions_str(self, p: Policy) -> str:
        c, parts = p.conditions, []
        if c.client_app_types:    parts.append("Client: " + ", ".join(c.client_app_types))
        if c.platforms_include:   parts.append("Platforms: " + ", ".join(c.platforms_include))
        if c.sign_in_risk_levels: parts.append("SignIn Risk: " + ", ".join(c.sign_in_risk_levels))
        if c.user_risk_levels:    parts.append("User Risk: " + ", ".join(c.user_risk_levels))
        if c.locations_include:   parts.append(f"Locations: {len(c.locations_include)}")
        return " \u00b7 ".join(parts)

    def _grant_str(self, p: Policy) -> str:
        if not p.grant_controls: return ""
        _lbl = {
            "mfa": "MFA", "compliantDevice": "Compliant Device",
            "domainJoinedDevice": "Hybrid Join", "block": "Block",
            "approvedApplication": "Approved App", "compliantApplication": "Compliant App",
        }
        ctrl = [_lbl.get(c, c) for c in p.grant_controls.built_in_controls]
        op   = p.grant_controls.operator or "OR"
        return (" " + op + " ").join(ctrl) if ctrl else ""

    def _session_str(self, p: Policy) -> str:
        if not p.session_controls: return ""
        sc, parts = p.session_controls, []
        if sc.sign_in_frequency_value is not None:
            parts.append(f"SIF: {sc.sign_in_frequency_value} {sc.sign_in_frequency_unit or ''}")
        if sc.persistent_browser_mode:           parts.append(f"Browser: {sc.persistent_browser_mode}")
        if sc.application_enforced_restrictions: parts.append("App Restrictions")
        if sc.cloud_app_security_type:           parts.append(f"MCAS: {sc.cloud_app_security_type}")
        return " \u00b7 ".join(parts)


# ── HTML template ─────────────────────────────────────────────────────────────
# All __DATA_XXX__ tokens are replaced by build() with JSON-serialised data.

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CA Policy Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1e293b;font-size:14px;line-height:1.5}
.site-hdr{background:#0f1b2d;color:#fff}
.hdr-inner{max-width:1400px;margin:0 auto;padding:18px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.site-hdr h1{font-size:20px;font-weight:600;margin-bottom:3px}
#rptMeta{font-size:12px;opacity:.65}
.container{max-width:1400px;margin:0 auto;padding:24px}
.sum-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.stat-card{background:#fff;border-radius:10px;padding:20px 22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.sc-val{font-size:42px;font-weight:700;line-height:1}
.sc-lbl{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#64748b;margin-top:5px}
.c-green{color:#16a34a}.c-gray{color:#6b7280}.c-blue{color:#3b82f6}
.gap-bar-row{background:#fff;border-radius:10px;padding:13px 20px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.08);display:flex;align-items:center;flex-wrap:wrap;gap:6px}
.no-gap-bar{background:#f0fdf4;border:1px solid #bbf7d0;color:#15803d;border-radius:10px;padding:13px 20px;margin-bottom:14px;font-weight:500}
.tab-bar{display:flex;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:14px}
.tab-btn{flex:1;padding:13px 20px;border:none;background:none;cursor:pointer;font-size:14px;font-weight:500;color:#64748b;border-bottom:3px solid transparent;transition:all .15s}
.tab-btn:hover{background:#f8fafc;color:#1e293b}
.tab-btn.active{color:#0f1b2d;border-bottom-color:#0f1b2d;background:#f8fafc}
.tab-ct{font-size:12px;background:#e2e8f0;color:#475569;padding:1px 7px;border-radius:10px;margin-left:6px;font-weight:600}
.card{background:#fff;border-radius:10px;padding:22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.tbl-ctrl{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.srch{padding:8px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;width:270px;outline:none;transition:border .15s;color:#1e293b}
.srch:focus{border-color:#3b82f6}
.filt-grp{display:flex;gap:5px;flex-wrap:wrap}
.fbtn{padding:7px 13px;border:1px solid #e2e8f0;background:#fff;border-radius:7px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all .15s}
.fbtn:hover{border-color:#cbd5e1;background:#f8fafc}
.fbtn.on{background:#0f1b2d;color:#fff;border-color:#0f1b2d}
.tbl-ct{font-size:12px;color:#94a3b8;margin-left:auto;white-space:nowrap}
.tbl-wrap{border-radius:8px;border:1px solid #e2e8f0;overflow:auto}
table{width:100%;border-collapse:collapse}
th{background:#f8fafc;padding:10px 14px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#64748b;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid #e2e8f0}
th:hover{background:#f1f5f9;color:#1e293b}
td{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle;font-size:13px}
tr.pr:last-of-type td{border-bottom:none}
tr.pr:hover>td{background:#fafafa;cursor:pointer}
tr.tr-off>td{opacity:.5}
tr.tr-ro>td:first-child{border-left:3px solid #3b82f6}
tr.pr>td:first-child{border-left:3px solid transparent}
.pol-nm{font-weight:500}
.xi{font-size:9px;color:#94a3b8;margin-left:6px;transition:color .15s}
.tc{color:#64748b;font-size:12px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td{color:#94a3b8;white-space:nowrap;font-size:12px}
.si{font-size:11px;color:#94a3b8;margin-left:2px}
.no-rows{text-align:center;padding:40px;color:#94a3b8;font-style:italic}
tr.det-row>td{background:#f8fafc;border-top:1px solid #e2e8f0;padding:0}
.det-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:16px 18px}
.di label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;display:block;margin-bottom:3px}
.di span{font-size:13px;color:#475569;word-break:break-word}
.di.wide{grid-column:1/-1}
.mono{font-family:monospace;font-size:11px!important;color:#64748b}
.bdg{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600}
.bdg-on{background:#dcfce7;color:#15803d}
.bdg-off{background:#f1f5f9;color:#6b7280}
.bdg-ro{background:#dbeafe;color:#1d4ed8}
.gaps-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.section-h{font-size:18px;font-weight:600}
.btn-export{padding:8px 16px;border:none;border-radius:8px;background:#16a34a;color:#fff;font-size:13px;font-weight:500;cursor:pointer}
.btn-export:hover{background:#15803d}
.gap-grp{margin-bottom:26px}
.gap-grp-hdr{font-size:16px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:10px}
.gap-grp-ct{font-size:13px;font-weight:500;color:#64748b}
.gap-card{border-left:4px solid;border-radius:8px;padding:16px 18px;margin-bottom:10px}
.gap-card-hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px;flex-wrap:wrap}
.gap-ttl{font-size:15px;font-weight:600;flex:1;min-width:0}
.cat-bdg{background:#e2e8f0;color:#475569;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap}
.gap-desc{font-size:13px;color:#475569;margin-bottom:12px;line-height:1.6}
.gap-aff{margin-bottom:12px}
.gap-aff-lbl{font-size:10px;font-weight:700;text-transform:uppercase;color:#94a3b8;margin-bottom:5px}
.ptag{display:inline-block;background:#e2e8f0;color:#475569;padding:2px 8px;border-radius:4px;font-size:11px;margin:2px}
.gap-rec{background:rgba(255,255,255,.75);border-radius:6px;padding:11px 14px;font-size:13px;margin-bottom:10px;line-height:1.6;border:1px solid rgba(0,0,0,.06)}
.gap-rec-lbl{font-size:10px;font-weight:700;text-transform:uppercase;color:#94a3b8;margin-bottom:5px}
.gap-meta{font-size:11px;color:#94a3b8}
.rule-id{background:#e2e8f0;padding:1px 6px;border-radius:3px;color:#475569;font-family:monospace;font-size:11px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.chart-card{background:#fff;border-radius:10px;padding:20px 22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.chart-ttl{font-size:14px;font-weight:600;color:#1e293b;margin-bottom:14px}
canvas{display:block;max-width:100%}
@media(max-width:900px){.sum-row{grid-template-columns:repeat(2,1fr)}.chart-grid{grid-template-columns:1fr}.det-grid{grid-template-columns:1fr 1fr}}
@media(max-width:600px){.sum-row{grid-template-columns:1fr}.tbl-ctrl{flex-direction:column;align-items:stretch}.srch{width:100%}}
</style>
</head>
<body>

<header class="site-hdr">
  <div class="hdr-inner">
    <div>
      <h1 id="rptTitle">CA Policy Report</h1>
      <p id="rptMeta"></p>
    </div>
    <div id="posturePill"></div>
  </div>
</header>

<div class="container">

  <div class="sum-row">
    <div class="stat-card"><div class="sc-val" id="sv-total"></div><div class="sc-lbl">Total Policies</div></div>
    <div class="stat-card"><div class="sc-val c-green" id="sv-enabled"></div><div class="sc-lbl">Enabled</div></div>
    <div class="stat-card"><div class="sc-val c-gray" id="sv-disabled"></div><div class="sc-lbl">Disabled</div></div>
    <div class="stat-card"><div class="sc-val c-blue" id="sv-ro"></div><div class="sc-lbl">Report-Only</div></div>
  </div>

  <div id="gapBar"></div>

  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab('inventory',this)">Policy Inventory <span id="inv-ct" class="tab-ct"></span></button>
    <button class="tab-btn" onclick="switchTab('gaps',this)">Gap Analysis <span id="gap-ct" class="tab-ct"></span></button>
    <button class="tab-btn" onclick="switchTab('charts',this)">Visualizations</button>
  </div>

  <div id="panel-inventory">
    <div class="card">
      <div class="tbl-ctrl">
        <input type="text" class="srch" placeholder="Search policies..." oninput="doSearch(this.value)">
        <div class="filt-grp">
          <button class="fbtn on" onclick="doFilter('all',this)">All</button>
          <button class="fbtn" onclick="doFilter('Enabled',this)">Enabled</button>
          <button class="fbtn" onclick="doFilter('Disabled',this)">Disabled</button>
          <button class="fbtn" onclick="doFilter('Report Only',this)">Report-Only</button>
        </div>
        <span id="tbl-ct" class="tbl-ct"></span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th onclick="doSort('name')">Policy Name <span id="si-name" class="si">&#8645;</span></th>
            <th onclick="doSort('state')">State <span id="si-state" class="si">&#8645;</span></th>
            <th onclick="doSort('userScope')">User Scope <span id="si-userScope" class="si">&#8645;</span></th>
            <th onclick="doSort('appScope')">App Scope <span id="si-appScope" class="si">&#8645;</span></th>
            <th>Conditions</th>
            <th>Grant Controls</th>
            <th onclick="doSort('modified')">Modified <span id="si-modified" class="si">&#8645;</span></th>
          </tr></thead>
          <tbody id="polBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="panel-gaps" style="display:none">
    <div class="card">
      <div class="gaps-hdr">
        <h2 class="section-h">Gap Analysis Results</h2>
        <button class="btn-export" onclick="exportCSV()">&#8595; Export CSV</button>
      </div>
      <div id="gapsContent"></div>
    </div>
  </div>

  <div id="panel-charts" style="display:none">
    <div class="chart-grid">
      <div class="chart-card"><div class="chart-ttl">Policy State Distribution</div><canvas id="cDonut" width="460" height="230"></canvas></div>
      <div class="chart-card"><div class="chart-ttl">Gap Severity Breakdown</div><canvas id="cGapBar" width="460" height="230"></canvas></div>
      <div class="chart-card"><div class="chart-ttl">Control &amp; Condition Adoption (enabled policies)</div><canvas id="cCond" width="460" height="270"></canvas></div>
      <div class="chart-card"><div class="chart-ttl">Policy Scope Breakdown (enabled policies)</div><canvas id="cScope" width="460" height="270"></canvas></div>
    </div>
  </div>

</div>

<script>
const POLICIES   = __DATA_POLICIES__;
const GAPS       = __DATA_GAPS__;
const STATS      = __DATA_STATS__;
const CONDITIONS = __DATA_CONDITIONS__;
const TENANT     = __DATA_TENANT__;
const GENERATED  = __DATA_GENERATED__;

var _filt='all', _sort='name', _dir=1, _q='';

document.addEventListener('DOMContentLoaded', function() {
  document.getElementById('rptTitle').textContent = TENANT + ' \u2014 CA Policy Report';
  document.getElementById('rptMeta').textContent  =
    'Generated: ' + GENERATED + '  \u00b7  Last policy modification: ' + STATS.exportDate;

  var pc = {Red:'#dc2626',Amber:'#d97706',Green:'#16a34a'}[STATS.posture] || '#64748b';
  document.getElementById('posturePill').innerHTML =
    '<span style="background:'+pc+';color:#fff;padding:7px 18px;border-radius:20px;font-weight:700;font-size:14px;letter-spacing:.5px">'+
    STATS.posture.toUpperCase()+' POSTURE</span>';

  document.getElementById('sv-total').textContent    = STATS.total;
  document.getElementById('sv-enabled').textContent  = STATS.enabled;
  document.getElementById('sv-disabled').textContent = STATS.disabled;
  document.getElementById('sv-ro').textContent       = STATS.reportOnly;

  renderGapBar();
  document.getElementById('inv-ct').textContent = POLICIES.length;
  if (GAPS.length) document.getElementById('gap-ct').textContent = GAPS.length;
  renderTable();
  renderGaps();
});

function renderGapBar() {
  var el   = document.getElementById('gapBar');
  var segs = [
    {l:'Critical',v:STATS.critical,c:'#dc2626'},
    {l:'High',    v:STATS.high,    c:'#ea580c'},
    {l:'Medium',  v:STATS.medium,  c:'#ca8a04'},
    {l:'Low',     v:STATS.low,     c:'#3b82f6'}
  ].filter(function(s){return s.v>0;});
  if (!segs.length) {
    el.innerHTML='<div class="no-gap-bar">\u2713 No gaps detected \u2014 strong posture!</div>';
    return;
  }
  var pills = segs.map(function(s){
    return '<span style="background:'+s.c+';color:#fff;padding:4px 14px;border-radius:14px;font-size:13px;font-weight:600">'+s.v+' '+s.l+'</span>';
  }).join(' ');
  el.innerHTML='<div class="gap-bar-row"><span style="color:#64748b;font-size:13px;font-weight:500;margin-right:4px">Gaps found:</span>'+pills+'</div>';
}

function switchTab(name, btn) {
  ['inventory','gaps','charts'].forEach(function(t){
    var p=document.getElementById('panel-'+t);
    if(p) p.style.display = (t===name)?'block':'none';
  });
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  if (name==='charts') setTimeout(renderCharts, 60);
}

function doFilter(state, btn) {
  _filt=state;
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('on');});
  btn.classList.add('on');
  renderTable();
}
function doSearch(q) { _q=q.toLowerCase(); renderTable(); }
function doSort(col) {
  if (_sort===col) _dir*=-1; else { _sort=col; _dir=1; }
  document.querySelectorAll('.si').forEach(function(s){s.innerHTML='&#8645;';});
  var el=document.getElementById('si-'+col);
  if(el) el.textContent=(_dir===1)?'\u2191':'\u2193';
  renderTable();
}

function renderTable() {
  var rows=POLICIES.slice();
  if (_filt!=='all') rows=rows.filter(function(p){return p.state===_filt;});
  if (_q) rows=rows.filter(function(p){
    return [p.name,p.userScope,p.appScope,p.conditions,p.grant]
      .some(function(f){return (f||'').toLowerCase().indexOf(_q)!==-1;});
  });
  rows.sort(function(a,b){
    var av=(a[_sort]||'').toLowerCase(), bv=(b[_sort]||'').toLowerCase();
    return av<bv?-_dir:av>bv?_dir:0;
  });
  document.getElementById('tbl-ct').textContent=rows.length+' / '+POLICIES.length+' policies';

  var BADGE={
    'Enabled':    '<span class="bdg bdg-on">Enabled</span>',
    'Disabled':   '<span class="bdg bdg-off">Disabled</span>',
    'Report Only':'<span class="bdg bdg-ro">Report-Only</span>'
  };
  var html=rows.map(function(p){
    var rc=p.stateRaw==='disabled'?'tr-off':p.stateRaw==='enabledForReportingButNotEnforced'?'tr-ro':'';
    var cond=(p.conditions||'');
    if(cond.length>58) cond=cond.slice(0,58)+'\u2026';
    return '<tr class="pr '+rc+'" onclick="toggleRow(\''+p.id+'\')">'
      +'<td><span class="pol-nm">'+esc(p.name)+'</span><span class="xi" id="xi-'+p.id+'">\u25b6</span></td>'
      +'<td>'+(BADGE[p.state]||esc(p.state))+'</td>'
      +'<td>'+esc(p.userScope)+'</td>'
      +'<td>'+esc(p.appScope)+'</td>'
      +'<td class="tc">'+esc(cond||'\u2014')+'</td>'
      +'<td>'+esc(p.grant||'\u2014')+'</td>'
      +'<td class="td">'+esc(p.modified||'\u2014')+'</td>'
      +'</tr>'
      +'<tr id="dr-'+p.id+'" class="det-row" style="display:none"><td colspan="7">'
      +'<div class="det-grid">'
      +'<div class="di"><label>Policy ID</label><span class="mono">'+esc(p.id)+'</span></div>'
      +'<div class="di"><label>Created</label><span>'+esc(p.created||'\u2014')+'</span></div>'
      +'<div class="di"><label>Last Modified</label><span>'+esc(p.modified||'\u2014')+'</span></div>'
      +'<div class="di"><label>User Scope</label><span>'+esc(p.userScope)+'</span></div>'
      +'<div class="di"><label>App Scope</label><span>'+esc(p.appScope)+'</span></div>'
      +'<div class="di"><label>Session Controls</label><span>'+esc(p.session||'\u2014')+'</span></div>'
      +'<div class="di wide"><label>Conditions</label><span>'+esc(p.conditions||'\u2014')+'</span></div>'
      +'<div class="di wide"><label>Grant Controls</label><span>'+esc(p.grant||'\u2014')+'</span></div>'
      +'</div></td></tr>';
  }).join('');
  document.getElementById('polBody').innerHTML=html||
    '<tr><td colspan="7" class="no-rows">No policies match the current filter.</td></tr>';
}

function toggleRow(id) {
  var dr=document.getElementById('dr-'+id), xi=document.getElementById('xi-'+id);
  if(!dr) return;
  var open=dr.style.display!=='none';
  dr.style.display=open?'none':'table-row';
  if(xi){xi.textContent=open?'\u25b6':'\u25bc';xi.style.color=open?'':'#3b82f6';}
}

function renderGaps() {
  if(!GAPS.length){
    document.getElementById('gapsContent').innerHTML=
      '<div style="text-align:center;padding:60px 20px;color:#64748b;font-size:15px">No gaps detected.</div>';
    return;
  }
  var SC={Critical:'#dc2626',High:'#ea580c',Medium:'#ca8a04',Low:'#3b82f6'};
  var SB={Critical:'#fef2f2',High:'#fff7ed',Medium:'#fefce8',Low:'#eff6ff'};
  var EL={Low:'Low effort',Medium:'Medium effort',High:'High effort'};
  var EC={Low:'#16a34a',Medium:'#ca8a04',High:'#dc2626'};
  var groups={Critical:[],High:[],Medium:[],Low:[]};
  GAPS.forEach(function(g){(groups[g.severity]=groups[g.severity]||[]).push(g);});
  var html='';
  ['Critical','High','Medium','Low'].forEach(function(sev){
    var gs=groups[sev]; if(!gs||!gs.length) return;
    var sc=SC[sev], sb=SB[sev];
    html+='<div class="gap-grp"><div class="gap-grp-hdr" style="color:'+sc+'">'+sev
      +' <span class="gap-grp-ct">'+gs.length+' finding'+(gs.length>1?'s':'')+'</span></div>';
    gs.forEach(function(g){
      var aff='';
      if(g.affected&&g.affected.length){
        aff='<div class="gap-aff"><div class="gap-aff-lbl">Affected policies</div>'
          +g.affected.map(function(n){return '<span class="ptag">'+esc(n)+'</span>';}).join('')+'</div>';
      }
      html+='<div class="gap-card" style="border-left-color:'+sc+';background:'+sb+'">'
        +'<div class="gap-card-hdr">'
        +'<span class="gap-ttl">'+esc(g.title)+'</span>'
        +(g.category?'<span class="cat-bdg">'+esc(g.category)+'</span>':'')
        +'<span style="font-size:11px;color:'+(EC[g.effort]||'#64748b')+';font-weight:600;white-space:nowrap">'
        +esc(EL[g.effort]||g.effort)+'</span></div>'
        +'<p class="gap-desc">'+esc(g.description)+'</p>'
        +aff
        +'<div class="gap-rec"><div class="gap-rec-lbl">Recommendation</div>'+esc(g.recommendation)+'</div>'
        +'<div class="gap-meta"><span class="rule-id">'+esc(g.ruleId)+'</span></div>'
        +'</div>';
    });
    html+='</div>';
  });
  document.getElementById('gapsContent').innerHTML=html;
}

function exportCSV() {
  var hdr=['Severity','Category','Title','Description','AffectedPolicies','Recommendation','Effort'];
  var rows=[hdr.join(',')];
  GAPS.forEach(function(g){
    rows.push([g.severity,g.category,g.title,g.description,
      (g.affected||[]).join(' | '),g.recommendation,g.effort]
      .map(function(v){return '"'+(v||'').replace(/"/g,'""')+'"';}).join(','));
  });
  var a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,%EF%BB%BF'+encodeURIComponent(rows.join('\r\n'));
  a.download='ca-gaps.csv'; a.click();
}

var _chartsDrawn=false;
function renderCharts() {
  if(_chartsDrawn) return; _chartsDrawn=true;
  drawDonut('cDonut',[
    {l:'Enabled',    v:STATS.enabled,   c:'#16a34a'},
    {l:'Disabled',   v:STATS.disabled,  c:'#9ca3af'},
    {l:'Report-Only',v:STATS.reportOnly,c:'#3b82f6'}
  ]);
  drawBar('cGapBar',
    ['Critical','High','Medium','Low'],
    [STATS.critical,STATS.high,STATS.medium,STATS.low],
    ['#dc2626','#ea580c','#ca8a04','#3b82f6']
  );
  drawHBar('cCond',Object.keys(CONDITIONS),Object.values(CONDITIONS),'#3b82f6');
  var en=POLICIES.filter(function(p){return p.stateRaw==='enabled';});
  drawHBar('cScope',
    ['All Users','Guests/Ext.','All Apps','Has MFA','Has Device','Sign-in Risk'],
    [
      en.filter(function(p){return p.userScope==='All Users';}).length,
      en.filter(function(p){return p.userScope==='Guests/External';}).length,
      en.filter(function(p){return p.appScope==='All Cloud Apps';}).length,
      en.filter(function(p){return p.hasMFA;}).length,
      en.filter(function(p){return p.hasDevice;}).length,
      en.filter(function(p){return p.hasSignInRisk;}).length
    ],
    '#16a34a'
  );
}

function drawDonut(id,segs){
  var canvas=document.getElementById(id); if(!canvas) return;
  var ctx=canvas.getContext('2d');
  var W=canvas.width,H=canvas.height;
  var total=segs.reduce(function(s,x){return s+x.v;},0);
  ctx.clearRect(0,0,W,H);
  if(!total){ctx.fillStyle='#e2e8f0';ctx.fillRect(0,0,W,H);return;}
  var cx=W*0.42,cy=H/2,R=Math.min(cx,cy)*0.86,r=R*0.52,a=-Math.PI/2;
  segs.forEach(function(s){
    var sw=(s.v/total)*2*Math.PI;
    ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,R,a,a+sw);ctx.closePath();
    ctx.fillStyle=s.c;ctx.fill();a+=sw;
  });
  ctx.beginPath();ctx.arc(cx,cy,r,0,2*Math.PI);ctx.fillStyle='#fff';ctx.fill();
  ctx.fillStyle='#1e293b';ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.font='bold 24px -apple-system,sans-serif';ctx.fillText(total,cx,cy-9);
  ctx.font='11px sans-serif';ctx.fillStyle='#64748b';ctx.fillText('policies',cx,cy+12);
  var ly=H/2-(segs.length*22)/2,lx=W*0.76;
  segs.forEach(function(s){
    ctx.fillStyle=s.c;ctx.fillRect(lx,ly,12,12);
    ctx.fillStyle='#1e293b';ctx.font='12px sans-serif';
    ctx.textAlign='left';ctx.textBaseline='top';
    ctx.fillText(s.l+' ('+s.v+')',lx+16,ly);ly+=22;
  });
}

function drawBar(id,labels,vals,colors){
  var canvas=document.getElementById(id);if(!canvas)return;
  var ctx=canvas.getContext('2d');
  var W=canvas.width,H=canvas.height,pt=28,pr=16,pb=40,pl=36;
  var cW=W-pl-pr,cH=H-pt-pb;
  var max=vals.reduce(function(m,v){return Math.max(m,v);},1);
  var gap=cW/labels.length,bW=gap*0.6;
  ctx.clearRect(0,0,W,H);
  [0.25,0.5,0.75,1].forEach(function(f){
    var y=pt+cH*(1-f);
    ctx.strokeStyle='#f1f5f9';ctx.lineWidth=1;
    ctx.beginPath();ctx.moveTo(pl,y);ctx.lineTo(W-pr,y);ctx.stroke();
    ctx.fillStyle='#94a3b8';ctx.font='10px sans-serif';
    ctx.textAlign='right';ctx.textBaseline='middle';
    ctx.fillText(Math.round(max*f),pl-4,y);
  });
  labels.forEach(function(lbl,i){
    var x=pl+i*gap+(gap-bW)/2,bH=(vals[i]/max)*cH,y=pt+cH-bH;
    ctx.fillStyle=colors[i];ctx.fillRect(x,y,bW,bH);
    if(vals[i]>0){
      ctx.fillStyle='#1e293b';ctx.font='bold 13px sans-serif';
      ctx.textAlign='center';ctx.textBaseline='bottom';
      ctx.fillText(vals[i],x+bW/2,y-2);
    }
    ctx.fillStyle='#64748b';ctx.font='12px sans-serif';
    ctx.textBaseline='top';ctx.fillText(lbl,x+bW/2,pt+cH+6);
  });
}

function drawHBar(id,labels,vals,color){
  var canvas=document.getElementById(id);if(!canvas)return;
  var ctx=canvas.getContext('2d');
  var W=canvas.width,H=canvas.height;
  var padL=110,padR=48,padT=12,padB=12;
  var cW=W-padL-padR,cH=H-padT-padB;
  var max=vals.reduce(function(m,v){return Math.max(m,v);},1);
  var n=labels.length,rowH=cH/n,bH=rowH*0.52;
  ctx.clearRect(0,0,W,H);
  labels.forEach(function(lbl,i){
    var y=padT+i*rowH+(rowH-bH)/2,barW=(vals[i]/max)*cW,mid=padT+i*rowH+rowH/2;
    ctx.fillStyle='#64748b';ctx.font='12px -apple-system,sans-serif';
    ctx.textAlign='right';ctx.textBaseline='middle';ctx.fillText(lbl,padL-8,mid);
    ctx.fillStyle='#f1f5f9';ctx.fillRect(padL,y,cW,bH);
    ctx.fillStyle=color;if(barW>0)ctx.fillRect(padL,y,barW,bH);
    if(vals[i]>0){
      ctx.fillStyle='#1e293b';ctx.font='11px sans-serif';
      ctx.textAlign='left';ctx.textBaseline='middle';
      ctx.fillText(vals[i],padL+barW+5,mid);
    }
  });
}

function esc(s){
  if(s==null)return'';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


_HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>CA Policy Report</title>\n<style>\n*{box-sizing:border-box;margin:0;padding:0}\nhtml,body{font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;background:#f0f2f5;color:#1e293b;font-size:14px;line-height:1.5}\n.site-hdr{background:#0f1b2d;color:#fff}\n.hdr-inner{max-width:1400px;margin:0 auto;padding:18px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}\n.site-hdr h1{font-size:20px;font-weight:600;margin-bottom:3px}\n#rptMeta{font-size:12px;opacity:.65}\n.container{max-width:1400px;margin:0 auto;padding:24px}\n.sum-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}\n.stat-card{background:#fff;border-radius:10px;padding:20px 22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}\n.sc-val{font-size:42px;font-weight:700;line-height:1}\n.sc-lbl{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#64748b;margin-top:5px}\n.c-navy{color:#0f1b2d}.c-green{color:#16a34a}.c-gray{color:#6b7280}.c-blue{color:#3b82f6}\n#gapBar{margin-bottom:14px}\n.gap-bar-row{background:#fff;border-radius:10px;padding:13px 20px;box-shadow:0 1px 4px rgba(0,0,0,.08);display:flex;align-items:center;flex-wrap:wrap;gap:6px}\n.no-gaps-bar{background:#f0fdf4;border:1px solid #bbf7d0;color:#15803d;border-radius:10px;padding:13px 20px;font-weight:500;font-size:14px}\n.tab-bar{display:flex;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:14px}\n.tab-btn{flex:1;padding:13px 20px;border:none;background:none;cursor:pointer;font-size:14px;font-weight:500;color:#64748b;border-bottom:3px solid transparent;transition:all .15s}\n.tab-btn:hover{background:#f8fafc;color:#1e293b}\n.tab-btn.active{color:#0f1b2d;border-bottom-color:#0f1b2d;background:#f8fafc}\n.tab-ct{font-size:12px;background:#e2e8f0;color:#475569;padding:1px 7px;border-radius:10px;margin-left:6px;font-weight:600}\n.card{background:#fff;border-radius:10px;padding:22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}\n.tbl-ctrl{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}\n.srch{padding:8px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;width:270px;outline:none;transition:border .15s}\n.srch:focus{border-color:#3b82f6}\n.filt-grp{display:flex;gap:5px;flex-wrap:wrap}\n.fbtn{padding:7px 13px;border:1px solid #e2e8f0;background:#fff;border-radius:7px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all .15s}\n.fbtn:hover{border-color:#cbd5e1;background:#f8fafc}\n.fbtn.on{background:#0f1b2d;color:#fff;border-color:#0f1b2d}\n.tbl-ct{font-size:12px;color:#94a3b8;margin-left:auto;white-space:nowrap}\n.tbl-wrap{border-radius:8px;border:1px solid #e2e8f0;overflow:auto}\ntable{width:100%;border-collapse:collapse}\nth{background:#f8fafc;padding:10px 14px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#64748b;cursor:pointer;user-select:none;white-space:nowrap;border-bottom:1px solid #e2e8f0}\nth:hover{background:#f1f5f9;color:#1e293b}\ntd{padding:10px 14px;border-bottom:1px solid #f1f5f9;vertical-align:middle;font-size:13px}\ntr:last-child>td{border-bottom:none}\ntr.pr:hover>td{background:#fafafa;cursor:pointer}\ntr.tr-off>td{opacity:.5}\ntr.tr-ro>td:first-child{border-left:3px solid #3b82f6}\ntr.pr>td:first-child{border-left:3px solid transparent}\n.pol-nm{font-weight:500}.xi{font-size:9px;color:#94a3b8;margin-left:6px;transition:color .15s}\n.tc{color:#64748b;font-size:12px;max-width:220px}.td{color:#94a3b8;white-space:nowrap;font-size:12px}\n.si{font-size:10px;color:#94a3b8;margin-left:2px}\n.no-rows{text-align:center;padding:40px;color:#94a3b8;font-style:italic}\ntr[id^="dr-"]>td{background:#f8fafc;border-top:1px solid #e2e8f0;padding:0}\n.det-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;padding:16px 18px}\n.di label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;display:block;margin-bottom:3px}\n.di span{font-size:13px;color:#475569;word-break:break-all}.di.di-w{grid-column:1/-1}\n.mono{font-family:monospace;font-size:11px!important}\n.bdg{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600}\n.bdg-on{background:#dcfce7;color:#15803d}.bdg-off{background:#f1f5f9;color:#6b7280}.bdg-ro{background:#dbeafe;color:#1d4ed8}\n.gaps-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}\n.section-h{font-size:18px;font-weight:600}\n.btn-exp{padding:8px 16px;border:none;border-radius:8px;background:#16a34a;color:#fff;font-size:13px;font-weight:500;cursor:pointer}\n.btn-exp:hover{background:#15803d}\n.gap-grp{margin-bottom:26px}\n.gap-grp-hdr{font-size:16px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:10px}\n.gap-grp-ct{font-size:13px;font-weight:500;color:#64748b}\n.gap-card{border-left:4px solid;border-radius:8px;padding:16px 18px;margin-bottom:10px}\n.gap-chdr{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px;flex-wrap:wrap}\n.gap-ttl{font-size:15px;font-weight:600;flex:1;min-width:0}\n.cat-bdg{background:#e2e8f0;color:#475569;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;white-space:nowrap}\n.gap-desc{font-size:13px;color:#475569;margin-bottom:12px;line-height:1.6}\n.gap-aff{margin-bottom:12px}\n.gap-aff-lbl{font-size:10px;font-weight:700;text-transform:uppercase;color:#94a3b8;margin-bottom:5px}\n.ptag{display:inline-block;background:#e2e8f0;color:#475569;padding:2px 8px;border-radius:4px;font-size:11px;margin:2px}\n.gap-rec{background:rgba(255,255,255,.75);border-radius:6px;padding:11px 14px;font-size:13px;margin-bottom:10px;line-height:1.6;border:1px solid rgba(0,0,0,.06)}\n.gap-rlbl{font-size:10px;font-weight:700;text-transform:uppercase;color:#94a3b8;margin-bottom:5px}\n.gap-meta{font-size:11px;color:#94a3b8}\n.rule-id{font-size:11px;background:#e2e8f0;padding:1px 6px;border-radius:3px;color:#475569;font-family:monospace}\n.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}\n.chart-card{background:#fff;border-radius:10px;padding:20px 22px;box-shadow:0 1px 4px rgba(0,0,0,.08)}\n.chart-ttl{font-size:14px;font-weight:600;margin-bottom:14px}\ncanvas{display:block;max-width:100%}\n@media(max-width:900px){.sum-row{grid-template-columns:repeat(2,1fr)}.chart-grid{grid-template-columns:1fr}.det-grid{grid-template-columns:1fr 1fr}}\n@media(max-width:600px){.sum-row{grid-template-columns:1fr}.tbl-ctrl{flex-direction:column}.srch{width:100%}}\n</style>\n</head>\n<body>\n<header class="site-hdr">\n<div class="hdr-inner">\n<div><h1 id="rptTitle">CA Policy Report</h1><p id="rptMeta"></p></div>\n<div id="posturePill"></div>\n</div>\n</header>\n<div class="container">\n<div class="sum-row">\n<div class="stat-card"><div class="sc-val c-navy" id="scv-total">-</div><div class="sc-lbl">Total Policies</div></div>\n<div class="stat-card"><div class="sc-val c-green" id="scv-enabled">-</div><div class="sc-lbl">Enabled</div></div>\n<div class="stat-card"><div class="sc-val c-gray" id="scv-disabled">-</div><div class="sc-lbl">Disabled</div></div>\n<div class="stat-card"><div class="sc-val c-blue" id="scv-ro">-</div><div class="sc-lbl">Report-Only</div></div>\n</div>\n<div id="gapBar"></div>\n<div class="tab-bar">\n<button class="tab-btn active" onclick="switchTab(\'inventory\',this)">Policy Inventory <span class="tab-ct" id="inv-ct"></span></button>\n<button class="tab-btn" onclick="switchTab(\'gaps\',this)">Gap Analysis <span class="tab-ct" id="gap-ct"></span></button>\n<button class="tab-btn" onclick="switchTab(\'charts\',this)">Visualizations</button>\n</div>\n<div id="panel-inventory">\n<div class="card">\n<div class="tbl-ctrl">\n<input type="text" class="srch" placeholder="Search policies..." oninput="doSearch(this.value)">\n<div class="filt-grp">\n<button class="fbtn on" onclick="doFilter(\'all\',this)">All</button>\n<button class="fbtn" onclick="doFilter(\'Enabled\',this)">Enabled</button>\n<button class="fbtn" onclick="doFilter(\'Disabled\',this)">Disabled</button>\n<button class="fbtn" onclick="doFilter(\'Report Only\',this)">Report-Only</button>\n</div>\n<span id="tbl-ct" class="tbl-ct"></span>\n</div>\n<div class="tbl-wrap">\n<table><thead><tr>\n<th onclick="doSort(\'name\')">Policy Name <span class="si" id="si-name">&#x21C5;</span></th>\n<th onclick="doSort(\'state\')">State <span class="si" id="si-state">&#x21C5;</span></th>\n<th onclick="doSort(\'userScope\')">User Scope <span class="si" id="si-userScope">&#x21C5;</span></th>\n<th onclick="doSort(\'appScope\')">App Scope <span class="si" id="si-appScope">&#x21C5;</span></th>\n<th>Conditions</th><th>Grant Controls</th>\n<th onclick="doSort(\'modified\')">Modified <span class="si" id="si-modified">&#x21C5;</span></th>\n</tr></thead>\n<tbody id="polBody"></tbody>\n</table>\n</div>\n</div>\n</div>\n<div id="panel-gaps" style="display:none">\n<div class="card">\n<div class="gaps-hdr"><h2 class="section-h">Gap Analysis Results</h2>\n<button class="btn-exp" onclick="exportCSV()">&#x2B07; Export CSV</button></div>\n<div id="gapsContent"></div>\n</div>\n</div>\n<div id="panel-charts" style="display:none">\n<div class="chart-grid">\n<div class="chart-card"><div class="chart-ttl">Policy State Distribution</div><canvas id="cDonut" width="460" height="230"></canvas></div>\n<div class="chart-card"><div class="chart-ttl">Gap Severity Breakdown</div><canvas id="cGapBar" width="460" height="230"></canvas></div>\n<div class="chart-card"><div class="chart-ttl">Control &amp; Condition Adoption (enabled policies)</div><canvas id="cCond" width="460" height="270"></canvas></div>\n<div class="chart-card"><div class="chart-ttl">Policy Scope Breakdown (enabled policies)</div><canvas id="cScope" width="460" height="270"></canvas></div>\n</div>\n</div>\n</div>\n<script>\nconst POLICIES=__DATA_POLICIES__;\nconst GAPS=__DATA_GAPS__;\nconst STATS=__DATA_STATS__;\nconst CONDITIONS=__DATA_CONDITIONS__;\nconst TENANT=__DATA_TENANT__;\nconst GENERATED=__DATA_GENERATED__;\nvar _filt=\'all\',_sort=\'name\',_dir=1,_q=\'\',_chartsDrawn=false;\ndocument.addEventListener(\'DOMContentLoaded\',function(){\n  document.getElementById(\'rptTitle\').textContent=TENANT+\' \\u2014 CA Policy Report\';\n  document.getElementById(\'rptMeta\').textContent=\'Generated: \'+GENERATED+\'  \\u00b7  Last policy modification: \'+STATS.exportDate;\n  var pc={Red:\'#dc2626\',Amber:\'#d97706\',Green:\'#16a34a\'}[STATS.posture]||\'#64748b\';\n  document.getElementById(\'posturePill\').innerHTML=\'<span style="background:\'+pc+\';color:#fff;padding:7px 20px;border-radius:20px;font-weight:700;font-size:14px">\'+STATS.posture.toUpperCase()+\' POSTURE</span>\';\n  document.getElementById(\'scv-total\').textContent=STATS.total;\n  document.getElementById(\'scv-enabled\').textContent=STATS.enabled;\n  document.getElementById(\'scv-disabled\').textContent=STATS.disabled;\n  document.getElementById(\'scv-ro\').textContent=STATS.reportOnly;\n  renderGapBar();\n  document.getElementById(\'inv-ct\').textContent=POLICIES.length;\n  if(GAPS.length)document.getElementById(\'gap-ct\').textContent=GAPS.length;\n  renderTable();renderGaps();\n});\nfunction renderGapBar(){\n  var el=document.getElementById(\'gapBar\');\n  var segs=[{l:\'Critical\',v:STATS.critical,c:\'#dc2626\'},{l:\'High\',v:STATS.high,c:\'#ea580c\'},{l:\'Medium\',v:STATS.medium,c:\'#ca8a04\'},{l:\'Low\',v:STATS.low,c:\'#3b82f6\'}].filter(function(s){return s.v>0;});\n  if(!segs.length){el.innerHTML=\'<div class="no-gaps-bar">&#x2713; No gaps detected &#x2014; strong posture!</div>\';return;}\n  var pills=segs.map(function(s){return \'<span style="background:\'+s.c+\';color:#fff;padding:4px 14px;border-radius:14px;font-size:13px;font-weight:600">\'+s.v+\' \'+s.l+\'</span>\';}).join(\'\');\n  el.innerHTML=\'<div class="gap-bar-row"><span style="color:#64748b;font-size:13px;font-weight:500;margin-right:8px">Gaps found:</span>\'+pills+\'</div>\';\n}\nfunction switchTab(name,btn){\n  [\'inventory\',\'gaps\',\'charts\'].forEach(function(t){var p=document.getElementById(\'panel-\'+t);if(p)p.style.display=t===name?\'block\':\'none\';});\n  document.querySelectorAll(\'.tab-btn\').forEach(function(b){b.classList.remove(\'active\');});\n  btn.classList.add(\'active\');\n  if(name===\'charts\')setTimeout(renderCharts,60);\n}\nfunction doFilter(state,btn){_filt=state;document.querySelectorAll(\'.fbtn\').forEach(function(b){b.classList.remove(\'on\');});btn.classList.add(\'on\');renderTable();}\nfunction doSearch(q){_q=q.toLowerCase();renderTable();}\nfunction doSort(col){_dir=_sort===col?_dir*-1:1;_sort=col;document.querySelectorAll(\'.si\').forEach(function(s){s.innerHTML=\'&#x21C5;\';});var el=document.getElementById(\'si-\'+col);if(el)el.innerHTML=_dir===1?\'&#x2191;\':\'&#x2193;\';renderTable();}\nfunction renderTable(){\n  var rows=POLICIES.slice();\n  if(_filt!==\'all\')rows=rows.filter(function(p){return p.state===_filt;});\n  if(_q)rows=rows.filter(function(p){return[p.name,p.userScope,p.appScope,p.conditions,p.grant].some(function(f){return(f||\'\').toLowerCase().indexOf(_q)!==-1;});});\n  rows.sort(function(a,b){var av=(a[_sort]||\'\').toString().toLowerCase(),bv=(b[_sort]||\'\').toString().toLowerCase();return av<bv?-_dir:av>bv?_dir:0;});\n  document.getElementById(\'tbl-ct\').textContent=rows.length+\' / \'+POLICIES.length+\' policies\';\n  var BADGE={\'Enabled\':\'<span class="bdg bdg-on">Enabled</span>\',\'Disabled\':\'<span class="bdg bdg-off">Disabled</span>\',\'Report Only\':\'<span class="bdg bdg-ro">Report-Only</span>\'};\n  var html=rows.map(function(p){\n    var rc=p.stateRaw===\'disabled\'?\'tr-off\':p.stateRaw===\'enabledForReportingButNotEnforced\'?\'tr-ro\':\'\';\n    var cnd=p.conditions&&p.conditions.length>55?p.conditions.slice(0,55)+\'\\u2026\':(p.conditions||\'\\u2014\');\n    return \'<tr class="pr \'+rc+\'" onclick="toggleRow(\\\'\'+p.id+\'\\\')">\'\n      +\'<td><span class="pol-nm">\'+esc(p.name)+\'</span><span class="xi" id="xi-\'+p.id+\'">\\u25b6</span></td>\'\n      +\'<td>\'+(BADGE[p.state]||esc(p.state))+\'</td>\'\n      +\'<td>\'+esc(p.userScope)+\'</td><td>\'+esc(p.appScope)+\'</td>\'\n      +\'<td class="tc">\'+esc(cnd)+\'</td>\'\n      +\'<td>\'+esc(p.grant||\'\\u2014\')+\'</td>\'\n      +\'<td class="td">\'+esc(p.modified||\'\\u2014\')+\'</td></tr>\'\n      +\'<tr id="dr-\'+p.id+\'" style="display:none"><td colspan="7">\'\n      +\'<div class="det-grid">\'\n      +\'<div class="di"><label>Policy ID</label><span class="mono">\'+esc(p.id)+\'</span></div>\'\n      +\'<div class="di"><label>Created</label><span>\'+esc(p.created||\'\\u2014\')+\'</span></div>\'\n      +\'<div class="di"><label>Last Modified</label><span>\'+esc(p.modified||\'\\u2014\')+\'</span></div>\'\n      +\'<div class="di"><label>User Scope</label><span>\'+esc(p.userScope)+\'</span></div>\'\n      +\'<div class="di"><label>App Scope</label><span>\'+esc(p.appScope)+\'</span></div>\'\n      +\'<div class="di"><label>Session Controls</label><span>\'+esc(p.session||\'\\u2014\')+\'</span></div>\'\n      +\'<div class="di di-w"><label>All Conditions</label><span>\'+esc(p.conditions||\'\\u2014\')+\'</span></div>\'\n      +\'<div class="di di-w"><label>Grant Controls</label><span>\'+esc(p.grant||\'\\u2014\')+\'</span></div>\'\n      +\'</div></td></tr>\';\n  }).join(\'\');\n  document.getElementById(\'polBody\').innerHTML=html||\'<tr><td colspan="7" class="no-rows">No policies match the current filter.</td></tr>\';\n}\nfunction toggleRow(id){\n  var dr=document.getElementById(\'dr-\'+id),xi=document.getElementById(\'xi-\'+id);\n  if(!dr)return;var open=dr.style.display!==\'none\';\n  dr.style.display=open?\'none\':\'table-row\';\n  if(xi){xi.textContent=open?\'\\u25b6\':\'\\u25bc\';xi.style.color=open?\'\':\'#3b82f6\';}\n}\nfunction renderGaps(){\n  var el=document.getElementById(\'gapsContent\');\n  if(!GAPS.length){el.innerHTML=\'<div style="text-align:center;padding:60px;color:#64748b">No gaps detected.</div>\';return;}\n  var SC={Critical:\'#dc2626\',High:\'#ea580c\',Medium:\'#ca8a04\',Low:\'#3b82f6\'};\n  var SB={Critical:\'#fef2f2\',High:\'#fff7ed\',Medium:\'#fefce8\',Low:\'#eff6ff\'};\n  var EL={Low:\'Low effort\',Medium:\'Medium effort\',High:\'High effort\'};\n  var EC={Low:\'#16a34a\',Medium:\'#ca8a04\',High:\'#dc2626\'};\n  var groups={Critical:[],High:[],Medium:[],Low:[]};\n  GAPS.forEach(function(g){(groups[g.severity]=groups[g.severity]||[]).push(g);});\n  var html=\'\';\n  [\'Critical\',\'High\',\'Medium\',\'Low\'].forEach(function(sev){\n    var gs=groups[sev];if(!gs||!gs.length)return;\n    html+=\'<div class="gap-grp"><div class="gap-grp-hdr" style="color:\'+SC[sev]+\'">\'+sev+\'<span class="gap-grp-ct">\'+gs.length+\' finding\'+(gs.length>1?\'s\':\'\')+\'</span></div>\';\n    gs.forEach(function(g){\n      var aff=g.affected&&g.affected.length?\'<div class="gap-aff"><div class="gap-aff-lbl">Affected policies</div>\'+g.affected.map(function(n){return\'<span class="ptag">\'+esc(n)+\'</span>\';}).join(\'\')+\'</div>\':\'\';\n      html+=\'<div class="gap-card" style="border-left-color:\'+SC[sev]+\';background:\'+SB[sev]+\'">\'\n        +\'<div class="gap-chdr"><span class="gap-ttl">\'+esc(g.title)+\'</span>\'\n        +(g.category?\'<span class="cat-bdg">\'+esc(g.category)+\'</span>\':\'\')\n        +\'<span style="font-size:11px;font-weight:600;color:\'+(EC[g.effort]||\'#64748b\')+\';white-space:nowrap">\'+esc(EL[g.effort]||g.effort)+\'</span></div>\'\n        +\'<p class="gap-desc">\'+esc(g.description)+\'</p>\'+aff\n        +\'<div class="gap-rec"><div class="gap-rlbl">Recommendation</div>\'+esc(g.recommendation)+\'</div>\'\n        +\'<div class="gap-meta"><code class="rule-id">\'+esc(g.ruleId)+\'</code></div></div>\';\n    });\n    html+=\'</div>\';\n  });\n  el.innerHTML=html;\n}\nfunction exportCSV(){\n  var hdr=[\'Severity\',\'Category\',\'Title\',\'Description\',\'AffectedPolicies\',\'Recommendation\',\'Effort\'];\n  var lines=[hdr.join(\',\')];\n  GAPS.forEach(function(g){lines.push([g.severity,g.category,g.title,g.description,(g.affected||[]).join(\' | \'),g.recommendation,g.effort].map(function(v){return\'"\'+(v||\'\').replace(/"/g,\'""\')+\'"\';}).join(\',\'));});\n  var a=document.createElement(\'a\');\n  a.href=\'data:text/csv;charset=utf-8,%EF%BB%BF\'+encodeURIComponent(lines.join(\'\\r\\n\'));\n  a.download=\'ca-gaps.csv\';a.click();\n}\nfunction renderCharts(){\n  if(_chartsDrawn)return;_chartsDrawn=true;\n  drawDonut(\'cDonut\',[{l:\'Enabled\',v:STATS.enabled,c:\'#16a34a\'},{l:\'Disabled\',v:STATS.disabled,c:\'#9ca3af\'},{l:\'Report-Only\',v:STATS.reportOnly,c:\'#3b82f6\'}]);\n  drawBar(\'cGapBar\',[\'Critical\',\'High\',\'Medium\',\'Low\'],[STATS.critical,STATS.high,STATS.medium,STATS.low],[\'#dc2626\',\'#ea580c\',\'#ca8a04\',\'#3b82f6\']);\n  drawHBar(\'cCond\',Object.keys(CONDITIONS),Object.values(CONDITIONS),\'#3b82f6\');\n  var en=POLICIES.filter(function(p){return p.stateRaw===\'enabled\';});\n  drawHBar(\'cScope\',\n    [\'All Users\',\'Guests/Ext.\',\'All Apps\',\'Has MFA\',\'Has Device\',\'Sign-in Risk\',\'Has Session\'],\n    [en.filter(function(p){return p.userScope===\'All Users\';}).length,\n     en.filter(function(p){return p.userScope===\'Guests/External\';}).length,\n     en.filter(function(p){return p.appScope===\'All Cloud Apps\';}).length,\n     en.filter(function(p){return p.hasMFA;}).length,\n     en.filter(function(p){return p.hasDevice;}).length,\n     en.filter(function(p){return p.hasSignInRisk;}).length,\n     en.filter(function(p){return !!p.session;}).length],\n    \'#16a34a\');\n}\nfunction drawDonut(id,segs){\n  var c=document.getElementById(id);if(!c)return;\n  var x=c.getContext(\'2d\'),W=c.width,H=c.height;\n  var tot=segs.reduce(function(s,v){return s+v.v;},0);\n  x.clearRect(0,0,W,H);if(!tot)return;\n  var cx=W*0.42,cy=H/2,R=Math.min(cx,cy)*0.86,r=R*0.52,a=-Math.PI/2;\n  segs.forEach(function(s){var sw=(s.v/tot)*2*Math.PI;x.beginPath();x.moveTo(cx,cy);x.arc(cx,cy,R,a,a+sw);x.closePath();x.fillStyle=s.c;x.fill();a+=sw;});\n  x.beginPath();x.arc(cx,cy,r,0,2*Math.PI);x.fillStyle=\'#fff\';x.fill();\n  x.fillStyle=\'#1e293b\';x.textAlign=\'center\';x.textBaseline=\'middle\';\n  x.font=\'bold 24px -apple-system,sans-serif\';x.fillText(tot,cx,cy-9);\n  x.font=\'11px sans-serif\';x.fillStyle=\'#64748b\';x.fillText(\'policies\',cx,cy+12);\n  var ly=H/2-(segs.length*22)/2,lx=W*0.76;\n  segs.forEach(function(s){x.fillStyle=s.c;x.fillRect(lx,ly,12,12);x.fillStyle=\'#1e293b\';x.font=\'12px sans-serif\';x.textAlign=\'left\';x.textBaseline=\'top\';x.fillText(s.l+\' (\'+s.v+\')\',lx+16,ly);ly+=22;});\n}\nfunction drawBar(id,labels,vals,colors){\n  var c=document.getElementById(id);if(!c)return;\n  var x=c.getContext(\'2d\'),W=c.width,H=c.height,pt=28,pr=16,pb=40,pl=36;\n  var cW=W-pl-pr,cH=H-pt-pb,mx=Math.max.apply(null,vals.concat([1]));\n  var gap=cW/labels.length,bW=gap*0.6;\n  x.clearRect(0,0,W,H);\n  [0.25,0.5,0.75,1].forEach(function(f){var y=pt+cH*(1-f);x.strokeStyle=\'#f1f5f9\';x.lineWidth=1;x.beginPath();x.moveTo(pl,y);x.lineTo(W-pr,y);x.stroke();x.fillStyle=\'#94a3b8\';x.font=\'10px sans-serif\';x.textAlign=\'right\';x.textBaseline=\'middle\';x.fillText(Math.round(mx*f),pl-4,y);});\n  labels.forEach(function(lbl,i){var bx=pl+i*gap+(gap-bW)/2,bH=(vals[i]/mx)*cH,by=pt+cH-bH;x.fillStyle=colors[i];x.fillRect(bx,by,bW,bH);if(vals[i]>0){x.fillStyle=\'#1e293b\';x.font=\'bold 13px sans-serif\';x.textAlign=\'center\';x.textBaseline=\'bottom\';x.fillText(vals[i],bx+bW/2,by-2);}x.fillStyle=\'#64748b\';x.font=\'12px sans-serif\';x.textBaseline=\'top\';x.fillText(lbl,bx+bW/2,pt+cH+6);});\n}\nfunction drawHBar(id,labels,vals,color){\n  var c=document.getElementById(id);if(!c)return;\n  var x=c.getContext(\'2d\'),W=c.width,H=c.height,pL=112,pR=48,pT=12,pB=12;\n  var cW=W-pL-pR,cH=H-pT-pB,mx=Math.max.apply(null,vals.concat([1]));\n  var n=labels.length,rH=cH/n,bH=rH*0.52;\n  x.clearRect(0,0,W,H);\n  labels.forEach(function(lbl,i){var y=pT+i*rH+(rH-bH)/2,bW=(vals[i]/mx)*cW,mid=pT+i*rH+rH/2;x.fillStyle=\'#64748b\';x.font=\'12px -apple-system,sans-serif\';x.textAlign=\'right\';x.textBaseline=\'middle\';x.fillText(lbl,pL-8,mid);x.fillStyle=\'#f1f5f9\';x.fillRect(pL,y,cW,bH);x.fillStyle=color;if(bW>0)x.fillRect(pL,y,bW,bH);if(vals[i]>0){x.fillStyle=\'#1e293b\';x.font=\'11px sans-serif\';x.textAlign=\'left\';x.textBaseline=\'middle\';x.fillText(vals[i],pL+bW+5,mid);}});\n}\nfunction esc(s){if(s==null)return\'\';return String(s).replace(/&/g,\'&amp;\').replace(/</g,\'&lt;\').replace(/>/g,\'&gt;\').replace(/"/g,\'&quot;\');}\n</script>\n</body>\n</html>\n'
