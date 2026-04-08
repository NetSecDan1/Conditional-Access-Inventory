"""Data models for the CA Policy Inventory tool."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyConditions:
    users_include: List[str] = field(default_factory=list)
    users_exclude: List[str] = field(default_factory=list)
    groups_include: List[str] = field(default_factory=list)
    groups_exclude: List[str] = field(default_factory=list)
    roles_include: List[str] = field(default_factory=list)
    roles_exclude: List[str] = field(default_factory=list)
    apps_include: List[str] = field(default_factory=list)
    apps_exclude: List[str] = field(default_factory=list)
    user_actions: List[str] = field(default_factory=list)
    client_app_types: List[str] = field(default_factory=list)
    platforms_include: List[str] = field(default_factory=list)
    platforms_exclude: List[str] = field(default_factory=list)
    locations_include: List[str] = field(default_factory=list)
    locations_exclude: List[str] = field(default_factory=list)
    sign_in_risk_levels: List[str] = field(default_factory=list)
    user_risk_levels: List[str] = field(default_factory=list)


@dataclass
class GrantControls:
    operator: Optional[str] = None
    built_in_controls: List[str] = field(default_factory=list)
    custom_auth_factors: List[str] = field(default_factory=list)
    terms_of_use: List[str] = field(default_factory=list)


@dataclass
class SessionControls:
    sign_in_frequency_value: Optional[int] = None
    sign_in_frequency_unit: Optional[str] = None
    persistent_browser_mode: Optional[str] = None
    application_enforced_restrictions: bool = False
    cloud_app_security_type: Optional[str] = None


@dataclass
class Policy:
    id: str
    display_name: str
    state: str
    conditions: PolicyConditions
    grant_controls: Optional[GrantControls]
    session_controls: Optional[SessionControls]
    created_datetime: Optional[str]
    modified_datetime: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)

    # ── State helpers ────────────────────────────────────────────────────

    @property
    def is_enabled(self) -> bool:
        return self.state == "enabled"

    @property
    def is_disabled(self) -> bool:
        return self.state == "disabled"

    @property
    def is_report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"

    @property
    def state_display(self) -> str:
        if self.is_enabled:
            return "Enabled"
        if self.is_disabled:
            return "Disabled"
        return "Report Only"

    # ── Control helpers ───────────────────────────────────────────────────

    @property
    def requires_mfa(self) -> bool:
        return bool(self.grant_controls and "mfa" in self.grant_controls.built_in_controls)

    @property
    def blocks_access(self) -> bool:
        return bool(self.grant_controls and "block" in self.grant_controls.built_in_controls)

    @property
    def requires_compliant_device(self) -> bool:
        return bool(self.grant_controls and "compliantDevice" in self.grant_controls.built_in_controls)

    @property
    def requires_domain_joined(self) -> bool:
        return bool(self.grant_controls and "domainJoinedDevice" in self.grant_controls.built_in_controls)

    # ── Scope helpers ─────────────────────────────────────────────────────

    @property
    def covers_all_users(self) -> bool:
        return "All" in self.conditions.users_include

    @property
    def covers_all_apps(self) -> bool:
        return "All" in self.conditions.apps_include

    @property
    def covers_guests(self) -> bool:
        return "GuestsOrExternalUsers" in self.conditions.users_include

    @property
    def targets_legacy_auth(self) -> bool:
        return bool({"exchangeActiveSync", "other"} & set(self.conditions.client_app_types))


@dataclass
class Gap:
    rule_id: str
    severity: str           # Critical | High | Medium | Low
    title: str
    description: str
    category: str = ""
    affected_policies: List[str] = field(default_factory=list)
    recommendation: str = ""
    effort: str = "Medium"  # Low | Medium | High


@dataclass
class Stats:
    total: int
    enabled: int
    disabled: int
    report_only: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    posture: str            # Red | Amber | Green
    export_date: Optional[str]
