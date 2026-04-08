"""Gap analysis rules based on Microsoft Zero Trust / CA best practice."""

from typing import Any, Dict, List, Optional

from models import Gap, Policy

# Well-known privileged role GUIDs
_ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "966707d0-3269-4727-9be2-8c3a10f19b9d",  # Password Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",  # Billing Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
}

_LEGACY_TYPES = {"exchangeActiveSync", "other"}

_BREAKGLASS_KW = {
    "breakglass", "break-glass", "break_glass",
    "emergency", "emerg", "eaa", "glass",
}


class GapEngine:

    def __init__(self, config: Dict[str, Any] = None):
        self._rules_cfg: Dict[str, Dict] = (config or {}).get("rules", {})

    def analyze(self, policies: List[Policy]) -> List[Gap]:
        enabled = [p for p in policies if p.is_enabled]
        results: List[Gap] = []

        for method in (
            self._mfa_all_users,
            self._mfa_admins,
            self._legacy_auth,
            self._sign_in_risk,
            self._user_risk,
            self._device_compliance,
            self._guest_coverage,
            self._breakglass,
            self._disabled_policies,
            self._report_only_policies,
            self._session_controls,
            self._no_controls,
            self._overlap,
        ):
            rule_id = method.__name__.lstrip("_").upper()
            cfg = self._rules_cfg.get(rule_id, {})
            if cfg.get("enabled", True) is False:
                continue

            found = method(policies, enabled)
            if not found:
                continue

            gaps = found if isinstance(found, list) else [found]
            for gap in gaps:
                if "severity" in cfg:
                    gap.severity = cfg["severity"]
                results.append(gap)

        return results

    # ── Rules ─────────────────────────────────────────────────────────────

    def _mfa_all_users(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any(p.requires_mfa and p.covers_all_users and p.covers_all_apps for p in enabled):
            return None
        return Gap(
            rule_id="MFA_ALL_USERS",
            severity="Critical",
            category="MFA",
            title="No MFA policy covering all users and all apps",
            description=(
                "No enabled policy requires MFA for All Users across All Cloud Apps. "
                "This is the single highest-impact CA control and the cornerstone of a "
                "Zero Trust identity posture."
            ),
            recommendation=(
                "Create an enabled CA policy: All Users → All Cloud Apps → Grant: Require MFA. "
                "Exclude break-glass accounts via a dedicated security group."
            ),
            effort="Low",
        )

    def _mfa_admins(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        covered = any(
            p.requires_mfa and (
                p.covers_all_users
                or bool(set(p.conditions.roles_include) & _ADMIN_ROLES)
                or any(r.lower() in {"all", "alladmins"} for r in p.conditions.roles_include)
            )
            for p in enabled
        )
        if covered:
            return None
        return Gap(
            rule_id="MFA_ADMINS",
            severity="Critical",
            category="MFA",
            title="No MFA policy explicitly targeting administrator roles",
            description=(
                "Privileged admin roles do not appear to be targeted by a dedicated MFA policy. "
                "Admin accounts are the highest-value targets for credential-based attacks."
            ),
            recommendation=(
                "Create a CA policy targeting all Directory Roles (or specific admin role GUIDs) "
                "requiring MFA or phishing-resistant MFA (FIDO2 / CBA)."
            ),
            effort="Low",
        )

    def _legacy_auth(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any(
            p.blocks_access and bool(_LEGACY_TYPES & set(p.conditions.client_app_types))
            for p in enabled
        ):
            return None
        return Gap(
            rule_id="LEGACY_AUTH",
            severity="Critical",
            category="Legacy Auth",
            title="Legacy authentication protocols are not blocked",
            description=(
                "No enabled policy blocks legacy authentication (Exchange ActiveSync, SMTP AUTH, "
                "POP3, IMAP4). These protocols bypass MFA entirely and are a primary vector for "
                "password spray and credential stuffing."
            ),
            recommendation=(
                "Create a CA policy: All Users → All Cloud Apps → Client Apps: "
                "Exchange ActiveSync + Other → Grant: Block. Test in report-only mode first."
            ),
            effort="Low",
        )

    def _sign_in_risk(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any(p.conditions.sign_in_risk_levels for p in enabled):
            return None
        return Gap(
            rule_id="SIGN_IN_RISK",
            severity="High",
            category="Risk",
            title="No sign-in risk policy configured",
            description=(
                "No enabled policy uses sign-in risk signals. Sign-in risk provides adaptive "
                "controls that challenge or block anomalous authentications in real time. "
                "Requires Entra ID P2 licensing."
            ),
            recommendation=(
                "Create policies for High sign-in risk (block or require MFA + compliant device) "
                "and Medium sign-in risk (require MFA). Requires Entra ID P2."
            ),
            effort="Medium",
        )

    def _user_risk(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any(p.conditions.user_risk_levels for p in enabled):
            return None
        return Gap(
            rule_id="USER_RISK",
            severity="High",
            category="Risk",
            title="No user risk policy configured",
            description=(
                "No enabled policy uses user risk signals. User risk detects compromised accounts "
                "(leaked credentials, anomalous activity) and should trigger remediation. "
                "Requires Entra ID P2 licensing."
            ),
            recommendation=(
                "Create a CA policy for High user risk requiring a secure password change. "
                "Requires Entra ID P2."
            ),
            effort="Medium",
        )

    def _device_compliance(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any(p.requires_compliant_device or p.requires_domain_joined for p in enabled):
            return None
        return Gap(
            rule_id="DEVICE_COMPLIANCE",
            severity="High",
            category="Device",
            title="No device compliance or hybrid join requirement",
            description=(
                "No enabled policy requires a compliant or hybrid Azure AD-joined device. "
                "Without device controls, any device—including personal or compromised—can access "
                "corporate resources after clearing MFA."
            ),
            recommendation=(
                "Require compliant or hybrid-joined devices for sensitive apps. "
                "For managed endpoints, consider requiring it for all apps."
            ),
            effort="High",
        )

    def _guest_coverage(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        if any("GuestsOrExternalUsers" in p.conditions.users_include for p in enabled):
            return None
        return Gap(
            rule_id="GUEST_COVERAGE",
            severity="High",
            category="Guest Access",
            title="No policy explicitly targets guest or external users",
            description=(
                "Guest and external users have no dedicated CA policy. "
                "While an 'All Users' policy may cover them, guests typically need stricter "
                "controls: MFA always required, no persistent sessions, limited app access."
            ),
            recommendation=(
                "Create a CA policy for GuestsOrExternalUsers requiring MFA, "
                "a limited sign-in frequency, and restricting access to approved apps only."
            ),
            effort="Medium",
        )

    def _breakglass(self, _all: List[Policy], enabled: List[Policy]) -> List[Gap]:
        gaps: List[Gap] = []

        def _has_bg(p: Policy) -> bool:
            excls = p.conditions.users_exclude + p.conditions.groups_exclude + p.conditions.roles_exclude
            return any(
                any(kw in str(e).lower() for kw in _BREAKGLASS_KW)
                for e in excls
            )

        if not any(_has_bg(p) for p in enabled):
            gaps.append(Gap(
                rule_id="BREAKGLASS_EXCLUSION",
                severity="High",
                category="Break Glass",
                title="No break-glass exclusion group detected across policies",
                description=(
                    "No enabled policy excludes break-glass or emergency access accounts. "
                    "A misconfigured CA policy could lock all administrators out, including "
                    "during an active incident."
                ),
                recommendation=(
                    "Create a dedicated security group for break-glass accounts and exclude it "
                    "from every CA policy. Monitor this group with privileged identity alerts."
                ),
                effort="Low",
            ))

        # Policies covering all users with zero exclusions
        exposed = [
            p for p in enabled
            if p.covers_all_users
            and not p.conditions.users_exclude
            and not p.conditions.groups_exclude
        ]
        if exposed:
            gaps.append(Gap(
                rule_id="ALL_USER_NO_EXCLUSION",
                severity="Medium",
                category="Break Glass",
                title=f"{len(exposed)} 'All Users' policy/policies have no user or group exclusions",
                description=(
                    "These policies target All Users with no exclusions, meaning break-glass "
                    "accounts are fully in scope and could be locked out."
                ),
                affected_policies=[p.display_name for p in exposed],
                recommendation="Add a break-glass exclusion group to every All Users policy.",
                effort="Low",
            ))

        return gaps

    def _disabled_policies(self, all_policies: List[Policy], _enabled: List[Policy]) -> List[Gap]:
        disabled = [p for p in all_policies if p.is_disabled]
        if not disabled:
            return []
        return [Gap(
            rule_id="DISABLED_POLICIES",
            severity="Low",
            category="Policy Hygiene",
            title=f"{len(disabled)} disabled policy/policies detected",
            description=(
                f"{len(disabled)} policies are in disabled state. These may be stale, "
                "forgotten, or held in development. They should be reviewed regularly."
            ),
            affected_policies=[p.display_name for p in disabled],
            recommendation=(
                "Review each disabled policy. Enable valid ones, delete stale ones, "
                "or document the business reason for keeping them disabled."
            ),
            effort="Low",
        )]

    def _report_only_policies(self, all_policies: List[Policy], _enabled: List[Policy]) -> List[Gap]:
        ro = [p for p in all_policies if p.is_report_only]
        if not ro:
            return []
        return [Gap(
            rule_id="REPORT_ONLY",
            severity="Medium",
            category="Policy Hygiene",
            title=f"{len(ro)} policy/policies stuck in report-only mode",
            description=(
                f"{len(ro)} policies are in report-only mode and provide zero enforcement. "
                "They may represent intended controls that were never promoted to enforcement."
            ),
            affected_policies=[p.display_name for p in ro],
            recommendation=(
                "Review sign-in logs for each report-only policy. "
                "If the impact is acceptable, promote to enabled. Otherwise refine scope and re-evaluate."
            ),
            effort="Medium",
        )]

    def _session_controls(self, _all: List[Policy], enabled: List[Policy]) -> Optional[Gap]:
        def _has_session(p: Policy) -> bool:
            sc = p.session_controls
            return bool(sc and (
                sc.sign_in_frequency_value is not None
                or sc.persistent_browser_mode
                or sc.application_enforced_restrictions
                or sc.cloud_app_security_type
            ))

        if any(_has_session(p) for p in enabled):
            return None
        return Gap(
            rule_id="SESSION_CONTROLS",
            severity="Medium",
            category="Session",
            title="No session controls configured across any enabled policy",
            description=(
                "No enabled policy sets sign-in frequency, persistent browser session policy, "
                "or app-enforced restrictions. Tokens may persist indefinitely on shared or "
                "unmanaged devices."
            ),
            recommendation=(
                "Set sign-in frequency for privileged access (1 hour) and general access (8 hours). "
                "Disable persistent browser sessions for unmanaged or guest devices."
            ),
            effort="Low",
        )

    def _no_controls(self, _all: List[Policy], enabled: List[Policy]) -> List[Gap]:
        empty = [p for p in enabled if not p.grant_controls and not p.session_controls]
        if not empty:
            return []
        return [Gap(
            rule_id="NO_CONTROLS",
            severity="Medium",
            category="Policy Hygiene",
            title=f"{len(empty)} enabled policy/policies apply no controls",
            description=(
                "These policies match conditions but apply neither grant nor session controls—"
                "they are effective no-ops. This is almost certainly a configuration mistake."
            ),
            affected_policies=[p.display_name for p in empty],
            recommendation=(
                "Add grant controls (MFA, block, compliant device) or session controls to each, "
                "or delete the policies if they serve no purpose."
            ),
            effort="Low",
        )]

    def _overlap(self, _all: List[Policy], enabled: List[Policy]) -> List[Gap]:
        broad = [p for p in enabled if p.covers_all_users and p.covers_all_apps]
        if len(broad) <= 3:
            return []
        return [Gap(
            rule_id="POLICY_OVERLAP",
            severity="Low",
            category="Policy Hygiene",
            title=f"{len(broad)} policies target all users and all apps simultaneously",
            description=(
                f"{len(broad)} enabled policies all scope to 'All Users' and 'All Cloud Apps'. "
                "Multiple broad-scope policies can create unintended control interactions."
            ),
            affected_policies=[p.display_name for p in broad],
            recommendation=(
                "Review these policies for redundancy. Confirm each has a distinct documented "
                "purpose and that their combined effect is intentional and tested."
            ),
            effort="Medium",
        )]
