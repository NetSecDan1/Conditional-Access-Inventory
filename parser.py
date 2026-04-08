"""Ingest and normalize Microsoft Graph CA policy JSON exports."""

import json
import os
from typing import Any, Dict, List

from models import GrantControls, Policy, PolicyConditions, SessionControls


class ParseError(Exception):
    pass


class PolicyParser:

    def parse(self, filepath: str) -> List[Policy]:
        """Parse a Graph JSON export.  Returns a list of normalized Policy objects."""
        if not os.path.exists(filepath):
            raise ParseError(f"File not found: {filepath}")

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON: {exc}") from exc

        raw_list = self._extract_list(data)

        policies: List[Policy] = []
        for raw in raw_list:
            try:
                policies.append(self._build(raw))
            except Exception as exc:  # noqa: BLE001
                name = raw.get("displayName") or raw.get("id") or "unknown"
                print(f"  [warn] Skipped policy '{name}': {exc}")

        return policies

    # ── Internal ──────────────────────────────────────────────────────────

    def _extract_list(self, data: Any) -> List[Dict]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            if "value" in data:
                return data["value"]
            if "id" in data:
                return [data]           # single policy object
        raise ParseError(
            "Unexpected JSON structure. Expected a list of CA policies or a Graph API "
            "response with a 'value' array.\n"
            "  Export:  az rest --method GET "
            "--url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'"
        )

    def _build(self, raw: Dict) -> Policy:
        cond_raw = raw.get("conditions") or {}
        return Policy(
            id=raw.get("id", ""),
            display_name=raw.get("displayName", "Unnamed Policy"),
            state=raw.get("state", "disabled"),
            conditions=self._conditions(cond_raw),
            grant_controls=self._grant(raw.get("grantControls")),
            session_controls=self._session(raw.get("sessionControls")),
            created_datetime=raw.get("createdDateTime"),
            modified_datetime=raw.get("modifiedDateTime"),
            raw=raw,
        )

    def _conditions(self, c: Dict) -> PolicyConditions:
        users = c.get("users") or {}
        apps  = c.get("applications") or {}
        plat  = c.get("platforms") or {}
        locs  = c.get("locations") or {}
        return PolicyConditions(
            users_include=self._lst(users.get("includeUsers")),
            users_exclude=self._lst(users.get("excludeUsers")),
            groups_include=self._lst(users.get("includeGroups")),
            groups_exclude=self._lst(users.get("excludeGroups")),
            roles_include=self._lst(users.get("includeRoles")),
            roles_exclude=self._lst(users.get("excludeRoles")),
            apps_include=self._lst(apps.get("includeApplications")),
            apps_exclude=self._lst(apps.get("excludeApplications")),
            user_actions=self._lst(apps.get("includeUserActions")),
            client_app_types=self._lst(c.get("clientAppTypes")),
            platforms_include=self._lst(plat.get("includePlatforms")),
            platforms_exclude=self._lst(plat.get("excludePlatforms")),
            locations_include=self._lst(locs.get("includeLocations")),
            locations_exclude=self._lst(locs.get("excludeLocations")),
            sign_in_risk_levels=self._lst(c.get("signInRiskLevels")),
            user_risk_levels=self._lst(c.get("userRiskLevels")),
        )

    def _grant(self, g: Any) -> GrantControls | None:
        if not g:
            return None
        return GrantControls(
            operator=g.get("operator"),
            built_in_controls=self._lst(g.get("builtInControls")),
            custom_auth_factors=self._lst(g.get("customAuthenticationFactors")),
            terms_of_use=self._lst(g.get("termsOfUse")),
        )

    def _session(self, s: Any) -> SessionControls | None:
        if not s:
            return None
        sif = s.get("signInFrequency") or {}
        pb  = s.get("persistentBrowser") or {}
        aer = s.get("applicationEnforcedRestrictions") or {}
        cas = s.get("cloudAppSecurity") or {}
        return SessionControls(
            sign_in_frequency_value=sif.get("value"),
            sign_in_frequency_unit=sif.get("type"),
            persistent_browser_mode=pb.get("mode"),
            application_enforced_restrictions=bool(aer.get("isEnabled")),
            cloud_app_security_type=cas.get("cloudAppSecurityType"),
        )

    @staticmethod
    def _lst(val: Any) -> List:
        if val is None:
            return []
        return val if isinstance(val, list) else [val]
