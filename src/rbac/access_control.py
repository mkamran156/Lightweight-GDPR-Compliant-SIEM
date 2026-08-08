"""
RBAC enforcement layer, loading role definitions from roles.yaml.

This module answers one question: "does this user's role grant this
permission?" It deliberately does not handle authentication (verifying
who the user is) -- that is expected to be handled upstream by your
identity provider, with the resulting role passed in here.

Usage:
    rbac = RBACPolicy.from_yaml("roles.yaml")
    if rbac.is_allowed(user_role="security_analyst", permission="access_salts"):
        ...
    else:
        raise PermissionError(...)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

import yaml


@dataclass(frozen=True)
class Role:
    name: str
    description: str
    permissions: Set[str]


class RBACPolicy:
    """Loads role -> permission mappings and answers authorization checks."""

    def __init__(self, roles: Dict[str, Role]):
        self._roles = roles

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RBACPolicy":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        roles: Dict[str, Role] = {}
        for name, definition in data.get("roles", {}).items():
            roles[name] = Role(
                name=name,
                description=definition.get("description", "").strip(),
                permissions=set(definition.get("permissions", [])),
            )
        return cls(roles)

    def is_allowed(self, user_role: str, permission: str) -> bool:
        """Return True if the given role grants the given permission."""
        role = self._roles.get(user_role)
        if role is None:
            return False
        return permission in role.permissions

    def require(self, user_role: str, permission: str) -> None:
        """Raise PermissionError if the role does not grant the permission."""
        if not self.is_allowed(user_role, permission):
            raise PermissionError(
                f"Role '{user_role}' does not have permission '{permission}'."
            )

    def permissions_for(self, user_role: str) -> List[str]:
        role = self._roles.get(user_role)
        return sorted(role.permissions) if role else []


if __name__ == "__main__":
    # Quick self-check when run directly.
    policy = RBACPolicy.from_yaml(Path(__file__).parent / "roles.yaml")

    checks = [
        ("administrator", "reidentify_pseudonyms", True),
        ("security_analyst", "reidentify_pseudonyms", False),
        ("security_analyst", "view_pseudonymized_logs", True),
        ("viewer", "acknowledge_alerts", False),
        ("viewer", "view_dashboards", True),
    ]
    for role, permission, expected in checks:
        result = policy.is_allowed(role, permission)
        status = "OK" if result == expected else "FAIL"
        print(f"[{status}] {role} -> {permission}: {result}")
