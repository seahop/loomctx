"""Predicates the identity connectors (Entra, Okta) share in one namespace.

Registration merges by predicate name with the later definition winning, so a
shared predicate that carries object types or flags must be declared
identically by every connector that writes it — otherwise whichever registered last rejects
the other's claims on its next import.
"""

from .. import coverage
from ..contracts import PredicateDef

SHARED_PREDICATES = [
    PredicateDef(name="member_of", object_types=["group", "directory_role"],
                 containment=True, description="direct group or role membership"),
    PredicateDef(name="has_role", object_types=["directory_role", "admin_role"],
                 description="a directory (Entra) or admin (Okta) role held by a "
                             "user, group or service principal"),
    coverage.PREDICATE_DEF,
    PredicateDef(name="enabled", node_status=True,
                 description="the account or principal is enabled / active; "
                             "reported on every path that passes through it"),
]
