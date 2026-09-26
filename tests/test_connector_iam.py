"""Identity/IAM connectors (Entra ID + Okta): JSON parsing, entity
extraction, group membership, role assignments, app permissions, and a
round-trip import → ask_scope over member_of + has_role that returns the
chain cited. No real IdP data; the fixtures are synthetic."""

from pathlib import Path

from loom.connectors import entra, okta
from loom.context import build_pack, find_paths
from loom.contracts import AskRequest, EntityRef, PathRequest, ScopeSpec
from loom.store.sqlite import SqliteStore

ENTRA_FIXTURE = Path(__file__).parent / "fixtures" / "entra_directory.json"
OKTA_FIXTURE = Path(__file__).parent / "fixtures" / "okta_directory.json"


# ---------------------------------------------------------------- Entra ID #

def test_entra_parses_all_object_types():
    text = ENTRA_FIXTURE.read_text()
    stats: dict[str, int] = {}
    envs = list(entra.entra_to_envelopes(text, "iam", stats=stats))
    assert stats.get("object", 0) >= 8
    preds = {e.predicate for e in envs}
    assert {"upn", "name", "enabled", "member_of", "has_role",
            "has_app_role", "owner_of", "has_permission"} <= preds


def test_entra_user_attributes():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    alice_envs = [e for e in envs if e.subject == EntityRef(type="user", key="u-001-alice")]
    by_pred = {e.predicate: e.object for e in alice_envs}
    assert by_pred["upn"] == "alice@contoso.com"
    assert by_pred["name"] == "Alice Zhao"
    assert by_pred["enabled"] is True
    assert by_pred["user_type"] == "Member"
    assert by_pred["job_title"] == "Security Engineer"


def test_entra_group_membership_and_ownership():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    member_ofs = [(e.subject.key, e.object.key) for e in envs if e.predicate == "member_of"]
    assert ("u-001-alice", "g-001-secops") in member_ofs
    assert ("u-002-bob", "g-001-secops") in member_ofs
    owners = [(e.subject.key, e.object.key) for e in envs if e.predicate == "owner_of"]
    assert ("u-001-alice", "g-001-secops") in owners
    assert ("u-001-alice", "sp-001-sentinel") in owners


def test_entra_dynamic_group():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    alluser_envs = [e for e in envs if e.subject == EntityRef(type="group", key="g-002-allusers")]
    types = {e.predicate: e.object for e in alluser_envs}
    assert types.get("group_type") == "dynamic"
    assert types.get("membership_rule") == 'user.userType -eq "Member"'


def test_entra_role_assignment_privileged():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    roles = [(e.subject.key, e.object.key, e.predicate) for e in envs if e.predicate == "has_role"]
    assert ("u-002-bob", "62e90394-69f5-4237-9190-012177145e10", "has_role") in roles
    assert ("u-001-alice", "194ae4cb-b126-40b2-bd5b-6091b380977d", "has_role") in roles
    priv = [e for e in envs if e.predicate == "privileged"]
    priv_keys = {e.subject.key for e in priv}
    assert "62e90394-69f5-4237-9190-012177145e10" in priv_keys


def test_entra_sp_credentials():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    sp_envs = [e for e in envs if e.subject == EntityRef(type="service_principal", key="sp-001-sentinel")]
    creds = [e for e in sp_envs if e.predicate in ("key_credential", "password_credential")]
    assert len(creds) == 2
    key_cred = next(e for e in creds if e.predicate == "key_credential")
    assert key_cred.attrs.get("key_expiry") == "2027-06-15T00:00:00Z"


def test_entra_app_role_and_permissions():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    app_roles = [e for e in envs if e.predicate == "has_app_role"]
    assert any(e.subject.key == "u-001-alice" and e.object.key == "sp-001-sentinel" for e in app_roles)
    permissions = [e for e in envs if e.predicate == "has_permission"]
    assert len(permissions) >= 2
    perm_scopes = {e.attrs.get("scope", "") for e in permissions}
    assert {"User.Read", "Directory.Read.All"} <= perm_scopes


def test_entra_app_registration_permissions():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    reqs = [e for e in envs if e.predicate == "requires_permission"]
    assert len(reqs) == 2
    assert all(e.subject == EntityRef(type="app_registration", key="ar-001-internalapi") for e in reqs)


def test_entra_reimport_idempotent(tmp_path):
    db = str(tmp_path / "entra.db")
    entra.main(["import", str(ENTRA_FIXTURE), "--namespace", "iam", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("iam"))
    entra.main(["import", str(ENTRA_FIXTURE), "--namespace", "iam", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("iam"))
    assert before == after and before > 0


def test_entra_scope_walk_user_to_role(tmp_path):
    """Import then ask_scope: bob -has_role-> Global Administrator. The walk
    reaches the role, every item cited."""
    db = str(tmp_path / "scope.db")
    entra.main(["import", str(ENTRA_FIXTURE), "--namespace", "iam", "--db", db])
    store = SqliteStore(db)
    try:
        scope = ScopeSpec(subjects=[EntityRef(type="user", key="u-002-bob")],
                          expand=["has_role", "member_of"], depth=2)
        pack = build_pack(store, AskRequest(
            namespace="iam", scope=scope, budget=4000,
            question="what roles does Bob have?"))
        blob = "\n".join(i.text for i in pack.items)
        assert "has_role" in blob
        reached = {(s.type, s.key) for s in pack.subjects}
        assert ("directory_role", "62e90394-69f5-4237-9190-012177145e10") in reached
        assert pack.items and all(i.citations for i in pack.items)
    finally:
        store.close()


def test_entra_find_path_user_to_role(tmp_path):
    """find_path: alice -has_role-> Security Administrator, cited."""
    db = str(tmp_path / "path.db")
    entra.main(["import", str(ENTRA_FIXTURE), "--namespace", "iam", "--db", db])
    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="iam",
            **{"from": EntityRef(type="user", key="u-001-alice")},
            to=EntityRef(type="directory_role", key="194ae4cb-b126-40b2-bd5b-6091b380977d"),
            via=["has_role"], depth=2, max_paths=4))
        assert pack.paths, "alice reaches Security Administrator via has_role"
        assert pack.paths[0][0].predicate == "has_role"
        assert all(e.cite.observation_id for e in pack.paths[0])
    finally:
        store.close()


def test_entra_schema_registers_predicates():
    reg = entra.schema("iam")
    preds = {p.name for p in reg.predicates}
    assert {"member_of", "has_role", "has_app_role", "has_permission",
            "owner_of", "requires_permission"} <= preds
    types = {t.name for t in reg.entity_types}
    assert {"user", "group", "service_principal", "app_registration",
            "directory_role", "api_permission"} <= types


def test_entra_disabled_guest_flagged():
    text = ENTRA_FIXTURE.read_text()
    envs = list(entra.entra_to_envelopes(text, "iam"))
    carol = [e for e in envs if e.subject == EntityRef(type="user", key="u-003-carol")]
    by_pred = {e.predicate: e.object for e in carol}
    assert by_pred["enabled"] is False
    assert by_pred["user_type"] == "Guest"


# ------------------------------------------------------------------- Okta #

def test_okta_parses_all_object_types():
    text = OKTA_FIXTURE.read_text()
    stats: dict[str, int] = {}
    envs = list(okta.okta_to_envelopes(text, "iam", stats=stats))
    assert stats.get("object", 0) >= 8
    preds = {e.predicate for e in envs}
    assert {"login", "name", "enabled", "member_of", "assigned_to",
            "mfa_enrolled"} <= preds


def test_okta_user_attributes():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    alice = [e for e in envs if e.subject == EntityRef(type="user", key="okta-u-001")]
    by_pred = {e.predicate: e.object for e in alice if e.predicate not in ("member_of", "mfa_factor")}
    assert by_pred["login"] == "alice@acme.com"
    assert by_pred["name"] == "Alice Chen"
    assert by_pred["enabled"] is True
    assert by_pred["mfa_enrolled"] is True
    assert by_pred["credential_provider"] == "OKTA"


def test_okta_suspended_user():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    dave = [e for e in envs if e.subject == EntityRef(type="user", key="okta-u-003")]
    by_pred = {e.predicate: e.object for e in dave}
    assert by_pred["enabled"] is False
    assert by_pred["status"] == "SUSPENDED"


def test_okta_group_membership():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    member_ofs = [(e.subject.key, e.object.key) for e in envs if e.predicate == "member_of"]
    assert ("okta-u-001", "okta-g-001") in member_ofs
    assert ("okta-u-001", "okta-g-002") in member_ofs
    assert ("okta-u-002", "okta-g-002") in member_ofs


def test_okta_membership_from_both_sides():
    """Membership emitted from the user's _groupIds AND the group's _members
    are deduplicated by event_id."""
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    alice_g1 = [e for e in envs if e.predicate == "member_of"
                and e.subject.key == "okta-u-001" and e.object.key == "okta-g-001"]
    eids = {e.event_id for e in alice_g1}
    assert len(eids) == 1


def test_okta_app_assignment():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    assigns = [(e.subject.key, e.object.key) for e in envs if e.predicate == "assigned_to"]
    assert ("okta-u-001", "okta-app-001") in assigns
    assert ("okta-u-002", "okta-app-001") in assigns
    assert ("okta-u-002", "okta-app-002") in assigns


def test_okta_mfa_factors():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    alice_factors = [e for e in envs if e.subject.key == "okta-u-001"
                     and e.predicate == "mfa_factor"]
    ftypes = {e.object for e in alice_factors}
    assert "push" in ftypes and "token:software:totp" in ftypes


def test_okta_app_sign_on_mode():
    text = OKTA_FIXTURE.read_text()
    envs = list(okta.okta_to_envelopes(text, "iam"))
    splunk = [e for e in envs if e.subject.key == "okta-app-001"]
    by_pred = {e.predicate: e.object for e in splunk}
    assert by_pred["sign_on_mode"] == "SAML_2_0"
    assert by_pred["name"] == "Splunk SIEM"


def test_okta_reimport_idempotent(tmp_path):
    db = str(tmp_path / "okta.db")
    okta.main(["import", str(OKTA_FIXTURE), "--namespace", "iam", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("iam"))
    okta.main(["import", str(OKTA_FIXTURE), "--namespace", "iam", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("iam"))
    assert before == after and before > 0


def test_okta_scope_walk_user_to_app(tmp_path):
    """Import then ask_scope: alice -member_of-> SOC Team, alice -assigned_to->
    Splunk SIEM. The walk reaches both, every item cited."""
    db = str(tmp_path / "scope.db")
    okta.main(["import", str(OKTA_FIXTURE), "--namespace", "iam", "--db", db])
    store = SqliteStore(db)
    try:
        scope = ScopeSpec(subjects=[EntityRef(type="user", key="okta-u-001")],
                          expand=["member_of", "assigned_to"], depth=2)
        pack = build_pack(store, AskRequest(
            namespace="iam", scope=scope, budget=4000,
            question="what groups and apps does Alice have access to?"))
        blob = "\n".join(i.text for i in pack.items)
        assert "member_of" in blob or "assigned_to" in blob
        assert pack.items and all(i.citations for i in pack.items)
    finally:
        store.close()


def test_okta_find_path_user_to_app(tmp_path):
    """find_path: alice -assigned_to-> Splunk SIEM, cited."""
    db = str(tmp_path / "path.db")
    okta.main(["import", str(OKTA_FIXTURE), "--namespace", "iam", "--db", db])
    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="iam",
            **{"from": EntityRef(type="user", key="okta-u-001")},
            to=EntityRef(type="app", key="okta-app-001"),
            via=["assigned_to"], depth=2, max_paths=4))
        assert pack.paths, "alice reaches Splunk via assigned_to"
        assert pack.paths[0][0].predicate == "assigned_to"
        assert all(e.cite.observation_id for e in pack.paths[0])
    finally:
        store.close()


def test_okta_schema_registers_predicates():
    reg = okta.schema("iam")
    preds = {p.name for p in reg.predicates}
    assert {"member_of", "assigned_to", "has_role", "mfa_enrolled"} <= preds
    types = {t.name for t in reg.entity_types}
    assert {"user", "group", "app", "admin_role"} <= types


# ------------------------------------------------ cross-IdP fusion test #

def test_entra_and_okta_in_same_namespace_with_scope_walk(tmp_path):
    """Both IdPs feed the same `iam` namespace. A scope walk from a user
    reaches both Entra roles and Okta app assignments, all cited."""
    db = str(tmp_path / "fusion.db")
    entra.main(["import", str(ENTRA_FIXTURE), "--namespace", "iam", "--db", db])
    okta.main(["import", str(OKTA_FIXTURE), "--namespace", "iam", "--db", db])
    store = SqliteStore(db)
    try:
        entra_count = sum(1 for o in store.iter_observations("iam")
                          if o.source == "entra-export")
        okta_count = sum(1 for o in store.iter_observations("iam")
                         if o.source == "okta-export")
        assert entra_count > 0 and okta_count > 0
    finally:
        store.close()
