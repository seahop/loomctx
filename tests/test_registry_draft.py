"""Schema drafting (D-106): `python -m loomctx.registry draft SAMPLE` reads a
sample export and proposes a SchemaRegistration for review. Small inline
samples plus the connector fixtures; nothing here touches a store."""

import json
from pathlib import Path

import pytest

from loomctx import registry, schema_draft
from loomctx.connectors import entra, ldap, okta
from loomctx.contracts import SchemaRegistration

FIXTURES = Path(__file__).parent / "fixtures"


def _envelope_lines(envs) -> str:
    return "".join(e.model_dump_json(exclude_none=True) + "\n" for e in envs)


def _draft(text: str, path: str = "sample", **kw) -> schema_draft.Draft:
    return schema_draft.draft([(path, text)], **kw)


def _preds(d: schema_draft.Draft) -> dict:
    return {p.name: p for p in d.registration.predicates}


def _valid(d: schema_draft.Draft) -> SchemaRegistration:
    return SchemaRegistration.model_validate_json(d.registration.model_dump_json())


def _overlap(d: schema_draft.Draft, hand: SchemaRegistration) -> tuple[float, float]:
    drafted = _preds(d)
    hp = {p.name: p for p in hand.predicates}
    both = set(hp) & set(drafted)
    flags = ("containment", "node_status", "label", "display")
    agree = sum(all(getattr(hp[n], f) == getattr(drafted[n], f) for f in flags) for n in both)
    return len(both) / len(hp), agree / len(both)


# ------------------------------------------------------------------ naming #

@pytest.mark.parametrize("raw,want", [
    ("sAMAccountName", "sam_account_name"),
    ("userPrincipalName", "user_principal_name"),
    ("msDS-AllowedToDelegateTo", "ms_ds_allowed_to_delegate_to"),
    ("nTSecurityDescriptor", "nt_security_descriptor"),
    ("@odata.type", "odata_type"),
    ("oauth2PermissionGrants", "oauth2_permission_grants"),
])
def test_snake(raw, want):
    assert schema_draft.snake(raw) == want


@pytest.mark.parametrize("raw,want", [
    ("service_principals", "service_principal"), ("policies", "policy"),
    ("addresses", "address"), ("status", "status"), ("class", "class"),
])
def test_singular(raw, want):
    assert schema_draft.singular(raw) == want


# --------------------------------------------------------------- envelopes #

def test_envelopes_from_okta_connector_reproduce_its_registration():
    text = _envelope_lines(okta.okta_to_envelopes(
        (FIXTURES / "okta_directory.json").read_text(), "iam"))
    d = _draft(text, "okta.ndjson")
    reg = _valid(d)
    assert reg.namespace == "iam" and not reg.strict
    p = _preds(d)
    assert p["member_of"].containment and p["member_of"].object_types == ["group"]
    assert p["assigned_to"].object_types == ["app"] and not p["assigned_to"].containment
    assert p["login"].label and p["login"].display
    assert p["mail"].label and not p["mail"].display
    assert p["status"].node_status and p["enabled"].node_status
    assert not p["department"].label and p["department"].object_types == []
    assert sum(q.display for q in reg.predicates) == 1
    matched, flags = _overlap(d, okta.schema("iam"))
    assert matched >= 0.7 and flags == 1.0


def test_envelopes_from_entra_connector_pick_the_upn_for_display():
    text = _envelope_lines(entra.entra_to_envelopes(
        (FIXTURES / "entra_directory.json").read_text(), "iam"))
    d = _draft(text)
    p = _preds(d)
    assert p["upn"].display and p["name"].label and p["mail"].label
    assert not p["security_enabled"].node_status     # only a status *name* is a status
    assert p["enabled"].node_status
    assert "directory_role" in p["has_role"].object_types
    matched, flags = _overlap(d, entra.schema("iam"))
    assert matched >= 0.7 and flags == 1.0


def test_envelopes_from_ldap_connector():
    text = _envelope_lines(ldap.ldif_to_envelopes((FIXTURES / "corp_ad.ldif").read_text(), "ad"))
    d = _draft(text)
    p = _preds(d)
    assert p["contains"].containment and p["member_of"].containment
    assert p["member_of"].object_types == ["group"]
    assert p["principal"].display and p["sam"].label and p["dn_name"].label
    assert p["enabled"].node_status and not p["kerberoastable"].node_status
    matched, flags = _overlap(d, ldap.schema("ad"))
    assert matched >= 0.6 and flags == 1.0


def test_a_predicate_reaching_many_types_stays_open():
    def claim(stype, key, obj):
        return json.dumps({"subject": {"type": stype, "key": key}, "predicate": "has_ace",
                           "object": obj, "observed_at": "2026-01-01T00:00:00Z", "source": "s"})
    lines = [claim("group", "g", {"type": t, "key": "k"})
             for t in ("user", "computer", "group", "domain")]
    lines.append(claim("user", "u", {"type": "group", "key": "g"}).replace("has_ace", "member_of"))
    d = _draft("\n".join(lines))
    p = _preds(d)
    assert p["has_ace"].object_types == [] and not p["has_ace"].containment
    assert p["member_of"].object_types == ["group"]
    assert any("`has_ace` points at 4 entity types" in n for n in d.notes)


def test_envelope_mixed_objects_and_documents_are_noted():
    lines = [
        {"subject": {"type": "host", "key": "web-01"}, "predicate": "runs",
         "object": {"type": "service", "key": "nginx"}, "observed_at": "2026-01-01T00:00:00Z",
         "source": "s", "namespace": "lab"},
        {"subject": {"type": "host", "key": "web-02"}, "predicate": "runs", "object": "nginx",
         "observed_at": "2026-01-01T00:00:00Z", "source": "s", "namespace": "lab"},
        {"kind": "document", "text": "hi", "source": "s", "observed_at": "2026-01-01T00:00:00Z"},
    ]
    d = _draft("\n".join(json.dumps(x) for x in lines), "x.ndjson", namespace="override")
    assert d.registration.namespace == "override"
    assert _preds(d)["runs"].object_types == []
    assert any("mixes entity references" in n for n in d.notes)
    assert any("document envelopes skipped" in n for n in d.notes)
    assert {t.name for t in d.registration.entity_types} == {"host", "service"}


# ----------------------------------------------------------------- records #

JSON_SAMPLE = {
    "users": [
        {"id": f"u{i}", "displayName": f"User {i}", "userPrincipalName": f"user{i}@corp.example",
         "accountEnabled": i != 2, "manager": {"id": "u0"} if i else None,
         "lastLogin": "2026-09-01T00:00:00Z"}
        for i in range(4)
    ],
    "groups": [
        {"id": "g1", "displayName": "admins", "type": "SECURITY",
         "members": [{"id": "u1"}, {"id": "u2"}], "owners": [{"id": "u0"}], "tags": []},
        {"id": "g2", "displayName": "ops", "type": "SECURITY",
         "members": [{"id": "u3"}, {"id": "g1"}], "owners": [{"id": "u0"}], "tags": []},
    ],
    "apps": [{"id": "a1", "label": "Payroll", "status": "ACTIVE"},
             {"id": "a2", "label": "Wiki", "status": "INACTIVE"}],
    "appAssignments": [
        {"id": "x1", "principalId": "u1", "appId": "a1", "scope": "USER"},
        {"id": "x2", "principalId": "g2", "appId": "a2", "scope": "GROUP"},
        {"id": "x3", "principalId": "u3", "appId": "a1", "scope": "USER"},
    ],
    "settings": {"tenant": "corp"},
}


def test_json_records_infer_kinds_refs_and_flags():
    d = _draft(json.dumps(JSON_SAMPLE), "export.json")
    reg = _valid(d)
    kinds = {t.name for t in reg.entity_types}
    assert kinds == {"user", "group", "app"}          # the assignment rows are an edge
    p = _preds(d)
    assert p["member_of"].containment
    assert p["member_of"].object_types == ["group"]   # drafted from the member's side
    assert p["owner_of"].object_types == ["group"] and not p["owner_of"].containment
    assert p["manager"].object_types == ["user"]
    assert p["app_assignment"].object_types == ["app"]
    assert p["upn"].label and p["upn"].display        # house style for userPrincipalName
    assert p["name"].label and not p["name"].display  # displayName and an app's label
    assert p["enabled"].node_status and p["status"].node_status
    assert p["group_type"].object_types == []         # a group's `type` is a scalar
    assert p["last_login"].description.startswith("last login: timestamp")
    assert "id" not in p and "tags" not in p
    notes = "\n".join(d.notes)
    assert "`app_assignment` records look like assignment rows" in notes
    assert "`tags` on group is empty in every record" in notes
    assert "top-level `settings` is not an array of records" in notes


def test_keep_names_keeps_source_names():
    p = _preds(_draft(json.dumps(JSON_SAMPLE), "export.json", keep_names=True))
    assert "user_principal_name" in p and "upn" not in p
    assert p["user_principal_name"].display and p["display_name"].label


def test_ndjson_records_with_a_kind_field():
    rows = [
        {"kind": "host", "key": "web-01", "hostname": "web-01.corp.example", "state": "up",
         "parent": "net-a"},
        {"kind": "host", "key": "web-02", "hostname": "web-02.corp.example", "state": "down",
         "parent": "net-a", "vendor_id": "zz-unknown-99"},
        {"kind": "network", "key": "net-a", "name": "dmz"},
    ]
    d = _draft("\n".join(json.dumps(r) for r in rows), "inv.ndjson")
    p = _preds(d)
    assert {t.name for t in d.registration.entity_types} == {"host", "network"}
    assert p["contains"].containment and p["contains"].object_types == ["host"]
    assert p["hostname"].label and p["state"].node_status
    assert "kind" not in p and "key" not in p
    assert any("`vendor_id` looks like an id" in n for n in d.notes)


LDIF = """\
version: 1
# 2026-09-20T09:00:00Z
dn: DC=lab,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
name: lab.local

dn: OU=Staff,DC=lab,DC=local
objectClass: top
objectClass: organizationalUnit
name: Staff

dn: CN=Ann,OU=Staff,DC=lab,DC=local
objectClass: top
objectClass: person
objectClass: user
name: Ann
sAMAccountName: ann
userPrincipalName: ann@lab.local
userAccountControl: 512
memberOf: CN=Admins,OU=Staff,DC=lab,DC=local
nTSecurityDescriptor:: AQAEgAAAAAAAAAAAAAAAABQAAAAEAAgAAAAAAA==

dn: CN=Bob,OU=Staff,DC=lab,DC=local
objectClass: top
objectClass: person
objectClass: user
name: Bob
sAMAccountName: bob
userPrincipalName: bob@lab.local
userAccountControl: 514
description: a long
  folded line

dn: CN=Admins,OU=Staff,DC=lab,DC=local
objectClass: top
objectClass: group
name: Admins
sAMAccountName: admins
member: CN=Bob,OU=Staff,DC=lab,DC=local
"""


def test_parse_ldif_folds_and_decodes():
    entries = schema_draft.parse_ldif(LDIF)
    assert len(entries) == 5
    bob = entries[3]
    assert bob["description"] == ["a long folded line"]
    sd = entries[2]["nTSecurityDescriptor"][0]
    assert isinstance(sd, schema_draft.Binary)


def test_ldif_infers_kinds_dn_containment_and_membership():
    d = _draft(LDIF, "export.ldif", namespace="ad")
    reg = _valid(d)
    assert {t.name for t in reg.entity_types} == {"domain", "organizational_unit", "user", "group"}
    p = _preds(d)
    assert p["member_of"].object_types == ["group"] and p["member_of"].containment
    assert p["contains"].containment
    assert p["sam"].label and p["upn"].display
    assert "dn_name" not in p                         # the DN is these records' key
    assert p["user_account_control"].object_types == []
    notes = "\n".join(d.notes)
    assert "binary attributes skipped: nTSecurityDescriptor" in notes
    assert "`user_account_control` is an integer that looks like a bit field" in notes


# --------------------------------------------------------------------- CLI #

def test_cli_writes_a_valid_draft_and_notes(tmp_path, capsys):
    sample = tmp_path / "export.json"
    sample.write_text(json.dumps(JSON_SAMPLE))
    out, notes = tmp_path / "draft.json", tmp_path / "draft.notes.txt"
    registry.main(["draft", str(sample), "--namespace", "corp", "--out", str(out),
                   "--notes", str(notes)])
    reg = SchemaRegistration.model_validate_json(out.read_text())
    assert reg.namespace == "corp" and reg.predicates
    err = capsys.readouterr().err
    assert err.startswith("# draft schema for namespace 'corp'")
    assert "nothing was registered" in err
    assert notes.read_text() == err


def test_cli_stdout_and_forced_format(tmp_path, capsys):
    sample = tmp_path / "export.txt"
    sample.write_text(LDIF)
    registry.main(["draft", str(sample), "--format", "ldif"])
    out = capsys.readouterr().out
    assert "member_of" in out
    SchemaRegistration.model_validate_json(out)


def test_cli_empty_sample_exits_2(tmp_path):
    sample = tmp_path / "empty.json"
    sample.write_text("[]")
    with pytest.raises(SystemExit) as exc:
        registry.main(["draft", str(sample)])
    assert exc.value.code == 2
