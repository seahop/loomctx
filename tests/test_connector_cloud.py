"""The cloud inventory / config connector (loom.connectors.cloud): parse a
resource export into cited, timestamped inventory claims in a `cloud`
namespace, and prove the walk answers "what is in this subnet / vpc" over the
D-067 path search — an instance reaches its vpc through the config edges,
cited.

The fixtures are REAL exports, not hand-written schemas:

  * `cloud_terraform_state.json` is genuine `terraform show -json` output
    (Terraform 1.9.8), produced by `terraform apply` against a throwaway
    config using ONLY the null / random / local providers (no cloud creds, no
    cloud API calls) in a container, so the JSON — format_version, the
    root/child module tree, `values`, `depends_on` — is genuinely
    Terraform's.
  * `cloud_awsconfig_snapshot.json` / `_t2.json` use the AWS Config
    `configurationItem` shape from AWS's public documentation examples
    (resourceType / resourceId / relationships[] with a relationship name /
    configuration / configurationItemCaptureTime).

Parser edge cases (a bare single item, the `relationshipName` spelling, an
empty export) are exercised with small inline documents."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from loom.connectors import cloud, vulns
from loom.context import find_paths, resolve_scope
from loom.contracts import ClaimIn, EntityRef, PathRequest, ScopeSpec
from loom.store.sqlite import SqliteStore

FIX = Path(__file__).parent / "fixtures"
TFSTATE = FIX / "cloud_terraform_state.json"
AWSCONFIG = FIX / "cloud_awsconfig_snapshot.json"
AWSCONFIG_T2 = FIX / "cloud_awsconfig_snapshot_t2.json"


def _claims(envs):
    return [e for e in envs if isinstance(e, ClaimIn)]


def _by_subject(claims, key):
    out: dict = {}
    for c in claims:
        if c.subject.key == key:
            out.setdefault(c.predicate, []).append(c)
    return out


# ------------------------------------------------------ terraform: real fixture #

def test_terraform_parses_resources_attrs_depends_on_and_module():
    envs = list(cloud.to_envelopes(TFSTATE.read_text(), "terraform", "cloud"))
    docs = [e for e in envs if not isinstance(e, ClaimIn)]
    claims = _claims(envs)
    assert len(docs) == 1 and docs[0].event_id.endswith(":snapshot")
    # every claim cites the snapshot document (D-039)
    assert all(c.provenance and c.provenance.artifact_event_id == docs[0].event_id for c in claims)

    # every managed resource, root AND child module, is an entity keyed by address
    subjects = {c.subject.key for c in claims}
    assert {"random_id.vpc", "random_pet.subnet", "null_resource.instance",
            "local_file.inventory", "module.net.random_pet.gateway"} <= subjects

    # a resource_type anchor + scalar attribute claims
    vpc = _by_subject(claims, "random_id.vpc")
    assert vpc["resource_type"][0].object == "random_id"
    assert any(c.predicate == "attr:byte_length" and c.object == 8 for c in claims
               if c.subject.key == "random_id.vpc")

    # explicit depends_on becomes depends_on edges (real terraform state field)
    inst = _by_subject(claims, "null_resource.instance")
    dep_targets = {c.object.key for c in inst["depends_on"]}
    assert {"random_pet.subnet", "random_id.vpc", "module.net.random_pet.gateway"} <= dep_targets


def test_terraform_reference_edge_from_an_attribute_value():
    """null_resource.instance.triggers.subnet == random_pet.subnet.id, so the
    referenced id becomes a resolved reference edge. The target resource is a
    generic `resource` (a null_resource, not a typed subnet), so the edge is
    the generic `references` — the type-constrained in_subnet is reserved for
    a target that is actually a subnet entity (a real aws_subnet reference)."""
    claims = _claims(cloud.to_envelopes(TFSTATE.read_text(), "terraform", "cloud"))
    inst = _by_subject(claims, "null_resource.instance")
    refs = inst.get("references", [])
    assert any(c.object == EntityRef(type="resource", key="random_pet.subnet")
               and c.attrs["via"] == "subnet" for c in refs)


# ------------------------------------------------------ aws config: real fixture #

def test_awsconfig_parses_resources_and_relationships():
    claims = _claims(cloud.to_envelopes(AWSCONFIG.read_text(), "awsconfig", "cloud"))
    # entities keyed by resource id, typed small-and-generic
    types = {(c.subject.type, c.subject.key) for c in claims}
    assert ("vpc", "vpc-0abc111111aaaa111") in types
    assert ("subnet", "subnet-0def222222bbbb222") in types
    assert ("security_group", "sg-0aa333333cccc333") in types
    assert ("resource", "i-0123456789abcdef0") in types      # instance -> generic resource

    inst = _by_subject(claims, "i-0123456789abcdef0")
    # relationships[] -> edges
    assert inst["in_subnet"][0].object == EntityRef(type="subnet", key="subnet-0def222222bbbb222")
    assert inst["in_vpc"][0].object == EntityRef(type="vpc", key="vpc-0abc111111aaaa111")
    assert inst["attached_to"][0].object == EntityRef(type="security_group", key="sg-0aa333333cccc333")
    # config scalars as claims; the capture time is observed_at
    all_inst = sum(inst.values(), [])
    assert any(c.predicate == "attr:instanceType" and c.object == "t3.micro" for c in all_inst)
    assert inst["in_subnet"][0].observed_at == datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)
    # every resource ties to its cloud account
    assert inst["in_account"][0].object == EntityRef(type="cloud_account", key="123456789012")

    sg = _by_subject(claims, "sg-0aa333333cccc333")
    ingress = {c.object for c in sg["allows_ingress"]}
    assert ingress == {"tcp/22", "tcp/443"}


BARE_ITEM = """{
  "resourceType": "AWS::EC2::Subnet",
  "resourceId": "subnet-single",
  "awsRegion": "eu-west-1",
  "accountId": "999900001111",
  "configurationItemCaptureTime": "2026-09-21T00:00:00Z",
  "relationships": [
    {"resourceId": "vpc-single", "resourceType": "AWS::EC2::VPC", "relationshipName": "Is contained in Vpc"}
  ],
  "configuration": {"cidrBlock": "10.9.0.0/24"}
}"""


def test_awsconfig_bare_single_item_and_relationshipName_spelling():
    claims = _claims(cloud.to_envelopes(BARE_ITEM, "awsconfig", "cloud"))
    sub = _by_subject(claims, "subnet-single")
    # a single bare item (not wrapped in configurationItems) and the API's
    # `relationshipName` spelling both parse
    assert sub["in_vpc"][0].object == EntityRef(type="vpc", key="vpc-single")
    assert sub["resource_type"][0].object == "AWS::EC2::Subnet"


# ------------------------------------------------------------------ drift / time #

def test_drift_opened_port_recorded_as_history(tmp_path):
    """A later snapshot where the security group opened tcp/3389 is recorded
    as new history at the new capture time, not an overwrite of the old rule
    set — both the before and after states remain, queryable by as_of."""
    db = str(tmp_path / "drift.db")
    cloud.main(["import", str(AWSCONFIG), "--format", "awsconfig", "--namespace", "cloud", "--db", db])

    sg = EntityRef(type="security_group", key="sg-0aa333333cccc333")
    store = SqliteStore(db)
    before = [o for o in store.observations_for("cloud", sg) if o.predicate == "allows_ingress"]
    store.close()
    assert {o.object for o in before} == {"tcp/22", "tcp/443"}       # no 3389 yet

    cloud.main(["import", str(AWSCONFIG_T2), "--format", "awsconfig", "--namespace", "cloud", "--db", db])
    store = SqliteStore(db)
    try:
        after = [o for o in store.observations_for("cloud", sg) if o.predicate == "allows_ingress"]
        objs = {o.object for o in after}
        assert "tcp/3389" in objs                                   # the opened port appeared
        rdp = [o for o in after if o.object == "tcp/3389"]
        assert len(rdp) == 1
        assert rdp[0].observed_at == datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)  # the later snapshot
        # the old rules are NOT overwritten: tcp/22 is observed at BOTH captures
        port22 = sorted(o.observed_at for o in after if o.object == "tcp/22")
        assert len(port22) == 2 and port22[0] == datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)
    finally:
        store.close()


def test_reimport_is_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    for fixture, fmt in ((TFSTATE, "terraform"), (AWSCONFIG, "awsconfig")):
        cloud.main(["import", str(fixture), "--format", fmt, "--namespace", "cloud", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("cloud"))
    for fixture, fmt in ((TFSTATE, "terraform"), (AWSCONFIG, "awsconfig")):
        cloud.main(["import", str(fixture), "--format", fmt, "--namespace", "cloud", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("cloud"))
    assert before == after and before > 0


# ------------------------------------------------------------------- edge cases #

def test_empty_and_invalid_exports():
    # an empty terraform state (no resources) yields only the snapshot document
    empty_tf = '{"format_version":"1.0","values":{"root_module":{}}}'
    envs = list(cloud.to_envelopes(empty_tf, "terraform", "cloud"))
    assert len(_claims(envs)) == 0 and len(envs) == 1
    # an empty AWS Config snapshot likewise
    envs = list(cloud.to_envelopes('{"configurationItems": []}', "awsconfig", "cloud"))
    assert len(_claims(envs)) == 0 and len(envs) == 1
    # neither shape -> a clear error, not a silent empty parse
    with pytest.raises(ValueError):
        list(cloud.to_envelopes('{"nope": true}', "terraform", "cloud"))
    with pytest.raises(ValueError):
        list(cloud.to_envelopes('{"nope": true}', "awsconfig", "cloud"))
    with pytest.raises(ValueError):
        list(cloud.to_envelopes("{}", "unknownfmt", "cloud"))


def test_schema_registers_small_generic_types_and_containment():
    reg = cloud.schema("cloud")
    ents = {e.name for e in reg.entity_types}
    assert ents == {"resource", "vpc", "subnet", "security_group", "cloud_account"}
    preds = {p.name: p for p in reg.predicates}
    assert {"resource_type", "in_subnet", "in_vpc", "in_account", "attached_to",
            "depends_on", "references", "allows_ingress", "member_of"} == set(preds)
    # the containment edges a scope with no explicit expand will follow (D-024)
    for pred in ("in_subnet", "in_vpc", "in_account", "member_of"):
        assert preds[pred].containment is True
    assert reg.strict is False


def test_import_exits_nonzero_when_the_engine_refuses(monkeypatch):
    """D-063 / S-36: a loader that saw any refusal must not exit 0."""
    from loom import ingest
    monkeypatch.setattr(vulns, "register", lambda *a, **k: None)

    def refusing(url, lines, size, key, timeout=60.0):
        n = sum(1 for _ in lines)
        return {"total": n, "recorded": n - 2, "accepted": 0, "rejected": 2}

    monkeypatch.setattr(ingest, "post_batches", refusing)
    with pytest.raises(SystemExit) as exc:
        cloud.main(["import", str(AWSCONFIG), "--format", "awsconfig", "--namespace", "cloud",
                    "--url", "http://loom.invalid"])
    assert exc.value.code not in (0, None)
    assert "2" in str(exc.value.code) and "refused" in str(exc.value.code)


# ------------------------------------------------------- the walk (D-067 / scope) #

def test_instance_reaches_its_vpc_through_the_subnet_cited(tmp_path):
    """"what is this instance in?" — import the AWS Config snapshot and assert
    the instance reaches the vpc through the config edges, cited: over
    find_path (an instance -> subnet -> vpc edge sequence exists) and over the
    scope walk (expanding the containment edges reaches the vpc)."""
    db = str(tmp_path / "walk.db")
    cloud.main(["import", str(AWSCONFIG), "--format", "awsconfig", "--namespace", "cloud", "--db", db])

    instance = EntityRef(type="resource", key="i-0123456789abcdef0")
    vpc = EntityRef(type="vpc", key="vpc-0abc111111aaaa111")
    subnet = EntityRef(type="subnet", key="subnet-0def222222bbbb222")

    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="cloud", **{"from": instance}, to=vpc,
            via=["in_subnet", "in_vpc"], depth=2))
        assert pack.paths, "the instance must reach its vpc through the config edges"
        # the instance -> subnet -> vpc path exists and passes through the subnet
        multihop = [p for p in pack.paths if len(p) == 2]
        assert multihop, "the two-hop path through the subnet must be present"
        best = multihop[0]
        assert [e.predicate for e in best] == ["in_subnet", "in_vpc"]
        nodes = {(e.subject.type, e.subject.key) for e in best} | {
            (e.object.type, e.object.key) for e in best if isinstance(e.object, EntityRef)}
        assert (subnet.type, subnet.key) in nodes and (vpc.type, vpc.key) in nodes
        # every hop is cited (hard constraint 3) and sourced to the connector
        assert all(e.cite.observation_id for e in best)
        assert all(e.source == "cloud" for e in best)

        # the scope walk reaches the vpc too (ask_scope over the containment edges)
        reached = resolve_scope(store, "cloud", ScopeSpec(
            subjects=[instance], expand=["in_subnet", "in_vpc"], depth=2))
        assert vpc in reached and subnet in reached
    finally:
        store.close()
