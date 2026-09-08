from loom.context import build_pack
from loom.contracts import AskRequest, EntityRef
from loom.seed import generate, cmd_load
from loom.store.sqlite import SqliteStore


def test_generate_is_deterministic():
    claims_a, docs_a = generate(seed=42)
    claims_b, docs_b = generate(seed=42)
    assert claims_a == claims_b
    assert docs_a == docs_b


def test_generate_has_volume_and_variety():
    claims, docs = generate()
    assert len(claims) > 500
    assert len(docs) >= 5
    namespaces = {c.namespace for c in claims}
    assert namespaces == {"netsec", "procurement"}
    predicates = {c.predicate for c in claims}
    assert {"logged_in_by", "assigned_to", "runs_os", "invoiced_amount",
            "contract_owner"} <= predicates
    # scalar and entity objects both present
    assert any(isinstance(c.object, EntityRef) for c in claims)
    assert any(not isinstance(c.object, EntityRef) for c in claims)
    # both document body kinds present
    assert any(d.text for d in docs) and any(d.content_b64 for d in docs)


def test_load_twice_does_not_double_the_corpus(tmp_path):
    """H-F2: a rehearsal that re-runs `seed load` keeps every documented number."""
    db = tmp_path / "seed.db"
    cmd_load(str(db), seed=42)
    cmd_load(str(db), seed=42)
    store = SqliteStore(db)
    claims, docs = generate(seed=42)
    total = sum(1 for _ in store.iter_observations())
    assert total == len(claims)
    assert sum(1 for _ in store.iter_artifacts()) == len(docs)
    store.close()


def test_load_then_ask_the_demo_questions(tmp_path):
    db = tmp_path / "seed.db"
    cmd_load(str(db), seed=42)
    store = SqliteStore(db)

    # the planted conflict about web-01's OS surfaces
    pack = build_pack(store, AskRequest(
        namespace="netsec",
        subject=EntityRef(type="host", key="web-01"),
        question="what operating system does this run?", budget=1200,
    ))
    assert any(i.kind == "conflict" and "runs_os" in i.text for i in pack.items)

    # the IP lease history is visible from the IP itself
    pack = build_pack(store, AskRequest(
        namespace="netsec",
        subject=EntityRef(type="ip", key="10.0.4.7"),
        question="which host was this assigned to?", budget=1200,
    ))
    facts = " | ".join(i.text for i in pack.items)
    assert "web-01" in facts and "laptop-17" in facts

    # procurement namespace answers its own questions
    pack = build_pack(store, AskRequest(
        namespace="procurement",
        subject=EntityRef(type="vendor", key="initech"),
        question="who owns this contract?", budget=1200,
    ))
    assert any(i.kind == "conflict" and "contract_owner" in i.text
               for i in pack.items)
    store.close()


def test_seed_never_prints_a_password():
    from loom.seed import redact_dsn
    assert redact_dsn("postgresql://loom:s3cret@host:5432/loom") == "postgresql://loom:***@host:5432/loom"
    assert redact_dsn("/data/loom.db") == "/data/loom.db"
