import pytest

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


def test_seed_plants_a_recorded_correction_not_a_conflict(tmp_path):
    """D-050 demo moment: the contract DB corrects its own earlier hooli
    owner record. `generate` marks the correction with the target's
    event_id; `seed load` resolves it to the observation id (minted at
    load time) and records ClaimIn.supersedes. One source, so no conflict
    item — the initech conflict (two sources) stays the conflict demo."""
    from loom.seed import SUPERSEDES_EVENT, resolve_supersessions
    claims, _ = generate(seed=42)
    corrections = [c for c in claims if SUPERSEDES_EVENT in c.attrs]
    assert len(corrections) == 1 and len(claims) == 592
    fix = corrections[0]
    target = next(c for c in claims if c.event_id == fix.attrs[SUPERSEDES_EVENT])
    assert (fix.subject, fix.predicate, fix.source) == (target.subject, target.predicate, target.source)
    assert fix.subject.key == "hooli" and fix.object == "rlee" and target.object == "mchen"
    assert fix.observed_at > target.observed_at and fix.supersedes is None

    db = tmp_path / "seed.db"
    cmd_load(str(db), seed=42)
    store = SqliteStore(db)
    obs = {o.event_id: o for o in store.observations_for("procurement", EntityRef(type="vendor", key="hooli"))}
    assert target.event_id in obs and fix.event_id in obs
    assert SUPERSEDES_EVENT not in obs[fix.event_id].attrs and obs[fix.event_id].attrs["note"]
    resolved = resolve_supersessions(claims, list(obs.values()))
    assert [c.supersedes for c in resolved] == [obs[target.event_id].id]
    # whether the store persists the field is the store's business (D-050
    # follow-up); when it does, it is exactly this id
    assert obs[fix.event_id].supersedes in (None, obs[target.event_id].id)
    with pytest.raises(ValueError, match="unknown event"):
        resolve_supersessions(claims, [])
    pack = build_pack(store, AskRequest(namespace="procurement", subject=EntityRef(type="vendor", key="hooli"),
                                       question="who owns this contract?", budget=1200))
    assert not any(i.kind == "conflict" for i in pack.items)          # one source: a correction, not a conflict
    assert any("rlee" in i.text for i in pack.items)
    store.close()


def test_load_without_db_uses_the_environment_store(tmp_path, monkeypatch, capsys):
    """`seed load` opens the store LOOM_DB / LOOM_SHARDS / LOOM_BLOB_*
    configure, like the engine; --db is an explicit single-store override."""
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "env.db"))
    monkeypatch.delenv("LOOM_SHARDS", raising=False)
    cmd_load(None, seed=42)
    assert "(env)" in capsys.readouterr().out
    store = SqliteStore(tmp_path / "env.db")
    assert sum(1 for _ in store.iter_artifacts()) >= 5
    store.close()
    monkeypatch.setattr("sys.argv", ["loom.seed", "load", "--db", str(tmp_path / "explicit.db")])
    from loom.seed import main
    main()
    assert (tmp_path / "explicit.db").exists() and "explicit.db" in capsys.readouterr().out


def test_seed_never_prints_a_password():
    from loom.seed import redact_dsn
    assert redact_dsn("postgresql://loom:s3cret@host:5432/loom") == "postgresql://loom:***@host:5432/loom"
    assert redact_dsn("/data/loom.db") == "/data/loom.db"
