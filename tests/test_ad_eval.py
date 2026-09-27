"""The synthetic AD generator (loomctx.connectors.ad_gen) and the object-level
reachability benchmark (loomctx.ad_eval): the generator is deterministic and
emits LDIF the raw-LDAP connector parses; a planted chain is recovered with
every edge cited; a decoy dead-end is not reported as connecting; and the
whole harness runs end to end on a small scale into a temp SQLite store. No
network — the scripted reader is the metric."""

import pytest

from loomctx import ad_eval
from loomctx.connectors import ad_gen
from loomctx.store.sqlite import SqliteStore


# ------------------------------------------------------------- generator #

def test_generator_is_deterministic():
    a_ldif, a_truth = ad_gen.generate(7, "small")
    b_ldif, b_truth = ad_gen.generate(7, "small")
    assert a_ldif == b_ldif
    assert a_truth == b_truth
    # a different seed changes the directory
    c_ldif, _ = ad_gen.generate(8, "small")
    assert c_ldif != a_ldif


def test_generator_emits_parseable_ldif_with_the_planted_shape():
    from loomctx.connectors import ldap
    ldif, truth = ad_gen.generate(7, "small")
    entries, export_at = ldap.parse_ldif(ldif)
    assert export_at is not None and len(entries) == truth["counts"]["objects"]
    # the planted chains and decoys are present in the promised buckets
    hops = sorted(c["hops"] for c in truth["chains"])
    assert 2 in hops and 3 in hops and 4 in hops
    reasons = {d["reason"] for d in truth["decoys"]}
    assert reasons == {"non_transitive_trust", "sid_filtered_trust", "disabled_principal"}
    # every planted edge is a real directory edge once decoded
    # _obs_edge_key reads subject/predicate/object/attrs, which a ClaimIn also has
    envs = list(ldap.ldif_to_envelopes(ldif, "ad"))
    keys = {ad_eval._obs_edge_key(e) for e in envs
            if e.predicate in ad_eval.CHAIN_PREDICATES}
    for chain in truth["chains"] + truth["decoys"]:
        for edge in chain["edges"]:
            assert ad_eval._truth_edge_key(edge) in keys, (chain["id"], edge)


# ------------------------------------------------------------ end to end #

@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    ldif, truth = ad_gen.generate(7, "small")
    db = str(tmp_path_factory.mktemp("ad") / "ad.db")
    store = SqliteStore(db)
    stats = ad_eval.load_ldif(store, ldif, "ad")
    index = ad_eval.build_index(store, "ad")
    yield store, truth, index, stats
    store.close()


def test_import_populates_the_store(loaded):
    store, truth, index, stats = loaded
    assert stats["objects"] == truth["counts"]["objects"]
    assert index.total_observations > 0
    assert index.total_entities >= truth["counts"]["users"]


def test_planted_3hop_chain_recovered_and_cited_at_budget_3000(loaded):
    store, truth, index, _ = loaded
    chain = next(c for c in truth["chains"] if c["hops"] == 3)
    walk = ad_eval.build_chain_packs(store, "ad", chain, budget=3000)
    row = ad_eval.score_chain(chain, walk, index)
    assert row["connects"] is True, row
    # every edge present AND backed by a real cited observation id
    for edge in row["edges"]:
        assert edge["present"] and edge["cited_ids"], edge


def test_4hop_cross_domain_chain_recovered(loaded):
    store, truth, index, _ = loaded
    chain = next(c for c in truth["chains"] if c["hops"] == 4)
    walk = ad_eval.build_chain_packs(store, "ad", chain, budget=4000)
    assert walk.scope_calls == 2                  # depth cap forces a re-anchor
    row = ad_eval.score_chain(chain, walk, index)
    assert row["connects"] is True, row


def test_decoy_dead_ends_are_not_reported_as_connecting(loaded):
    store, truth, index, _ = loaded
    for decoy in truth["decoys"]:
        walk = ad_eval.build_chain_packs(store, "ad", decoy, budget=3000)
        row = ad_eval.score_decoy(decoy, walk, index)
        # the disqualifying fact is surfaced and cited, so the reader excludes it
        assert row["excluded"] is True, row
        assert row["connects"] is False, row
        assert row["disqualifier_cited"] is True, row


def test_harness_runs_end_to_end_and_summarizes(loaded):
    store, truth, index, _ = loaded
    results = ad_eval.evaluate(store, "ad", truth, (1500, 3000), index)
    summary = ad_eval.summarize(results, index)
    assert summary["total_entities"] == index.total_entities
    # at the higher budget every planted chain is recovered and no decoy leaks
    top = summary["per_budget"][3000]
    got, total = top["path_recall_all"]
    assert got == total and total == len(truth["chains"])
    ex, dtot = top["decoy_excluded"]
    assert ex == dtot and dtot == len(truth["decoys"])
    assert top["edge_precision"] == 1.0
    # the "sorted through this much" number is real: the walk gathered a small
    # slice of a much larger store
    assert 0 < top["gathered_mean"] < index.total_entities
    table = ad_eval.markdown(summary, {"date": "2026-09-26", "namespace": "ad",
                                       "scale": "small", "seed": 7,
                                       "counts": truth["counts"]})
    assert "path-recall" in table and "3-hop recall" in table


def test_cli_report_redacts_a_store_dsn_password(monkeypatch, tmp_path):
    """The report's `store` line must not carry a DSN password (as S-45 in
    retrieval_eval): main() redacts it before markdown() prints it."""
    captured = {}
    ldif, truth = ad_gen.generate(7, "tiny")
    truth_path = tmp_path / "t.json"
    import json
    truth_path.write_text(json.dumps({**truth, "chains": [], "decoys": []}))
    db = str(tmp_path / "r.db")
    store = SqliteStore(db)
    ad_eval.load_ldif(store, ldif, "ad")
    store.close()
    monkeypatch.setattr("loomctx.store.factory.store_from_url", lambda url: SqliteStore(db))
    real_md = ad_eval.markdown

    def spy(summary, meta):
        captured["meta"] = meta
        return real_md(summary, meta)

    monkeypatch.setattr(ad_eval, "markdown", spy)
    ad_eval.main(["--db", "postgresql://loomctx:s3cret@db:5432/loomctx", "--truth", str(truth_path),
                  "--budgets", "1500", "--quiet", "--out", str(tmp_path / "r.md")])
    assert "s3cret" not in captured["meta"]["store"]
    assert "s3cret" not in (tmp_path / "r.md").read_text()


def test_blind_mode_knows_only_the_endpoints(loaded):
    """S-51: the blind walk is anchored only at the two named endpoints over
    the fixed predicate set; decoys land in exactly one of three outcomes
    (a walk that surfaced nothing no longer counts as 'excluded')."""
    store, truth, index, _ = loaded
    results = ad_eval.evaluate(store, "ad", truth, (3000,), index, blind=True)
    b = results[3000]
    assert len(b.path_rows) == len(truth["chains"]) + len(truth["decoys"])
    summary = ad_eval.summarize(results, index)
    top = summary["per_budget"][3000]
    assert sum(top["decoy_outcomes"].values()) == len(truth["decoys"])
    assert sum(top["find_path"]["decoys"].values()) == len(truth["decoys"])
    got, total = top["find_path"]["all"]
    assert total == len(truth["chains"]) and got > 0
    table = ad_eval.markdown_blind(summary, {"date": "2026-09-26", "namespace": "ad",
                                             "scale": "small", "seed": 7,
                                             "counts": truth["counts"]})
    assert "Blind" in table and "find_path" in table and "| Edge precision |" not in table
