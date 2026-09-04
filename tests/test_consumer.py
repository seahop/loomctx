from loom.consumer import handle_message
from loom.contracts import EntityRef
from loom.store.sqlite import SqliteStore

CLAIM = b"""{
  "kind": "claim",
  "subject": {"type": "host", "key": "web-01"},
  "predicate": "logged_in_by",
  "object": {"type": "user", "key": "jdoe"},
  "observed_at": "2026-09-01T14:03:00Z",
  "source": "auth-log"
}"""

DOCUMENT = (b'{"kind": "document", "text": "report", "source": "ir",'
            b' "observed_at": "2026-09-02T09:00:00Z"}')


def test_claim_message_is_recorded(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, CLAIM) == "recorded"
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1 and obs[0].source == "auth-log"


def test_document_message_is_accepted(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, DOCUMENT) == "accepted"


def test_poison_message_is_skipped_not_raised(tmp_path):
    store = SqliteStore(tmp_path / "c.db")
    assert handle_message(store, b"{not json") == "skipped"
    assert handle_message(store, b'{"kind": "claim"}') == "skipped"


def test_batch_mixes_kinds_and_survives_poison(tmp_path):
    from loom.consumer import handle_batch

    store = SqliteStore(tmp_path / "c.db")
    counts = handle_batch(store, [CLAIM, CLAIM, DOCUMENT, b"{poison"])
    assert counts == {"recorded": 2, "accepted": 1, "skipped": 1}
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 2
