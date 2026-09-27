import pytest
from pydantic import TypeAdapter, ValidationError

from loomctx.contracts import ClaimIn, DocumentIn, EntityRef, IngestEnvelope

ENVELOPE = TypeAdapter(IngestEnvelope)

CLAIM = {
    "kind": "claim",
    "namespace": "netsec",
    "subject": {"type": "host", "key": "web-01"},
    "predicate": "logged_in_by",
    "object": {"type": "user", "key": "jdoe"},
    "observed_at": "2026-09-01T14:03:00Z",
    "source": "auth-log",
}


def test_claim_envelope_roundtrip():
    parsed = ENVELOPE.validate_python(CLAIM)
    assert isinstance(parsed, ClaimIn)
    assert parsed.object == EntityRef(type="user", key="jdoe")
    assert parsed.confidence == 1.0
    reparsed = ENVELOPE.validate_python(parsed.model_dump(mode="json"))
    assert reparsed == parsed


def test_scalar_object_stays_scalar():
    parsed = ENVELOPE.validate_python({**CLAIM, "object": "fedora-44"})
    assert parsed.object == "fedora-44"
    parsed = ENVELOPE.validate_python({**CLAIM, "object": 443})
    assert parsed.object == 443


def test_document_envelope():
    parsed = ENVELOPE.validate_python(
        {
            "kind": "document",
            "text": "Incident report about web-01.",
            "source": "ir-pipeline",
            "observed_at": "2026-09-02T09:00:00Z",
        }
    )
    assert isinstance(parsed, DocumentIn)


def test_document_requires_exactly_one_body():
    base = {
        "kind": "document",
        "source": "ir-pipeline",
        "observed_at": "2026-09-02T09:00:00Z",
    }
    with pytest.raises(ValidationError):
        ENVELOPE.validate_python(base)
    with pytest.raises(ValidationError):
        ENVELOPE.validate_python({**base, "text": "x", "content_b64": "eA=="})


def test_confidence_bounds():
    with pytest.raises(ValidationError):
        ENVELOPE.validate_python({**CLAIM, "confidence": 1.5})


def test_provenance_needs_a_reference():
    from loomctx.contracts import Provenance
    assert Provenance(artifact_event_id="doc-1").artifact_id is None
    assert Provenance(artifact_id="abc").artifact_event_id is None
    with pytest.raises(ValidationError):
        Provenance(span_start=1)


def test_observed_at_may_not_be_in_the_future():
    """D-046: a forward-dated observation poisons recency ranking; 24 h of
    clock skew is tolerated, a validity window may be scheduled ahead."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="observed_at is in the future"):
        ENVELOPE.validate_python({**CLAIM, "observed_at": (now + timedelta(days=2)).isoformat()})
    with pytest.raises(ValidationError, match="observed_at is in the future"):
        ENVELOPE.validate_python({"kind": "document", "text": "x", "source": "s",
                                  "observed_at": "2099-01-01T00:00:00Z"})
    skewed = ENVELOPE.validate_python({**CLAIM, "observed_at": (now + timedelta(hours=1)).isoformat()})
    assert isinstance(skewed, ClaimIn)
    scheduled = ENVELOPE.validate_python({**CLAIM, "valid_from": "2099-01-01T00:00:00Z",
                                          "valid_to": "2099-02-01T00:00:00Z"})
    assert scheduled.valid_from.year == 2099
