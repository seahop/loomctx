"""Export the contracts as JSON Schema for non-Python SDKs.

Usage: docker compose run --rm loom python -m loom.schemas > schemas.json

The Go gateway validates IngestEnvelope; the TypeScript SDK's
`src/contracts.ts` is generated from every root here (D-026). CI checks the
checked-in copy regenerates identically.
"""

import json

from pydantic import TypeAdapter

from .contracts import (
    AnswerRequest,
    AnswerResponse,
    Artifact,
    AskRequest,
    ContextPack,
    Entity,
    ExpandRequest,
    IngestEnvelope,
    Observation,
    SchemaRegistration,
    SemanticSearchResponse,
)

ROOTS = {
    "IngestEnvelope": lambda: TypeAdapter(IngestEnvelope).json_schema(),
    "Observation": Observation.model_json_schema,
    "Entity": Entity.model_json_schema,
    "Artifact": Artifact.model_json_schema,
    "AskRequest": AskRequest.model_json_schema,
    "ExpandRequest": ExpandRequest.model_json_schema,
    "ContextPack": ContextPack.model_json_schema,
    "AnswerRequest": AnswerRequest.model_json_schema,
    "AnswerResponse": AnswerResponse.model_json_schema,
    "SemanticSearchResponse": SemanticSearchResponse.model_json_schema,
    "SchemaRegistration": SchemaRegistration.model_json_schema,
}


def main() -> None:
    print(json.dumps({name: build() for name, build in ROOTS.items()}, indent=2))


if __name__ == "__main__":
    main()
