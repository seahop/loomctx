"""Export the contracts as JSON Schema (default) or the HTTP API as OpenAPI.

Usage:
    docker compose run --rm loom python -m loom.schemas          > contracts/schemas.json
    docker compose run --rm loom python -m loom.schemas openapi  > contracts/openapi.json

The OpenAPI document (D-034) is what any language's generator consumes
(`openapi-generator-cli generate -g java|csharp|go|rust|kotlin|php ...`);
CI regenerates both files and fails on drift.

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
    IngestBatchResponse,
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
    "IngestBatchResponse": IngestBatchResponse.model_json_schema,
}


def openapi() -> dict:
    from .api.http import app

    doc = app.openapi()
    doc["info"]["description"] = (
        "Loom context engine HTTP API. Generated from the FastAPI app; the "
        "Pydantic contracts in src/loom/contracts.py are the source of truth."
    )
    return doc


def main() -> None:
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "openapi":
        print(json.dumps(openapi(), indent=2, sort_keys=True))
        return
    print(json.dumps({name: build() for name, build in ROOTS.items()}, indent=2))


if __name__ == "__main__":
    main()
