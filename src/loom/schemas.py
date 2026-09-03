"""Export the contracts as JSON Schema for non-Python SDKs.

Usage: docker compose run --rm loom python -m loom.schemas > schemas.json
"""

import json

from pydantic import TypeAdapter

from .contracts import ContextPack, IngestEnvelope, Observation, SchemaRegistration


def main() -> None:
    out = {
        "IngestEnvelope": TypeAdapter(IngestEnvelope).json_schema(),
        "Observation": Observation.model_json_schema(),
        "ContextPack": ContextPack.model_json_schema(),
        "SchemaRegistration": SchemaRegistration.model_json_schema(),
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
