#!/usr/bin/env bash
# The scale shape end to end, in compose: device -> lb :8081 -> 2 gateways -> NATS JetStream
# -> writer consumer -> store -> engine :8000. One claim in through the queue, read back through
# the engine with its citation. Runs in CI on every push (D-045); locally: scripts/smoke-scale.sh
set -euo pipefail
cd "$(dirname "$0")/.."
cleanup() { docker compose --profile scale stop >/dev/null 2>&1 || true; docker compose --profile scale rm -f nats gateway lb consumer >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker compose --profile scale up -d --build --scale gateway=2 --wait --wait-timeout 180 loom nats gateway lb consumer >/dev/null
EID="smoke-$(date +%s)"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST http://localhost:8081/v1/ingest \
  -H 'content-type: application/json' \
  -d "{\"kind\":\"claim\",\"namespace\":\"smoke\",\"event_id\":\"$EID\",\"subject\":{\"type\":\"host\",\"key\":\"smoke-01\"},\"predicate\":\"logged_in_by\",\"object\":{\"type\":\"user\",\"key\":\"smoke\"},\"observed_at\":\"2026-09-11T00:00:00Z\",\"source\":\"smoke\"}")
[[ "$code" == "202" || "$code" == "200" ]] || { echo "gateway returned HTTP $code"; docker compose --profile scale logs --tail=30 gateway lb; exit 1; }
for i in $(seq 1 60); do
  n=$(curl -s --max-time 5 "http://localhost:8000/v1/entities/host/smoke-01/observations?namespace=smoke" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("count",0))' 2>/dev/null || echo 0)
  [[ "$n" -ge 1 ]] && break
  sleep 1
done
[[ "$n" -ge 1 ]] || { echo "claim never reached the store through the queue"; docker compose --profile scale logs --tail=40 consumer gateway nats; exit 1; }
pack=$(curl -s --max-time 10 -X POST http://localhost:8000/v1/ask -H 'content-type: application/json' \
  -d '{"namespace":"smoke","subject":{"type":"host","key":"smoke-01"},"question":"who logged in?","budget":300}')
echo "$pack" | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["items"] and p["items"][0]["citations"], p; print("ok: claim landed through lb -> gateway -> NATS -> consumer -> store in", sys.argv[1], "s; pack cites", p["items"][0]["citations"][0]["observation_id"][:12])' "$i"
