-- Fluent Bit Lua filter: reshape a log record into a Loom claim envelope.
-- Adapt the field mapping to your records; return code 1 = record replaced.
function to_loom_claim(tag, timestamp, record)
  local host = record["host"] or "unknown-host"
  local user = record["user"] or "unknown-user"
  local id = record["id"] or (tostring(timestamp) .. "-" .. host .. "-" .. user)
  local observed = os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(timestamp))
  local envelope = {
    kind = "claim",
    namespace = "netsec",
    event_id = "fluent-bit:" .. id,
    subject = { type = "host", key = host },
    predicate = "logged_in_by",
    object = { type = "user", key = user },
    observed_at = observed,
    source = "fluent-bit:auth-log",
    confidence = 1.0,
    attrs = { method = record["method"] or "unknown" },
  }
  return 1, timestamp, envelope
end
