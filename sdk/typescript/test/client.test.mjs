// End-to-end against a live engine: LOOMCTX_URL=http://loomctx:8000 (compose `sdk`
// profile / CI). Skips cleanly when unset so `npm test` works offline.
import assert from "node:assert/strict";
import { test } from "node:test";
import { LoomCtx, LoomCtxError } from "../dist/index.js";

const url = process.env.LOOMCTX_URL;
const OBSERVED = "2026-09-01T14:03:00Z";

test("typescript sdk round trip", { skip: !url && "LOOMCTX_URL not set" }, async () => {
  const loomctx = new LoomCtx(url, { namespace: "tsdk" });
  assert.equal(await loomctx.ready(), true);

  const first = await loomctx.claim({
    subject: ["host", "web 01/a"], predicate: "logged_in_by", object: ["user", "j&d"],
    observed_at: OBSERVED, source: "auth-log", event_id: "ts-e1",
  });
  const replay = await loomctx.claim({
    subject: ["host", "web 01/a"], predicate: "logged_in_by", object: ["user", "j&d"],
    observed_at: OBSERVED, source: "auth-log", event_id: "ts-e1",
  });
  assert.equal(first.observation_id, replay.observation_id);

  const obs = await loomctx.observations(["host", "web 01/a"]);
  assert.equal(obs.count, 1);
  const found = await loomctx.search("web 01");
  assert.deepEqual(found.matches.map((m) => m.key), ["web 01/a"]);

  const pack = await loomctx.ask(["host", "web 01/a"], "who logged in?", { budget: 400 });
  assert.ok(pack.items.length > 0 && pack.items[0].citations.length > 0);
  assert.equal(pack.namespace, "tsdk");

  await loomctx.claim({
    subject: ["host", "web 01/a"], predicate: "member_of", object: ["domain", "corp.local"],
    observed_at: OBSERVED, source: "inv", event_id: "ts-m1",
  });
  const paths = await loomctx.path(["user", "j&d"], ["domain", "corp.local"],
    { via: ["logged_in_by", "member_of"], depth: 2, budget: 2000 });
  assert.equal(paths.from.key, "j&d");
  assert.ok(paths.paths.length > 0 && paths.paths[0].every((e) => e.cite));

  const doc = await loomctx.document({ text: "report body", source: "ir", observed_at: OBSERVED, filename: "ir.txt", event_id: "ts-d1" });
  assert.equal(doc.status, "accepted");
  assert.equal((await loomctx.artifact(doc.artifact_id)).text, "report body");

  const reg = await loomctx.registerSchema({
    entity_types: [{ name: "host" }, { name: "user" }],
    predicates: [{ name: "logged_in_by", object_types: ["user"] }],
  });
  assert.equal(reg.strict, false);
  assert.equal((await loomctx.schema()).predicates[0].name, "logged_in_by");
  await assert.rejects(
    loomctx.claim({ subject: ["host", "x"], predicate: "logged_in_by", object: "scalar", observed_at: OBSERVED, source: "s" }),
    (e) => e instanceof LoomCtxError && e.status === 422 && /expects an entity object/.test(e.detail),
  );
  await assert.rejects(loomctx.artifact("missing"), (e) => e instanceof LoomCtxError && e.status === 404);
});

// A key read from a file or a k8s Secret often ends in a newline; the client
// strips it before sending, as the Python SDK does (review 2026-09-26).
test("api key is trimmed", async () => {
  const sent = [];
  const fetch = async (_url, init) => {
    sent.push(init.headers["X-LoomCtx-Key"]);
    return new Response(JSON.stringify({ status: "ready" }), { status: 200 });
  };
  assert.equal(await new LoomCtx("http://loomctx", { apiKey: "  s3cret\n", fetch }).ready(), true);
  await new LoomCtx("http://loomctx", { apiKey: " \n", fetch }).ready();
  assert.deepEqual(sent, ["s3cret", undefined]);
});
