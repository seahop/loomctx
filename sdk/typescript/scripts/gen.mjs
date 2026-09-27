// Generate src/contracts.ts from contracts/schemas.json (D-026).
//
//   node scripts/gen.mjs ../../contracts/schemas.json src/contracts.ts
//
// Every root exported by `python -m loomctx.schemas` becomes an exported type;
// the shared $defs (EntityRef, Citation, ...) are emitted once. The output is
// committed and CI regenerates it to prove the SDK cannot drift from the
// Python contracts.
import { readFileSync, writeFileSync } from "node:fs";
import { compile } from "json-schema-to-typescript";

const [schemasPath, outPath] = process.argv.slice(2);
if (!schemasPath || !outPath) {
  console.error("usage: gen.mjs <schemas.json> <out.ts>");
  process.exit(2);
}
const roots = JSON.parse(readFileSync(schemasPath, "utf8"));

// One combined schema: each root becomes a property, and their $defs are
// merged (Pydantic emits identical definitions for shared models).
const defs = {};
const properties = {};
for (const [name, schema] of Object.entries(roots)) {
  const { $defs = {}, ...rest } = schema;
  for (const [k, v] of Object.entries($defs)) {
    if (defs[k] && JSON.stringify(defs[k]) !== JSON.stringify(v)) {
      throw new Error(`conflicting $defs for ${k} between roots`);
    }
    defs[k] = v;
  }
  properties[name] = { ...rest, title: rest.title ?? name };
}
// A root that also appears among the shared $defs (ContextPack inside
// AnswerResponse) must be emitted once: point the root at the def.
for (const name of Object.keys(properties)) {
  if (defs[name]) properties[name] = { $ref: `#/$defs/${name}` };
}
// Pydantic titles every property ("Namespace", "Kind1", ...), which the
// generator would turn into one alias per field. Keep titles only on
// object-shaped schemas (the real models); drop them elsewhere.
function untitleLeaves(node, isRoot = false) {
  if (Array.isArray(node)) return node.forEach((n) => untitleLeaves(n));
  if (!node || typeof node !== "object") return;
  const isModel = node.properties !== undefined; // free-form dicts (attrs) are not models
  if (!isRoot && !isModel) delete node.title;
  for (const [k, v] of Object.entries(node)) {
    if (k === "$defs" || k === "properties") {
      for (const child of Object.values(v)) untitleLeaves(child, k === "$defs");
    } else if (typeof v === "object") untitleLeaves(v);
  }
}
for (const p of Object.values(properties)) untitleLeaves(p, true);
for (const d of Object.values(defs)) untitleLeaves(d, true);

const combined = {
  title: "LoomCtxContracts",
  description: "All LoomCtx contract roots (generated wrapper; use the named exports).",
  type: "object",
  properties,
  additionalProperties: false,
  $defs: defs,
};

const banner =
  "/* eslint-disable */\n" +
  "/**\n * GENERATED from contracts/schemas.json by scripts/gen.mjs — do not edit.\n" +
  " * Source of truth: src/loomctx/contracts.py (docs/contracts.md).\n */\n\n";
const ts = await compile(combined, "LoomCtxContracts", {
  bannerComment: banner,
  additionalProperties: false,
  style: { singleQuote: false, semi: true },
  unreachableDefinitions: true,
});
writeFileSync(outPath, ts);
console.error(`wrote ${outPath} (${Object.keys(roots).length} roots, ${Object.keys(defs).length} shared defs)`);
