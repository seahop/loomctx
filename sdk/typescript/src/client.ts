/**
 * Thin TypeScript client for LoomCtx's HTTP API (docs/sdk.md). Typed transport
 * only — no retries into semantics, no client-side ranking — over the
 * generated contract types in ./contracts, so it cannot drift from the
 * server. Zero runtime dependencies: uses the platform `fetch`.
 */
import type {
  AnswerRequest,
  AnswerResponse,
  Artifact,
  AskRequest,
  ContextPack,
  EntityRef,
  IngestBatchResponse,
  Observation,
  ListFilter,
  ListPage,
  ListRequest,
  PathPack,
  PathRequest,
  QueryRequest,
  SchemaRegistration,
  SemanticSearchResponse,
} from "./contracts.js";

export type EntityTuple = [type: string, key: string];
export type ObjectArg = EntityTuple | string | number | boolean;

/** A non-2xx response: `status` is the HTTP code, `detail` the engine's message. */
export class LoomCtxError extends Error {
  constructor(public readonly status: number, public readonly detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.name = "LoomCtxError";
  }
}

export interface LoomCtxOptions {
  namespace?: string;
  /** X-LoomCtx-Key: the caller's identity + data permissions (D-013a). */
  apiKey?: string;
  /** X-LoomCtx-LLM-Key on answer(): bill LLM spend to this caller. */
  llmKey?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export interface ClaimArgs {
  subject: EntityTuple;
  predicate: string;
  object: ObjectArg;
  observed_at: string;
  source: string;
  confidence?: number;
  valid_from?: string | null;
  valid_to?: string | null;
  event_id?: string | null;
  attrs?: Record<string, unknown>;
}

export interface DocumentArgs {
  source: string;
  observed_at: string;
  text?: string | null;
  content_b64?: string | null;
  content_type?: string;
  filename?: string | null;
  event_id?: string | null;
  attrs?: Record<string, unknown>;
}

export interface AskOptions {
  budget?: number;
  /** what was KNOWN at T (ISO timestamp) */
  as_of?: string | null;
  /** what was TRUE at T (ISO timestamp) */
  valid_at?: string | null;
  scope?: AskRequest["scope"];
}

export interface PathOptions {
  /** predicates to traverse (both directions); empty = containment predicates */
  via?: string[];
  depth?: number;
  max_paths?: number;
  budget?: number;
  as_of?: string | null;
  valid_at?: string | null;
}

export interface ListOptions {
  /** keep only entities of this type */
  type?: string | null;
  /** list what is connected to this entity along `via` */
  of?: EntityTuple | null;
  via?: string[];
  /** in: edges pointing at `of` (a group's members); out; any */
  direction?: "in" | "out" | "any";
  depth?: number;
  /** conditions on current values, all must hold */
  where?: ListFilter[];
  fields?: string[];
  limit?: number;
  offset?: number;
  budget?: number;
  as_of?: string | null;
  valid_at?: string | null;
}

export interface ObservationsResponse {
  entity: EntityRef;
  namespace: string;
  count: number;
  observations: Observation[];
}

export interface SearchResponse {
  query: string;
  matches: Array<{ id: string; namespace: string; type: string; key: string; provisional: boolean; created_at: string }>;
}

const ref = (t: EntityTuple): EntityRef => ({ type: t[0], key: t[1] });

export class LoomCtx {
  readonly baseUrl: string;
  readonly namespace: string;
  private readonly apiKey?: string;
  private readonly llmKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(baseUrl: string, opts: LoomCtxOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.namespace = opts.namespace ?? "default";
    // a key read from a file or a k8s Secret often ends in a newline; the
    // engine compares hashes of the exact bytes, so strip it (as the Python SDK does)
    this.apiKey = opts.apiKey?.trim() || undefined;
    this.llmKey = opts.llmKey?.trim() || undefined;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  // ------------------------------------------------------------ write side

  claim(a: ClaimArgs): Promise<{ status: string; observation_id: string }> {
    const object = Array.isArray(a.object) ? ref(a.object) : a.object;
    return this.post("/v1/ingest", {
      kind: "claim",
      namespace: this.namespace,
      event_id: a.event_id ?? null,
      subject: ref(a.subject),
      predicate: a.predicate,
      object,
      observed_at: a.observed_at,
      valid_from: a.valid_from ?? null,
      valid_to: a.valid_to ?? null,
      source: a.source,
      confidence: a.confidence ?? 1.0,
      attrs: a.attrs ?? {},
    });
  }

  document(a: DocumentArgs): Promise<{ status: string; artifact_id: string; extraction: string }> {
    return this.post("/v1/ingest", {
      kind: "document",
      namespace: this.namespace,
      event_id: a.event_id ?? null,
      text: a.text ?? null,
      content_b64: a.content_b64 ?? null,
      content_type: a.content_type ?? "text/plain",
      filename: a.filename ?? null,
      source: a.source,
      observed_at: a.observed_at,
      attrs: a.attrs ?? {},
    });
  }

  /** Many envelopes in one request (D-034); each is reported individually. */
  ingestBatch(envelopes: unknown[]): Promise<IngestBatchResponse> {
    return this.post("/v1/ingest/batch", envelopes);
  }

  registerSchema(reg: Omit<SchemaRegistration, "namespace">): Promise<SchemaRegistration> {
    return this.post("/v1/schemas", { namespace: this.namespace, ...reg });
  }

  // ------------------------------------------------------------- read side

  observations(subject: EntityTuple, limit = 100): Promise<ObservationsResponse> {
    const [t, k] = subject.map((p) => encodeURIComponent(p));
    return this.get(`/v1/entities/${t}/${k}/observations`, { limit });
  }

  artifact(artifactId: string): Promise<Artifact> {
    return this.get(`/v1/artifacts/${encodeURIComponent(artifactId)}`);
  }

  /** One of subject / opts.scope. */
  ask(subject: EntityTuple | null, question: string, opts: AskOptions = {}): Promise<ContextPack> {
    const body: AskRequest = {
      namespace: this.namespace,
      subject: subject ? ref(subject) : null,
      scope: opts.scope ?? null,
      question,
      budget: opts.budget ?? 800,
      as_of: opts.as_of ?? null,
      valid_at: opts.valid_at ?? null,
    };
    return this.post("/v1/ask", body);
  }

  expand(handleId: string, budget = 800): Promise<ContextPack> {
    return this.post("/v1/expand", { handle: handleId, budget });
  }

  /**
   * The edge sequence(s) that connect two entities along `opts.via`
   * predicates (D-067) — "what connects A to B?". Empty `via` follows the
   * namespace's containment predicates. Reports paths that EXIST, each hop
   * cited; it does not rank or score them.
   */
  path(from: EntityTuple, to: EntityTuple, opts: PathOptions = {}): Promise<PathPack> {
    const body: PathRequest = {
      namespace: this.namespace,
      from: ref(from),
      to: ref(to),
      via: opts.via ?? [],
      depth: opts.depth ?? 3,
      max_paths: opts.max_paths ?? 8,
      budget: opts.budget ?? 800,
      as_of: opts.as_of ?? null,
      valid_at: opts.valid_at ?? null,
    };
    return this.post("/v1/path", body);
  }

  /**
   * Every entity matching conditions, with an exact count (D-107): entities
   * of `opts.type`, or connected to `opts.of` along `opts.via`, filtered on
   * current values. Rows are cited; page with `offset` / `next_offset`.
   */
  list(opts: ListOptions = {}): Promise<ListPage> {
    const body: ListRequest = {
      namespace: this.namespace,
      type: opts.type ?? null,
      of: opts.of ? ref(opts.of) : null,
      via: opts.via ?? [],
      direction: opts.direction ?? "in",
      depth: opts.depth ?? 1,
      where: opts.where ?? [],
      fields: opts.fields ?? [],
      limit: opts.limit ?? 50,
      offset: opts.offset ?? 0,
      budget: opts.budget ?? 1500,
      as_of: opts.as_of ?? null,
      valid_at: opts.valid_at ?? null,
    };
    return this.post("/v1/list", body);
  }

  /** Run one of the namespace's named queries (D-108); the answer is a list page. */
  query(
    name: string,
    params: Record<string, unknown> = {},
    opts: { limit?: number; offset?: number; budget?: number; as_of?: string | null; valid_at?: string | null } = {},
  ): Promise<ListPage> {
    const body: QueryRequest = {
      namespace: this.namespace,
      name,
      params,
      limit: opts.limit ?? 50,
      offset: opts.offset ?? 0,
      budget: opts.budget ?? 1500,
      as_of: opts.as_of ?? null,
      valid_at: opts.valid_at ?? null,
    };
    return this.post("/v1/query", body);
  }

  answer(
    question: string,
    opts: AskOptions & { subject?: EntityTuple | null; max_tokens?: number } = {},
  ): Promise<AnswerResponse> {
    const body: AnswerRequest = {
      namespace: this.namespace,
      question,
      subject: opts.subject ? ref(opts.subject) : null,
      scope: opts.scope ?? null,
      budget: opts.budget ?? 1200,
      as_of: opts.as_of ?? null,
      valid_at: opts.valid_at ?? null,
      max_tokens: opts.max_tokens ?? 1024,
    };
    const headers: Record<string, string> = this.llmKey ? { "X-LoomCtx-LLM-Key": this.llmKey } : {};
    return this.post("/v1/answer", body, headers);
  }

  search(query: string, limit = 10): Promise<SearchResponse> {
    return this.get("/v1/entities/search", { q: query, limit });
  }

  /** Entities related to a question by meaning (D-025); 503 until the engine has an embedder. */
  semantic(question: string, limit = 10): Promise<SemanticSearchResponse> {
    return this.get("/v1/entities/semantic", { q: question, limit });
  }

  schema(): Promise<SchemaRegistration> {
    return this.get("/v1/schemas");
  }

  async ready(): Promise<boolean> {
    try {
      const r = await this.get<{ status: string }>("/readyz");
      return r.status === "ready";
    } catch {
      return false;
    }
  }

  // ------------------------------------------------------------- plumbing

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const h: Record<string, string> = {
      "content-type": "application/json",
      "X-LoomCtx-Namespace": this.namespace,
      ...extra,
    };
    if (this.apiKey) h["X-LoomCtx-Key"] = this.apiKey;
    return h;
  }

  private async send<T>(url: string, init: RequestInit): Promise<T> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, { ...init, signal: ctl.signal });
      const text = await res.text();
      if (!res.ok) {
        let detail = text;
        try {
          const parsed = JSON.parse(text);
          detail = typeof parsed.detail === "string" ? parsed.detail : JSON.stringify(parsed.detail ?? parsed);
        } catch {
          /* keep raw body */
        }
        throw new LoomCtxError(res.status, detail);
      }
      return text ? (JSON.parse(text) as T) : (undefined as T);
    } finally {
      clearTimeout(timer);
    }
  }

  private post<T>(path: string, body: unknown, extra: Record<string, string> = {}): Promise<T> {
    return this.send<T>(this.baseUrl + path, {
      method: "POST",
      headers: this.headers(extra),
      body: JSON.stringify(body),
    });
  }

  private get<T>(path: string, params: Record<string, string | number> = {}): Promise<T> {
    const qs = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString();
    return this.send<T>(this.baseUrl + path + (qs ? `?${qs}` : ""), {
      method: "GET",
      headers: this.headers(),
    });
  }
}
