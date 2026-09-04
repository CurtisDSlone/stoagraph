-- StoaGraph adapter config store — the RELATIONAL config the file-based recipes
-- bind to (Planning/18). THIS IS THE ONE DDL FILE FOR THIS SCHEMA. Project rule:
-- NO MIGRATIONS. To change the schema, edit this file and re-init (remove the DB
-- file, reopen); recollecting data is fine. Never add ALTER/version steps.

-- MCP tool servers StoaGraph proxies (the ACT channel; each tool call is gated).
CREATE TABLE IF NOT EXISTS mcp_server (
  name         TEXT PRIMARY KEY,
  transport    TEXT NOT NULL,              -- "stdio" | "http"
  target       TEXT NOT NULL,              -- command line (stdio) or URL (http)
  enabled      INTEGER NOT NULL DEFAULT 1,
  -- Downstream auth (Planning/28) — HTTP only; stdio servers authenticate via the proxy's process
  -- env. The GATE holds the credential so the agent never does (credential isolation). Prefer
  -- secret_env over a persisted secret.
  auth_scheme  TEXT NOT NULL DEFAULT 'none',  -- none | bearer | header | query | oauth
  auth_header  TEXT NOT NULL DEFAULT '',       -- header scheme: the header name (bearer => Authorization)
  secret       TEXT NOT NULL DEFAULT '',       -- dev: the bearer/header value or oauth client_secret
  secret_env   TEXT NOT NULL DEFAULT '',       -- PREFERRED: env var holding the secret
  oauth_config TEXT NOT NULL DEFAULT '{}'      -- oauth non-secret JSON: {client_id, scopes, token_url?}
);

-- Tools discovered on a server (its tools/list); owned by the server.
CREATE TABLE IF NOT EXISTS mcp_tool (
  server_name  TEXT NOT NULL,
  name         TEXT NOT NULL,
  input_schema TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (server_name, name)
);

-- Context providers StoaGraph proxies (the READ channel; output is untrusted).
CREATE TABLE IF NOT EXISTS context_provider (
  name     TEXT PRIMARY KEY,
  kind     TEXT NOT NULL,                -- "rag" | "mcp_resource" | "http"
  config   TEXT NOT NULL DEFAULT '',     -- JSON blob
  enabled  INTEGER NOT NULL DEFAULT 1
);

-- The tool -> recipe bindings: one recipe governs one tool. The live gate builds
-- its router from these rows (recipe_name resolves to a recipestore recipe).
-- A route DELEGATES: it names the tool, the SERVER that serves it, the recipe that governs it, and
-- which argument(s) that recipe judges. The server is part of the binding on purpose. The gate must
-- never INFER which downstream a tool belongs to: inference means that registering an unrelated MCP
-- server could change (or invalidate) a route you already wrote, and "the policy quietly changed when
-- I added a server" is precisely the class of surprise this product exists to eliminate.
-- The key is (tool_name, server_name), NOT tool_name alone. A bare tool name is not unique across a
-- fleet — GitHub's server and a local one may both expose `search_code` — so keying on it made the
-- two collide: the second route UPSERTED over the first and silently repointed it at another server,
-- which is the very failure the paragraph above says must never happen. Each (server, tool) pair now
-- carries its own recipe, and the gate advertises them apart as <server>__<tool>.
CREATE TABLE IF NOT EXISTS route (
  tool_name    TEXT NOT NULL,
  server_name  TEXT NOT NULL,   -- the MCP server this tool is dispatched to
  recipe_name  TEXT NOT NULL,
  gate_arg     TEXT NOT NULL,
  -- 0 = an ordinary advertised route (the default, and what every existing row means).
  -- 1 = SEQUENCED: not offered to the agent, and unreachable without a one-shot grant minted
  --     by the recipe `invoke` step that authorizes the call.
  sequenced    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tool_name, server_name)
);

-- Human-approval queue for ESCALATED actions (Stage 5). When the gate escalates a
-- tool call, the proxy records it here as `pending`. A human approve mints a SIGNED
-- release token (ed25519 over the fingerprint); the retried call then releases via
-- the recipe's signed_equality gate (expected value resolved from `token`). The
-- release is ONE-TIME: `approved` -> `consumed` on release, so a replay re-escalates.
-- id is sha256(fingerprint)[:16] so re-escalating the same action is idempotent.
CREATE TABLE IF NOT EXISTS approval (
  id           TEXT PRIMARY KEY,               -- sha256(fingerprint)[:16]
  tool         TEXT NOT NULL,
  fingerprint  TEXT NOT NULL,                  -- canonical tool+args (minus meta); the token binds this
  args_json    TEXT NOT NULL DEFAULT '{}',     -- proposed args, for the dashboard
  recipe       TEXT NOT NULL DEFAULT '',
  recipe_hash  TEXT NOT NULL DEFAULT '',
  status       TEXT NOT NULL DEFAULT 'pending',-- pending | approved | denied | consumed
  token        TEXT NOT NULL DEFAULT '',       -- signed release (base64 ed25519 sig), set on approve
  reason       TEXT NOT NULL DEFAULT '',       -- approver note (optional)
  created_at   TEXT NOT NULL DEFAULT '',
  decided_at   TEXT NOT NULL DEFAULT ''
);

-- An EPHEMERAL, one-shot authorization minted by a recipe's `invoke` step: it makes a sequenced
-- tool reachable for exactly one call and is deleted on use. Deliberately a SEPARATE table from
-- `approval`: both are grants bound to a fingerprint and spent on use, but one is minted by a
-- person and one by a policy, and nothing should ever be able to read a machine grant as though
-- a human approved it.
CREATE TABLE IF NOT EXISTS authorization_grant (
  fingerprint  TEXT PRIMARY KEY,               -- canonical tool+args: binds the EXACT call
  tool         TEXT NOT NULL,
  source       TEXT NOT NULL,                  -- the policy that minted it; never a person
  created_at   TEXT NOT NULL DEFAULT ''
);
