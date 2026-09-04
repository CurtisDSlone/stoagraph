# OAuth provider profiles

**Adding a provider must never require code.** These are the adapters — and they are JSON, not Go.

A spec-compliant MCP server needs **none of this**. The gate discovers its authorization server (RFC
9728 → RFC 8414/OIDC), registers itself dynamically (RFC 7591), and signs in with PKCE. Zero config. That
is what the MCP spec asks servers to support, and it is the path most of them take.

This directory is for **everything else** — the provider that publishes no metadata, or won't register a
client for you, or needs one weird parameter without which it quietly hands you a token that expires in
an hour and can never be refreshed.

## How to use one

Register an MCP server with scheme **OAuth sign-in** via `POST /api/mcp-servers` with
`"oauthConfig": "<the profile's JSON>"`, then start the auth-code flow with `GET /api/oauth/start`.

Everything in a profile is an **override on top of discovery**. Set only what the provider gets wrong.

## The fields

| Field | Use it when |
|---|---|
| `client_id`, `client_secret` | the provider has no dynamic registration (GitHub, Google, most big ones) |
| `scopes` | you want least privilege instead of everything the server advertises |
| `authorization_endpoint`, `token_endpoint` | **the provider publishes no metadata at all** — setting both SKIPS discovery |
| `registration_endpoint` | discovery missed it |
| `token_auth_method` | `client_secret_basic` \| `client_secret_post` \| `none` — only if the provider lies about, or omits, what it accepts |
| `authorize_params` | extra query params on `/authorize` |
| `token_params` | extra form params on `/token` |

`authorize_params` is the one that matters most, because its absence fails **silently**.

## Why `authorize_params` exists

Google will happily complete a sign-in without `access_type=offline` — and simply never issue a refresh
token. Everything looks fine until the access token expires an hour later and the operator is logged out
with no way back. Auth0 without `audience` returns a token the API rejects. These are not bugs in the
gate; they are provider dialects. A profile is how you speak one.

## Contributing a provider

Add a `<provider>.json` here with a short comment on **why** each non-obvious field is needed, and open a
PR. No release, no new code path — a profile is data the operator pastes in.
