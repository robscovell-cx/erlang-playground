# Passkey Authentication — Implemented State

## Context
WebAuthn passkey-only authentication has been added to the counter app. Auth
ceremonies (`navigator.credentials`) are handled in plain JavaScript (`frontend/auth.js`).
Sessions are maintained via an `HttpOnly; SameSite=Strict` cookie set by the server;
JavaScript cannot read the token, so it cannot be exfiltrated by XSS. The browser
sends the cookie automatically with every same-origin request — `counter_wasm.c` needs
no Authorization header logic. The Erlang backend verifies attestations and assertions
with pure OTP (`crypto`, `json`, `base64` urlsafe mode). Counter HTTP routes are
session-guarded with per-user counters keyed by username binary. The TCP server
(port 9090) bypasses auth entirely and uses atom `default` as the counter key so
`make test` continues to pass.

---

## Schema-Driven Code Generation

New tooling generates Erlang modules and JavaScript form helpers from a single
YAML schema file, keeping the two in sync without manual duplication.

### `schema/address.yaml`
Flat format:
```yaml
table: user_address
fields:
  - name: line1
    label: Street Address
    required: true
  ...
```
Root `table:` key names the Mnesia table and output files. Each field entry
carries `name`, `label`, and optional `required`.

### `erlang/gen_schema.escript`
Run via `make gen`. Parses every `schema/*.yaml` with a minimal recursive
descent YAML parser (no third-party lib), then calls:
- `emit_erlang(Table, Fields)` — writes `erlang/<table>.erl`
- `emit_javascript(Table, Fields)` — writes `frontend/<table>_form.js`

The Erlang emitter produces a complete, self-contained module with
`start_link/0`, `get/1`, `put/2`, and a `coerce/1` helper. The JS emitter
produces a `_<Cap>Fields` metadata array and three functions
(`build<Cap>Form`, `load<Cap>`, `save<Cap>`).

`make gen` (Makefile):
```makefile
gen:
    @for f in $(SCHEMA_DIR)/*.yaml; do \
        escript $(GEN_ESCRIPT) $$f; \
    done
```

---

## Erlang Modules

### `erlang/webauthn_cbor.erl`
Pure recursive-descent CBOR decoder (RFC 7049). Handles only the major types
WebAuthn needs: 0=uint, 1=nint, 2=bstr, 3=tstr, 4=array, 5=map.
- Exported: `decode(Binary) -> {ok, Value} | {error, cbor_decode_failed}`
- Map keys decoded as-is (integers for COSE_Key, binaries for attestationObject)

Core pattern:
```erlang
decode_item(<<IB:8, Rest/binary>>) ->
    {Arg, Rest2} = decode_argument(IB band 16#1f, Rest),
    decode_value(IB bsr 5, Arg, Rest2).
```

### `erlang/webauthn.erl`
Registration and assertion verification. Depends on `webauthn_cbor`, `crypto`, `json`, `base64`.

**`verify_registration(Username, ChallengeB64, AttObjB64, ClientDataB64)`**
1. base64url-decode and `json:decode` clientDataJSON; check `type="webauthn.create"`,
   challenge matches (bytes comparison after decoding both sides), `origin="http://localhost:8080"`
2. base64url-decode attestationObject; `webauthn_cbor:decode`; extract `authData` bytes
3. Parse authData binary:
   ```erlang
   <<RpIdHash:32/binary, Flags:8, _SignCount:32,
     _AAGUID:16/binary, CredIdLen:16,
     CredId:CredIdLen/binary, CoseBytes/binary>> = AuthData
   ```
4. Verify `RpIdHash =:= crypto:hash(sha256, <<"localhost">>)`
5. Verify UP flag `(Flags band 1) =:= 1`
6. `webauthn_cbor:decode(CoseBytes)` → `extract_ec_pubkey(#{-2 := X, -3 := Y})`
7. Public key = `<<16#04, X:32/binary, Y:32/binary>>`
8. Attestation: `fmt="none"` → skip; `fmt="packed"` (self-attest) → verify sig with
   `crypto:verify(ecdsa, sha256, AuthDataRaw, Sig, [PubKey, prime256v1])`
9. Return `{ok, #{cred_id => CredId, public_key => PubKey, sign_count => 0}}`

**`verify_assertion(ExpectedChallengeB64, AuthDataB64, ClientDataB64, SigB64, StoredCred)`**
1. clientDataJSON: check `type="webauthn.get"`, challenge, origin
2. Parse authData; check rpIdHash, UP flag, extract SignCount
3. `SignedData = <<AuthDataRaw/binary, (crypto:hash(sha256, ClientDataJSONRaw))/binary>>`
4. `crypto:verify(ecdsa, sha256, SignedData, Sig, [StoredPubKey, prime256v1])`
5. `check_sign_count`: count=0 always ok; new > stored ok; otherwise `{error, sign_count_replay}`
6. Return `{ok, NewSignCount}`

Note: OTP's `crypto` uses `prime256v1` (OpenSSL's name for P-256/secp256r1).

### `erlang/auth.erl`
Gen_server owning four Mnesia `disc_copies` tables. Most exported API functions use
dirty ops directly — single-node disc_copies tables are inherently safe for concurrent
dirty access. The gen_server exists only to run `ensure_tables/0` once at startup and
schedule the hourly session purge.

**Records:**
```erlang
-record(webauthn_user,       {username, created_at}).
-record(webauthn_credential, {credential_id, username, public_key, sign_count, created_at}).
%% secondary index on username field (for credentials_for_user/1)
-record(webauthn_challenge,  {challenge, username, kind, created_at}).
-record(webauthn_session,    {token, username, expires_at}).
```

**Exported API:**
- `create_challenge(Username, Kind) -> {ok, ChallengeB64}` — 32 random bytes stored as key; base64url returned
- `consume_challenge(ChallengeB64, Kind) -> {ok, Username} | {error, not_found|expired}` — one-time; deleted on use; TTL 300s
- `register_credential(Username, CredId, PubKey, SignCount) -> ok` — creates user row if absent
- `find_credential(CredIdRaw) -> {ok, Map} | {error, not_found}` — returns plain map
- `credentials_for_user(Username) -> [Map]` — via `mnesia:dirty_index_read` on `#webauthn_credential.username`
- `update_sign_count(CredId, NewCount) -> ok`
- `create_session(Username) -> {ok, Token}` — 32 random bytes base64url; TTL = now + 3600
- `validate_session(Token) -> {ok, Username} | {error, invalid|expired}` — lazy delete on expired
- `delete_session(Token) -> ok`
- `user_exists(Username) -> boolean()`

Hourly purge: `erlang:send_after(3_600_000, self(), purge_sessions)` in `init/1`;
`handle_info` uses `mnesia:select` with `[{'<', '$2', Now}]` guard to delete expired sessions.

### `erlang/auth_http.erl`
Each handler returns `{HttpCode, ExtraHeaders, JsonBinary}`. `ExtraHeaders` is `[]` or
contains `{<<"Set-Cookie">>, Value}` tuples assembled by `set_cookie/1` and `clear_cookie/0`.

- `handle_register_begin(Body)` → check user absent; generate random 16-byte `userId`
  (not the username — PII must not go in `user.id` per the WebAuthn spec, as it may be
  stored on the authenticator); `auth:create_challenge`; return `{challenge, userId, rpId, rpName}`
- `handle_register_complete(Body)` → `auth:consume_challenge`; `webauthn:verify_registration/4`;
  `auth:register_credential`; `auth:create_session`; return `{201, [set_cookie(Token)], {status, username}}`
- `handle_login_begin(Body)` → `auth:credentials_for_user`; `auth:create_challenge`; return `{challenge, rpId, allowCredentials}`
- `handle_login_complete(Body)` → extract challenge from clientDataJSON (signed by authenticator,
  not client-supplied); `auth:consume_challenge`; `auth:find_credential`; `webauthn:verify_assertion/5`;
  `auth:update_sign_count`; `auth:create_session`; return `{200, [set_cookie(Token)], {username}}`
- `handle_logout(Token)` → `auth:delete_session(Token)`; return `{200, [clear_cookie()], {status: ok}}`

Cookie format: `session=TOKEN; HttpOnly; SameSite=Strict; Path=/`
Logout clears with: `session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
(Add `; Secure` for HTTPS deployments.)

### `erlang/user_address.erl`
Generated by `gen_schema.escript` from `schema/address.yaml` — do not edit
by hand; run `make gen` to regenerate.

Record:
```erlang
-record(user_address, {username, line1, line2, city, state, postcode, country}).
```

- `start_link/0` — calls `ensure_table/0` (disc_copies), then
  `mnesia:wait_for_tables/2`; not a gen_server — returns `{ok, self()}`
- `get(Username) -> {ok, Map}` — dirty_read; missing record returns all-empty
  binary defaults; present record runs each field through `coerce/1`
- `put(Username, Data) -> ok` — dirty_write; extracts fields with
  `maps:get(<<"field">>, Data, <<>>)`
- `coerce/1` — normalises `undefined → <<>>`, lists → binary, binaries pass
  through

### `erlang/counter.erl`
API: `increment(User)`, `decrement(User)`, `reset(User)`, `value(User)`.
Mnesia record key is the User parameter (binary username from HTTP, atom `default` from TCP).

### `erlang/counter_server.erl`
TCP server passes atom `default` as the user key. Keeps all 12 existing C tests passing.

### `erlang/counter_http.erl`
- `start/0`: starts `counter`, `auth`, and `user_address`
- `collect_headers/2`: accumulates `Content-Length` and `Cookie` (replaces old `Authorization` parsing)
- `parse_session_cookie/1`: splits Cookie header on `"; "`, extracts `session=` value
- `route/4(Method, Path, Body, Token)`: auth routes → counter routes → static files (order matters)
- `GET /auth/me`: lightweight session check — returns `{username}` or 401; used by frontend on page load
- `session_guard/4`: validates session → passes Username to `counter_route/4`
- `response/3` wraps `response/4` with `[]`; `response/4` includes `ExtraHeaders` between CORS and Content-Length
- `route/4`: user address routes `GET /user_address`, `POST /user_address`
  dispatched to `session_guard_state/4` — placed before counter routes
- `session_guard_state(get | put, Mod, Body, Token)`: generic session-guarded
  handler; calls `Mod:get(User)` or `Mod:put(User, json:decode(Body))`; designed
  to work with any module that exports `get/1` and `put/2`
- `cors_headers/0`: `Content-Type` only (no `Authorization` — cookies are not a CORS credential)
- `status_line/1`: covers 200, 201, 400, 401, 404, 409, 500

---

## C Files

### `c/counter_wasm.c`
No auth logic. `do_fetch` sets up `emscripten_fetch_attr_t` and fires the request; the browser
sends the `HttpOnly` session cookie automatically for same-origin requests. On HTTP 401,
`EM_ASM({ Module.showAuthPanel(); })` redirects to the auth panel.

No Asyncify, no EM_JS bridge, no Authorization header.

---

## Frontend

### `frontend/auth.js`
```javascript
const _API = 'http://localhost:8080';

// base64url encode: loop, not spread, to avoid call-stack overflow on large buffers
function _b64url(buf) { ... }
function _b64url_decode(s) { ... }

// Parse error body defensively — falls back to status code if response is not JSON
async function _err_msg(resp) { ... }

// Check browser support before calling navigator.credentials
function _webauthn_available() {
    return !!(window.PublicKeyCredential && navigator.credentials);
}

// Called from Module.onRuntimeInitialized — restores login state from HttpOnly cookie
async function authCheckSession() { /* GET /auth/me → showCounterPanel if 200 */ }

async function authRegister() { /* begin → credentials.create → complete */ }
async function authLogin()    { /* begin → credentials.get   → complete */ }
async function authLogout()   { /* POST /auth/logout, showAuthPanel */ }
```

Key points:
- No `window.__sessionToken` — session is in an HttpOnly cookie, invisible to JS
- `authRegister` uses `opts.userId` (random server-generated bytes) for `user.id`, not the username
- All error paths wrap `resp.json()` in try/catch; non-JSON responses (e.g. 502 HTML) are handled gracefully
- `authLogout` is fire-and-forget; navigates back to auth panel immediately

### `frontend/user_address_form.js`
Generated by `gen_schema.escript` — do not edit by hand.

- `_UserAddressFields` — array of `{name, label, required}` metadata
- `buildUserAddressForm()` — clears `#user_address-fields`, injects a `<label>` +
  `<input>` pair per field with inline CSS matching the existing card style
- `loadUserAddress()` — `GET /user_address` → populates inputs from JSON; silent
  on network/auth failures
- `saveUserAddress()` — validates required fields (sets `#user_address-status`
  on missing), then `POST /user_address` with JSON body; shows "Saved" or error

### `frontend/index.html`
- `Module.onRuntimeInitialized`: shows auth panel, then calls `authCheckSession()` (async)
- Buttons: `onclick="authRegister()"`, `onclick="authLogin()"`, `onclick="authLogout()"`
- Counter buttons: `onclick="Module._increment()"` etc.
- Address panel: `#user_address-panel` card shown alongside the counter panel;
  Save button calls `saveUserAddress()`; status shown in `#user_address-status`
- `showCounterPanel` now also shows `#user_address-panel`, calls
  `buildUserAddressForm()` and `loadUserAddress()`
- `showAuthPanel` hides `#user_address-panel` (in addition to counter panel)
- Load order: `auth.js` → `user_address_form.js` → `counter.js`

---

## Makefile

```makefile
EMFLAGS = -O2 -sFETCH \
          -sEXPORTED_FUNCTIONS='["_increment","_decrement","_reset_counter","_refresh"]' \
          -sEXPORTED_RUNTIME_METHODS='["UTF8ToString","stringToUTF8"]'

## Regenerate Erlang + JS from all schema YAML files.
gen:
    @for f in $(SCHEMA_DIR)/*.yaml; do \
        escript $(GEN_ESCRIPT) $$f; \
    done

wasm: $(FRONTEND_BUILD)
    $(EMCC) $(CDIR)/counter_wasm.c \
        -o $(FRONTEND_BUILD)/counter.js $(EMFLAGS)
    cp $(FRONTEND_SRC)/index.html             $(FRONTEND_BUILD)/
    cp $(FRONTEND_SRC)/auth.js                $(FRONTEND_BUILD)/
    cp $(FRONTEND_SRC)/user_address_form.js   $(FRONTEND_BUILD)/
```

No Asyncify. No `ccall`. Single C source file. `user_address.beam` is included
in the `BEAMS` list so `make all` compiles it.

---

## File Summary

| Status | File |
|--------|------|
| Created | `erlang/webauthn_cbor.erl` |
| Created | `erlang/webauthn.erl` |
| Created | `erlang/auth.erl` |
| Created | `erlang/auth_http.erl` |
| Created | `erlang/gen_schema.escript` (code generator) |
| Created | `erlang/user_address.erl` (generated from schema) |
| Created | `schema/address.yaml` |
| Created | `frontend/auth.js` |
| Created | `frontend/user_address_form.js` (generated from schema) |
| Modified | `erlang/counter.erl` (per-user API) |
| Modified | `erlang/counter_server.erl` (uses `default` key) |
| Modified | `erlang/counter_http.erl` (session guard, Cookie parsing, /auth/me, /user_address, session_guard_state) |
| Modified | `c/counter_wasm.c` (no auth header; 401 → showAuthPanel) |
| Modified | `frontend/index.html` (async session check, address panel) |
| Modified | `Makefile` (no Asyncify, copies auth.js + user_address_form.js, gen target) |
| Deleted | `c/auth_wasm.c` (replaced by auth.js) |
| Deleted | `frontend/QA.md` |

---

## Verification

1. `make all` — all 7 beams compile cleanly
2. `make test` — all 12 C tests pass (TCP server, `default` counter key, no auth)
3. `make wasm` — WASM builds without warnings
4. `make serve` — server starts on port 8080
5. Open `http://localhost:8080` — auth panel visible
6. Register a passkey (Touch ID on macOS) → counter panel appears; counter starts at 0
7. Click +/−/Reset — counter value updates; Mnesia persists across server restarts
8. Sign Out → auth panel returns; session cookie cleared
9. Sign In with same passkey → counter panel returns with correct persisted value
10. Refresh page → `authCheckSession` hits `/auth/me`; if cookie valid, counter panel shown; otherwise auth panel
11. `curl http://localhost:8080/value` without cookie → 401 `{"error":"Unauthorized"}`
12. Two different usernames → each has an independent counter
13. `make gen` — regenerates `erlang/user_address.erl` and `frontend/user_address_form.js`
    from `schema/address.yaml` (files should be identical to committed versions)
14. After login, address form appears below the counter; fill in all required fields,
    click Save → "Saved" status appears
15. Refresh page → `loadUserAddress()` repopulates fields from Mnesia
16. Two different users → each has an independent address record
