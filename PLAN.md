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

### `erlang/counter.erl`
API: `increment(User)`, `decrement(User)`, `reset(User)`, `value(User)`.
Mnesia record key is the User parameter (binary username from HTTP, atom `default` from TCP).

### `erlang/counter_server.erl`
TCP server passes atom `default` as the user key. Keeps all 12 existing C tests passing.

### `erlang/counter_http.erl`
- `start/0`: starts both `counter` and `auth` gen_servers
- `collect_headers/2`: accumulates `Content-Length` and `Cookie` (replaces old `Authorization` parsing)
- `parse_session_cookie/1`: splits Cookie header on `"; "`, extracts `session=` value
- `route/4(Method, Path, Body, Token)`: auth routes → counter routes → static files (order matters)
- `GET /auth/me`: lightweight session check — returns `{username}` or 401; used by frontend on page load
- `session_guard/4`: validates session → passes Username to `counter_route/4`
- `response/3` wraps `response/4` with `[]`; `response/4` includes `ExtraHeaders` between CORS and Content-Length
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

### `frontend/index.html`
- `Module.onRuntimeInitialized`: shows auth panel, then calls `authCheckSession()` (async)
- Buttons: `onclick="authRegister()"`, `onclick="authLogin()"`, `onclick="authLogout()"`
- Counter buttons: `onclick="Module._increment()"` etc.
- Load order: `auth.js` before `counter.js`

---

## Makefile

```makefile
EMFLAGS = -O2 -sFETCH \
          -sEXPORTED_FUNCTIONS='["_increment","_decrement","_reset_counter","_refresh"]' \
          -sEXPORTED_RUNTIME_METHODS='["UTF8ToString","stringToUTF8"]'

wasm: $(FRONTEND_BUILD)
    $(EMCC) $(CDIR)/counter_wasm.c \
        -o $(FRONTEND_BUILD)/counter.js $(EMFLAGS)
    cp $(FRONTEND_SRC)/index.html $(FRONTEND_BUILD)/
    cp $(FRONTEND_SRC)/auth.js    $(FRONTEND_BUILD)/
```

No Asyncify. No `ccall`. Single C source file.

---

## File Summary

| Status | File |
|--------|------|
| Created | `erlang/webauthn_cbor.erl` |
| Created | `erlang/webauthn.erl` |
| Created | `erlang/auth.erl` |
| Created | `erlang/auth_http.erl` |
| Created | `frontend/auth.js` |
| Modified | `erlang/counter.erl` (per-user API) |
| Modified | `erlang/counter_server.erl` (uses `default` key) |
| Modified | `erlang/counter_http.erl` (session guard, Cookie parsing, /auth/me) |
| Modified | `c/counter_wasm.c` (no auth header; 401 → showAuthPanel) |
| Modified | `frontend/index.html` (async session check) |
| Modified | `Makefile` (no Asyncify, copies auth.js) |
| Deleted | `c/auth_wasm.c` (replaced by auth.js) |

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
