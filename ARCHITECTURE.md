# Architecture

## System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                           Browser                                │
│                                                                  │
│   ┌───────────────────┐         ┌──────────────────────────┐    │
│   │    Auth Panel      │         │      Counter Panel        │    │
│   │  ┌─────────────┐  │         │                          │    │
│   │  │   username  │  │         │       ┌───────┐          │    │
│   │  └─────────────┘  │  ──────►│       │  -42  │          │    │
│   │  [Register] [Sign] │         │       └───────┘          │    │
│   └───────────────────┘         │  [−]  [Reset]  [+]       │    │
│                                  │  [Sign Out]              │    │
│                                  └──────────────────────────┘    │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    WebAssembly Module                       │  │
│  │                  (C compiled with emcc)                     │  │
│  │                                                            │  │
│  │   auth_wasm.c                     counter_wasm.c           │  │
│  │   ┌──────────────────────┐        ┌──────────────────────┐ │  │
│  │   │ EM_ASYNC_JS flows    │        │ emscripten_fetch      │ │  │
│  │   │ navigator.credentials│        │ Authorization: Bearer │ │  │
│  │   │ g_session_token[128] │──────► │ (reads shared global) │ │  │
│  │   │ g_username[256]      │        │ handles 401 → logout  │ │  │
│  │   └──────────────────────┘        └──────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
         │  /auth/*  (no token needed)       │  /value /increment
         │  POST JSON                        │  /decrement /reset
         │                                   │  Authorization: Bearer <token>
         └───────────────┬───────────────────┘
                         │ HTTP/1.1  port 8080
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                     counter_http.erl                             │
│                 (one Erlang process per connection)              │
│                                                                  │
│   parse request line + headers (collect Authorization header)   │
│   read body (Content-Length bytes)                              │
│                                                                  │
│   /auth/*  ──────────────────────────────► auth_http.erl        │
│   (unauthenticated)                        (returns {Code, JSON})│
│                                                                  │
│   /value /increment /decrement /reset                           │
│      └── auth:validate_session(Token)                           │
│               │ {ok, Username}          │ {error, _}            │
│               ▼                         ▼                        │
│          counter.erl               401 Unauthorized             │
└──────────────────────────────────────────────────────────────────┘
          │                                    │
          ▼                                    ▼
┌──────────────────────┐          ┌────────────────────────────┐
│     counter.erl      │          │         auth.erl           │
│     (gen_server)     │          │        (gen_server)        │
│                      │          │                            │
│  increment(Username) │          │  validate_session(Token)   │
│  decrement(Username) │          │  create_challenge(User, K) │
│  reset(Username)     │          │  consume_challenge(B64, K) │
│  value(Username)     │          │  register_credential(...)  │
│                      │          │  create_session(Username)  │
│  Mnesia key = User   │          │  delete_session(Token)     │
└──────────────────────┘          └────────────────────────────┘
          │                                    │
          ▼                                    ▼
┌──────────────────────────────────────────────────────────────────┐
│                           Mnesia                                 │
│                      (disc_copies on disk)                       │
│                                                                  │
│   counter              webauthn_user      webauthn_credential    │
│   ┌──────┬───────┐     ┌──────────┐       ┌───────────────────┐ │
│   │ key  │ value │     │ username │       │ credential_id     │ │
│   ├──────┼───────┤     │ creat_at │       │ username  (index) │ │
│   │"alice│  17   │     └──────────┘       │ public_key        │ │
│   │"bob" │  -3   │                        │ sign_count        │ │
│   │defaul│   0   │     webauthn_challenge  └───────────────────┘ │
│   └──────┴───────┘     ┌────────────────┐                       │
│   (TCP dev server       │ challenge(raw) │  webauthn_session     │
│    uses key=default)    │ username       │  ┌─────────────────┐  │
│                         │ kind           │  │ token           │  │
│                         │ created_at     │  │ username        │  │
│                         └────────────────┘  │ expires_at      │  │
│                         TTL: 300s           └─────────────────┘  │
│                                             TTL: 3600s           │
└──────────────────────────────────────────────────────────────────┘
```

---

## Passkey Registration Flow

```
  Browser / WASM                 counter_http          auth_http / auth
       │                               │                      │
       │  POST /auth/register/begin    │                      │
       │  {"username": "alice"}        │                      │
       │ ────────────────────────────► │                      │
       │                               │ handle_register_begin│
       │                               │ ───────────────────► │
       │                               │                      │ user_exists("alice")?
       │                               │                      │ create_challenge("alice", registration)
       │                               │                      │ store raw bytes in Mnesia
       │                               │ {"challenge":"abc..",│ return base64url string
       │                               │  "rpId":"localhost"} │
       │ ◄──────────────────────────── │ ◄─────────────────── │
       │                               │                      │
       │  navigator.credentials.create(│                      │
       │    challenge: decode(abc..),  │                      │
       │    rp: {id:"localhost", ...}, │                      │
       │    pubKeyCredParams: [alg:-7])│                      │
       │  [Touch ID / passkey prompt]  │                      │
       │                               │                      │
       │  POST /auth/register/complete │                      │
       │  {username, challenge,        │                      │
       │   attestationObject (CBOR),   │                      │
       │   clientDataJSON (JSON)}      │                      │
       │ ────────────────────────────► │                      │
       │                               │ handle_register_     │
       │                               │ complete             │
       │                               │ ───────────────────► │
       │                               │                      │ consume_challenge(challenge, registration)
       │                               │                      │   decode b64url → raw bytes
       │                               │                      │   lookup Mnesia, check TTL, delete
       │                               │                      │
       │                               │                      │ webauthn:verify_registration(...)
       │                               │                      │   decode clientDataJSON → check type/origin/challenge
       │                               │                      │   CBOR-decode attestationObject
       │                               │                      │   parse authData binary:
       │                               │                      │     rpIdHash | flags | signCount |
       │                               │                      │     AAGUID | credIdLen | credId | COSE key
       │                               │                      │   CBOR-decode COSE key → X, Y coords
       │                               │                      │   public key = 0x04 ++ X ++ Y (65 bytes)
       │                               │                      │   verify attestation signature
       │                               │                      │
       │                               │                      │ register_credential(alice, credId, pubKey, 0)
       │                               │                      │   write webauthn_user (if new)
       │                               │                      │   write webauthn_credential
       │                               │                      │
       │  201 {"status":"ok"}          │                      │
       │ ◄──────────────────────────── │ ◄─────────────────── │
       │                               │                      │
       │  showCounterPanel("alice")    │                      │
```

---

## Passkey Login Flow

```
  Browser / WASM                 counter_http          auth_http / auth
       │                               │                      │
       │  POST /auth/login/begin       │                      │
       │  {"username": "alice"}        │                      │
       │ ────────────────────────────► │                      │
       │                               │ ───────────────────► │
       │                               │                      │ credentials_for_user("alice")
       │                               │                      │   Mnesia index read on username
       │                               │                      │ create_challenge("alice", authentication)
       │                               │                      │
       │  {"challenge":"xyz..",        │                      │
       │   "allowCredentials":[...]}   │                      │
       │ ◄──────────────────────────── │ ◄─────────────────── │
       │                               │                      │
       │  navigator.credentials.get(   │                      │
       │    challenge: decode(xyz..),  │                      │
       │    allowCredentials: [...])   │                      │
       │  [Touch ID / passkey prompt]  │                      │
       │                               │                      │
       │  POST /auth/login/complete    │                      │
       │  {credentialId,               │                      │
       │   authenticatorData,          │                      │
       │   clientDataJSON,             │                      │
       │   signature}                  │                      │
       │ ────────────────────────────► │                      │
       │                               │ ───────────────────► │
       │                               │                      │ extract challenge from clientDataJSON
       │                               │                      │ consume_challenge(challenge, authentication)
       │                               │                      │ find_credential(credId) → stored public key
       │                               │                      │
       │                               │                      │ webauthn:verify_assertion(...)
       │                               │                      │   check type / origin / challenge
       │                               │                      │   check rpIdHash, UP flag
       │                               │                      │   SignedData = authData ++ sha256(clientDataJSON)
       │                               │                      │   crypto:verify(ecdsa, sha256,
       │                               │                      │     SignedData, Sig, [PubKey, prime256v1])
       │                               │                      │   check sign_count > stored (replay guard)
       │                               │                      │
       │                               │                      │ update_sign_count(credId, newCount)
       │                               │                      │ create_session("alice") → Token
       │                               │                      │   random 32 bytes, base64url
       │                               │                      │   store in Mnesia, expires +3600s
       │                               │                      │
       │  {"token":"…","username":"…"} │                      │
       │ ◄──────────────────────────── │ ◄─────────────────── │
       │                               │                      │
       │  store token in g_session_token (C global)           │
       │  showCounterPanel("alice")    │                      │
```

---

## Authenticated Counter Request

```
  Browser / WASM           counter_http             counter.erl        Mnesia
       │                        │                        │               │
       │  GET /value            │                        │               │
       │  Authorization:        │                        │               │
       │   Bearer <token>       │                        │               │
       │ ──────────────────────►│                        │               │
       │                        │ parse headers          │               │
       │                        │ extract token          │               │
       │                        │                        │               │
       │                        │ auth:validate_session(token)           │
       │                        │ ──── Mnesia dirty_read ────────────────►
       │                        │ ◄─── {ok, "alice"} ────────────────────
       │                        │                        │               │
       │                        │ counter:value("alice") │               │
       │                        │ ──────────────────────►│               │
       │                        │                        │ mnesia:read   │
       │                        │                        │ (counter,"alice")
       │                        │                        │ ─────────────►│
       │                        │                        │ ◄─────────────│
       │                        │ {reply, 17, State}     │               │
       │                        │ ◄──────────────────────│               │
       │                        │                        │               │
       │  200 OK  "17"          │                        │               │
       │ ◄──────────────────────│                        │               │
       │                        │                        │               │
       │  (token invalid/expired)                        │               │
       │  401 {"error":         │                        │               │
       │       "Unauthorized"}  │                        │               │
       │ ◄──────────────────────│                        │               │
       │  WASM clears token,    │                        │               │
       │  shows auth panel      │                        │               │
```

---

## Dev / Test Path (no authentication)

```
  counter_client.c          counter_server.erl       counter.erl
  counter_tests.c                                    (key = default)
       │                           │                      │
       │  TCP port 9090            │                      │
       │  "increment\n"            │                      │
       │ ─────────────────────────►│                      │
       │                           │ counter:increment(default)
       │                           │ ────────────────────►│
       │                           │                      │ Mnesia read/write
       │  "ok\n"                   │                      │ key = atom 'default'
       │ ◄─────────────────────────│                      │
```

The TCP server is an internal dev/test tool only — it bypasses authentication entirely and operates on a single shared counter under the key `default`.
