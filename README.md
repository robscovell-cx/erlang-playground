# Erlang Passkey Auth — Proof of Concept

A proof of concept for adding WebAuthn passkey authentication to an Erlang web
application. The domain is deliberately simple — a per-user counter — so the focus
stays on the auth layer rather than application logic.

## What this explores

- Implementing the WebAuthn registration and assertion ceremonies in pure Erlang/OTP,
  with no third-party libraries
- Storing credentials and sessions in Mnesia (OTP's built-in distributed database)
- Verifying ECDSA signatures from passkeys using OTP's `crypto` module
- Decoding CBOR (the binary format WebAuthn uses for attestation objects) in Erlang
- Handling the browser side of passkey auth in plain JavaScript, then wiring it to
  a WebAssembly counter module served by the same Erlang HTTP server
- Securing session tokens with `HttpOnly; SameSite=Strict` cookies rather than
  JavaScript-accessible storage

## How it works

A user registers a passkey (Touch ID, Face ID, or a hardware key). The browser asks
the authenticator to create a new EC key pair; the private key never leaves the device.
The server stores the public key. On subsequent logins the server issues a challenge,
the authenticator signs it, and the server verifies the signature — proving the user
controls the device that registered — without any password.

Once authenticated, the user gets a session cookie. The counter page is served as a
WebAssembly module (written in C, compiled with Emscripten) that calls back to the
Erlang HTTP server to read and update the counter. Each user has their own counter,
persisted in Mnesia across server restarts.

## Stack

| Layer | Technology |
|-------|-----------|
| HTTP server | Erlang/OTP — raw `gen_tcp`, `{packet, http_bin}` |
| Auth logic | Erlang — `crypto`, `json`, `base64` (all OTP built-ins) |
| CBOR decoding | Hand-written Erlang (`erlang/webauthn_cbor.erl`) |
| Persistence | Mnesia `disc_copies` tables |
| Counter UI | C → WebAssembly via Emscripten, `emscripten_fetch` |
| Auth UI | Plain JavaScript (`frontend/auth.js`) |

## Running it

Prerequisites: Erlang/OTP 27+, Emscripten (`emcc`), a C compiler.

```sh
# Build Erlang beams and C binaries
make all

# Build the WebAssembly counter module and copy frontend files
make wasm

# Start the HTTP server on http://localhost:8080
make serve

# Run the TCP counter tests (no auth; uses port 9090)
make test
```

Open `http://localhost:8080` in a browser that supports WebAuthn (Safari, Chrome,
Firefox on macOS/Windows with a platform authenticator). Register a username with
a passkey, then use the counter.

## Further reading

- `ARCHITECTURE.md` — system diagrams and request flows
- `PLAN.md` — detailed notes on every module and design decision
- `erlang/webauthn.erl` — annotated registration and assertion verification
- `erlang/auth.erl` — session and credential management with Mnesia
