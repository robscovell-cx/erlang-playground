/*
 * Browser-side passkey authentication, compiled to WebAssembly via Emscripten.
 *
 * Passkeys (WebAuthn) work by letting the browser talk to a hardware
 * authenticator (Touch ID, Windows Hello, a security key). The authenticator
 * holds private keys that never leave the device. The server only ever sees
 * public keys and signed challenges.
 *
 * The two ceremonies implemented here:
 *
 *   Registration  — Create a new key pair on the authenticator, send the
 *                   public key to the server. Triggered by auth_register().
 *
 *   Login (assertion) — Sign a server-issued challenge with the private key.
 *                   The server verifies the signature. Triggered by auth_login().
 *
 * Each ceremony is a two-round-trip flow:
 *   1. Ask the server to generate a challenge (begin endpoint).
 *   2. Ask the authenticator to act on it (navigator.credentials).
 *   3. Send the authenticator's response back to the server (complete endpoint).
 *
 * EM_ASYNC_JS compiles the JS body via Emscripten's Asyncify mechanism, which
 * rewrites the WASM binary so the C stack can be suspended while awaiting an
 * async JS operation (fetch, navigator.credentials) without blocking the
 * browser event loop.
 *
 * Important: C preprocessor macros are NOT expanded inside EM_ASYNC_JS bodies
 * because the # operator stringifies without macro-expanding. Use literal
 * strings instead of #defines.
 */
#include <emscripten.h>
#include <emscripten/fetch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Session state lives in C globals so counter_wasm.c can read them.
 * Written by auth_login_async via Emscripten's stringToUTF8 helper.
 * Read by auth_is_logged_in() and counter_wasm.c's do_fetch(). */
char g_session_token[128] = {0};
char g_username[256]      = {0};

/* ---------- registration ------------------------------------------------- */

/*
 * Full registration flow in a single async JS function.
 *
 * Base64url helpers are inlined here (and again in auth_login_async) because
 * each EM_ASYNC_JS body is its own JS function scope — there is no shared
 * scope between EM_ASYNC_JS bodies.
 *
 * The helpers avoid /\// regex because the C preprocessor sees // as a line
 * comment inside the macro body. /[+]/ is used instead of /\+/ because the
 * # stringification operator strips backslashes.
 */
EM_ASYNC_JS(void, auth_register_async, (), {
    const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/[+]/g, "-").split("/").join("_").replace(/=/g, "");
    const b64url_decode = s => {
        s = s.replace(/-/g, "+").split("_").join("/");
        while (s.length % 4) s += "=";
        return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    };

    const usernameEl = document.getElementById("username-input");
    const statusEl   = document.getElementById("auth-status");
    const username   = usernameEl ? usernameEl.value.trim() : "";
    if (!username) { if (statusEl) statusEl.textContent = "Enter a username"; return; }

    try {
        /* Step 1: ask the server for a challenge and RP metadata. */
        const r1 = await fetch("http://localhost:8080" + "/auth/register/begin", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username})
        });
        if (!r1.ok) {
            const e = await r1.json();
            if (statusEl) statusEl.textContent = "Error: " + (e.error || r1.status);
            return;
        }
        const opts = await r1.json();

        /*
         * Step 2: ask the authenticator (Touch ID / security key) to create a
         * new key pair. This is what triggers the biometric prompt.
         *
         *   challenge        — raw bytes we got from the server (decoded from base64url)
         *   rp               — identifies our site; authenticator binds the key to this
         *   user             — identifies the account on the authenticator's side
         *   pubKeyCredParams — alg: -7 means ES256 (ECDSA with P-256 and SHA-256)
         *   attestation      — "none": we don't need a hardware proof of device model
         */
        const cred = await navigator.credentials.create({publicKey: {
            challenge: b64url_decode(opts.challenge),
            rp: {id: opts.rpId, name: opts.rpName},
            user: {
                id: new TextEncoder().encode(username),
                name: username,
                displayName: username
            },
            pubKeyCredParams: [{type: "public-key", alg: -7}],
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "preferred"
            },
            attestation: "none",
            timeout: 60000
        }});

        /*
         * Step 3: send the authenticator's response to the server.
         *
         *   attestationObject — CBOR blob containing the new public key and
         *                       a proof that the authenticator generated it
         *   clientDataJSON    — JSON the browser constructed, including the
         *                       challenge and origin; the server checks these
         */
        const r2 = await fetch("http://localhost:8080" + "/auth/register/complete", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                username,
                challenge:         opts.challenge,
                attestationObject: b64url(cred.response.attestationObject),
                clientDataJSON:    b64url(cred.response.clientDataJSON)
            })
        });
        if (r2.ok) {
            Module.showCounterPanel(username);
        } else {
            const e = await r2.json();
            if (statusEl) statusEl.textContent = "Registration failed: " + (e.error || r2.status);
        }
    } catch(err) {
        if (statusEl) statusEl.textContent = "Registration error: " + err.message;
    }
});

/* ---------- login --------------------------------------------------------- */

/*
 * Full authentication (assertion) flow.
 *
 * token_buf / token_len and user_buf / user_len are C memory locations.
 * Emscripten's stringToUTF8 writes the JS strings into them directly, so the
 * C globals g_session_token and g_username are populated without any extra
 * copying.
 */
EM_ASYNC_JS(void, auth_login_async, (char *token_buf, int token_len,
                                     char *user_buf,  int user_len), {
    const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/[+]/g, "-").split("/").join("_").replace(/=/g, "");
    const b64url_decode = s => {
        s = s.replace(/-/g, "+").split("_").join("/");
        while (s.length % 4) s += "=";
        return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    };

    const usernameEl = document.getElementById("username-input");
    const statusEl   = document.getElementById("auth-status");
    const username   = usernameEl ? usernameEl.value.trim() : "";
    if (!username) { if (statusEl) statusEl.textContent = "Enter a username"; return; }

    try {
        /* Step 1: get a challenge and the list of registered credential IDs. */
        const r1 = await fetch("http://localhost:8080" + "/auth/login/begin", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({username})
        });
        if (!r1.ok) {
            const e = await r1.json();
            if (statusEl) statusEl.textContent = "Error: " + (e.error || r1.status);
            return;
        }
        const opts = await r1.json();

        /* Convert the allowCredentials list from base64url strings to byte arrays.
         * The authenticator uses these IDs to find the matching private key. */
        const allowCreds = (opts.allowCredentials || []).map(c => ({
            type: "public-key",
            id: b64url_decode(c.id)
        }));

        /*
         * Step 2: ask the authenticator to sign the challenge.
         * This triggers the biometric prompt. The authenticator finds the
         * private key matching one of the allowed credential IDs, signs
         * (authenticatorData ++ sha256(clientDataJSON)), and returns the
         * assertion object.
         */
        const assertion = await navigator.credentials.get({publicKey: {
            challenge: b64url_decode(opts.challenge),
            rpId: opts.rpId,
            allowCredentials: allowCreds,
            userVerification: "preferred",
            timeout: 60000
        }});

        /*
         * Step 3: send the assertion to the server for verification.
         *
         *   credentialId      — which key was used (server looks up the public key)
         *   authenticatorData — device flags and sign count, signed by the device
         *   clientDataJSON    — browser's record of what was requested (incl. challenge)
         *   signature         — ECDSA signature over authData ++ sha256(clientDataJSON)
         */
        const r2 = await fetch("http://localhost:8080" + "/auth/login/complete", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                credentialId:      b64url(assertion.rawId),
                authenticatorData: b64url(assertion.response.authenticatorData),
                clientDataJSON:    b64url(assertion.response.clientDataJSON),
                signature:         b64url(assertion.response.signature)
            })
        });
        if (r2.ok) {
            const data = await r2.json();
            /* Write the session token and username into C memory so counter_wasm.c
             * can attach the Bearer token to subsequent counter requests. */
            stringToUTF8(data.token,    token_buf, token_len);
            stringToUTF8(data.username, user_buf,  user_len);
            Module.showCounterPanel(data.username);
        } else {
            const e = await r2.json();
            if (statusEl) statusEl.textContent = "Login failed: " + (e.error || r2.status);
        }
    } catch(err) {
        if (statusEl) statusEl.textContent = "Login error: " + err.message;
    }
});

/* ---------- logout -------------------------------------------------------- */

/*
 * Tell the server to invalidate the session, then show the auth panel.
 * We fire-and-forget the fetch — even if it fails, the client-side state
 * is cleared and the user is effectively logged out locally.
 */
EM_ASYNC_JS(void, auth_logout_async, (char *token_buf), {
    const token = UTF8ToString(token_buf);
    try {
        await fetch("http://localhost:8080" + "/auth/logout", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: "{}"
        });
    } catch(_) {}
    Module.showAuthPanel();
});

/* ---------- exported C API ----------------------------------------------- */

/*
 * These thin wrappers are exported to JavaScript via EMSCRIPTEN_KEEPALIVE so
 * the HTML can call them with Module.ccall(). They bridge into the EM_ASYNC_JS
 * bodies which then suspend the C stack while JS awaits async operations.
 */

EMSCRIPTEN_KEEPALIVE void auth_register(void) {
    auth_register_async();
}

EMSCRIPTEN_KEEPALIVE void auth_login(void) {
    /* Pass pointers to the C globals so the JS body can write results directly. */
    auth_login_async(g_session_token, sizeof(g_session_token),
                     g_username,      sizeof(g_username));
}

EMSCRIPTEN_KEEPALIVE void auth_logout(void) {
    auth_logout_async(g_session_token);
    /* Clear both globals so auth_is_logged_in() returns false immediately
     * and counter_wasm.c stops sending the stale token. */
    memset(g_session_token, 0, sizeof(g_session_token));
    memset(g_username,      0, sizeof(g_username));
}

/* The HTML calls this on startup to decide whether to show the auth panel
 * or go straight to the counter (e.g. after a soft page reload). Since the
 * token lives in a C global (not a cookie or localStorage), it resets on
 * every hard page load — the user must log in again after closing the tab. */
EMSCRIPTEN_KEEPALIVE int auth_is_logged_in(void) {
    return g_session_token[0] != '\0';
}
