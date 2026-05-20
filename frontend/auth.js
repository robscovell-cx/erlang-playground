/*
 * Passkey (WebAuthn) authentication — plain JavaScript.
 *
 * Each ceremony is a two-round-trip flow:
 *   1. Ask the server to generate a challenge  (begin endpoint)
 *   2. Ask the authenticator to act on it      (navigator.credentials)
 *   3. Send the result back to the server      (complete endpoint)
 *
 * The session token is stored in window.__sessionToken.  counter_wasm.c reads
 * it from there via an EM_JS bridge and attaches it as an Authorization header
 * on every counter request.
 */

const _API = "http://localhost:8080";

/* Session state.  Lives on window so counter_wasm.c can read it from C via
 * an EM_JS call.  Resets on every hard page load (no localStorage / cookie). */
window.__sessionToken = "";

function authIsLoggedIn() {
    return window.__sessionToken !== "";
}

/* base64url encode/decode — needed to convert between the binary buffers the
 * WebAuthn API produces and the strings the server JSON API expects. */
function _b64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/[+]/g, "-").split("/").join("_").replace(/=/g, "");
}

function _b64url_decode(s) {
    s = s.replace(/-/g, "+").split("_").join("/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

/* ---------------------------------------------------------------------- */
/* Registration                                                            */
/* ---------------------------------------------------------------------- */

async function authRegister() {
    const usernameEl = document.getElementById("username-input");
    const statusEl   = document.getElementById("auth-status");
    const username   = usernameEl ? usernameEl.value.trim() : "";
    if (!username) { if (statusEl) statusEl.textContent = "Enter a username"; return; }

    try {
        /* Step 1 — get a challenge and RP metadata from the server. */
        const r1 = await fetch(_API + "/auth/register/begin", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body:    JSON.stringify({username})
        });
        if (!r1.ok) {
            const e = await r1.json();
            if (statusEl) statusEl.textContent = "Error: " + (e.error || r1.status);
            return;
        }
        const opts = await r1.json();

        /* Step 2 — ask the authenticator (Touch ID / security key) to create
         * a new key pair.  This is what triggers the biometric prompt.
         * alg: -7 = ES256 (ECDSA with P-256 and SHA-256). */
        const cred = await navigator.credentials.create({publicKey: {
            challenge:        _b64url_decode(opts.challenge),
            rp:               {id: opts.rpId, name: opts.rpName},
            user:             {id: new TextEncoder().encode(username),
                               name: username, displayName: username},
            pubKeyCredParams: [{type: "public-key", alg: -7}],
            authenticatorSelection: {residentKey: "preferred",
                                     userVerification: "preferred"},
            attestation: "none",
            timeout:     60000
        }});

        /* Step 3 — send the attestation to the server.  The server verifies
         * the signed authData, extracts the public key, and stores the
         * credential.  On success it also creates a session token so we are
         * immediately logged in without a separate login step. */
        const r2 = await fetch(_API + "/auth/register/complete", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                username,
                challenge:         opts.challenge,
                attestationObject: _b64url(cred.response.attestationObject),
                clientDataJSON:    _b64url(cred.response.clientDataJSON)
            })
        });
        if (r2.ok) {
            const data = await r2.json();
            window.__sessionToken = data.token;
            Module.showCounterPanel(username);
        } else {
            const e = await r2.json();
            if (statusEl) statusEl.textContent = "Registration failed: " + (e.error || r2.status);
        }
    } catch (err) {
        if (statusEl) statusEl.textContent = "Registration error: " + err.message;
    }
}

/* ---------------------------------------------------------------------- */
/* Login (assertion)                                                       */
/* ---------------------------------------------------------------------- */

async function authLogin() {
    const usernameEl = document.getElementById("username-input");
    const statusEl   = document.getElementById("auth-status");
    const username   = usernameEl ? usernameEl.value.trim() : "";
    if (!username) { if (statusEl) statusEl.textContent = "Enter a username"; return; }

    try {
        /* Step 1 — get a challenge and the credential IDs registered for
         * this user so the authenticator knows which private key to use. */
        const r1 = await fetch(_API + "/auth/login/begin", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body:    JSON.stringify({username})
        });
        if (!r1.ok) {
            const e = await r1.json();
            if (statusEl) statusEl.textContent = "Error: " + (e.error || r1.status);
            return;
        }
        const opts = await r1.json();

        /* Step 2 — ask the authenticator to sign the challenge.
         * allowCredentials narrows which key to use; if the user has only
         * one registered device the browser picks it automatically. */
        const assertion = await navigator.credentials.get({publicKey: {
            challenge:        _b64url_decode(opts.challenge),
            rpId:             opts.rpId,
            allowCredentials: (opts.allowCredentials || []).map(c => ({
                                  type: "public-key",
                                  id:   _b64url_decode(c.id)
                              })),
            userVerification: "preferred",
            timeout:          60000
        }});

        /* Step 3 — send the assertion to the server.  The server verifies
         * the ECDSA signature against the stored public key, checks the
         * sign count, and issues a session token. */
        const r2 = await fetch(_API + "/auth/login/complete", {
            method:  "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                credentialId:      _b64url(assertion.rawId),
                authenticatorData: _b64url(assertion.response.authenticatorData),
                clientDataJSON:    _b64url(assertion.response.clientDataJSON),
                signature:         _b64url(assertion.response.signature)
            })
        });
        if (r2.ok) {
            const data = await r2.json();
            window.__sessionToken = data.token;
            Module.showCounterPanel(data.username);
        } else {
            const e = await r2.json();
            if (statusEl) statusEl.textContent = "Login failed: " + (e.error || r2.status);
        }
    } catch (err) {
        if (statusEl) statusEl.textContent = "Login error: " + err.message;
    }
}

/* ---------------------------------------------------------------------- */
/* Logout                                                                  */
/* ---------------------------------------------------------------------- */

async function authLogout() {
    const token = window.__sessionToken;
    /* Clear the token immediately so counter_wasm.c stops sending it even if
     * the network request below is slow or fails. */
    window.__sessionToken = "";
    try {
        await fetch(_API + "/auth/logout", {
            method:  "POST",
            headers: {"Content-Type": "application/json",
                      "Authorization": "Bearer " + token},
            body:    "{}"
        });
    } catch (_) {}
    Module.showAuthPanel();
}
