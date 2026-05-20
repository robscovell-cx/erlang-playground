/*
 * Passkey (WebAuthn) authentication — plain JavaScript.
 *
 * Each ceremony is a two-round-trip flow:
 *   1. Ask the server to generate a challenge  (begin endpoint)
 *   2. Ask the authenticator to act on it      (navigator.credentials)
 *   3. Send the result back to the server      (complete endpoint)
 *
 * The session is maintained via an HttpOnly cookie set by the server on a
 * successful login or registration. HttpOnly means JavaScript cannot read the
 * token, so it cannot be exfiltrated by an XSS attack. The browser sends it
 * automatically with every same-origin request — counter_wasm.c does not need
 * to attach any Authorization header.
 */

const _API = 'http://localhost:8080';

/* ---------------------------------------------------------------------- */
/* Helpers                                                                 */
/* ---------------------------------------------------------------------- */

/* base64url encode.  Uses a loop rather than spread (String.fromCharCode
 * ...new Uint8Array) to avoid exceeding the JavaScript engine's call-stack
 * argument limit on large buffers (typically ~65 000 items). */
function _b64url(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/[+]/g, '-').split('/').join('_').replace(/=/g, '');
}

function _b64url_decode(s) {
    s = s.replace(/-/g, '+').split('_').join('/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

/* Extract an error message from a non-OK response.  Falls back to the HTTP
 * status code if the body is not valid JSON (e.g. a proxy returned HTML). */
async function _err_msg(resp) {
    try { const e = await resp.json(); return e.error || String(resp.status); }
    catch (_) { return String(resp.status); }
}

/* Check that the WebAuthn API is available.  It requires a Secure Context
 * (HTTPS or localhost) and is absent in very old browsers. */
function _webauthn_available() {
    return !!(window.PublicKeyCredential && navigator.credentials);
}

/* ---------------------------------------------------------------------- */
/* Session check — called from Module.onRuntimeInitialized                */
/*                                                                         */
/* Hits /auth/me with the session cookie the browser holds.  If valid,    */
/* switches to the counter panel; otherwise leaves the auth panel shown.  */
/* ---------------------------------------------------------------------- */

async function authCheckSession() {
    try {
        const r = await fetch(_API + '/auth/me');
        if (r.ok) {
            const data = await r.json();
            Module.showCounterPanel(data.username);
        }
        /* 401 or network error → stay on auth panel */
    } catch (_) {}
}

/* ---------------------------------------------------------------------- */
/* Registration                                                            */
/* ---------------------------------------------------------------------- */

async function authRegister() {
    const usernameEl = document.getElementById('username-input');
    const statusEl   = document.getElementById('auth-status');
    const username   = usernameEl ? usernameEl.value.trim() : '';
    if (!username) { if (statusEl) statusEl.textContent = 'Enter a username'; return; }

    if (!_webauthn_available()) {
        if (statusEl) statusEl.textContent = 'Passkeys are not supported in this browser';
        return;
    }

    try {
        /* Step 1 — get a challenge, RP metadata, and a random user ID from
         * the server.  The user ID is a random value, not the username: the
         * WebAuthn spec warns against using PII for user.id because it may be
         * stored on the authenticator and could be read off the device. */
        const r1 = await fetch(_API + '/auth/register/begin', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body:    JSON.stringify({username})
        });
        if (!r1.ok) {
            if (statusEl) statusEl.textContent = 'Error: ' + (await _err_msg(r1));
            return;
        }
        const opts = await r1.json();

        /* Step 2 — ask the authenticator (Touch ID / security key) to create
         * a new key pair.  This is what triggers the biometric prompt.
         * alg: -7 = ES256 (ECDSA with P-256 and SHA-256). */
        const cred = await navigator.credentials.create({publicKey: {
            challenge:        _b64url_decode(opts.challenge),
            rp:               {id: opts.rpId, name: opts.rpName},
            user:             {id:          _b64url_decode(opts.userId),
                               name:        username,
                               displayName: username},
            pubKeyCredParams: [{type: 'public-key', alg: -7}],
            authenticatorSelection: {residentKey: 'preferred',
                                     userVerification: 'preferred'},
            attestation: 'none',
            timeout:     60000
        }});

        /* Step 3 — send the attestation to the server.  The server verifies
         * the signed authData, extracts the public key, stores the credential,
         * and sets an HttpOnly session cookie.  No token appears in the JSON
         * body — it lives only in the cookie, invisible to JavaScript. */
        const r2 = await fetch(_API + '/auth/register/complete', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username,
                challenge:         opts.challenge,
                attestationObject: _b64url(cred.response.attestationObject),
                clientDataJSON:    _b64url(cred.response.clientDataJSON)
            })
        });
        if (r2.ok) {
            const data = await r2.json();
            Module.showCounterPanel(data.username);
        } else {
            if (statusEl) statusEl.textContent = 'Registration failed: ' + (await _err_msg(r2));
        }
    } catch (err) {
        if (statusEl) statusEl.textContent = 'Registration error: ' + err.message;
    }
}

/* ---------------------------------------------------------------------- */
/* Login (assertion)                                                       */
/* ---------------------------------------------------------------------- */

async function authLogin() {
    const usernameEl = document.getElementById('username-input');
    const statusEl   = document.getElementById('auth-status');
    const username   = usernameEl ? usernameEl.value.trim() : '';
    if (!username) { if (statusEl) statusEl.textContent = 'Enter a username'; return; }

    if (!_webauthn_available()) {
        if (statusEl) statusEl.textContent = 'Passkeys are not supported in this browser';
        return;
    }

    try {
        /* Step 1 — get a challenge and the credential IDs registered for
         * this user so the authenticator knows which private key to use. */
        const r1 = await fetch(_API + '/auth/login/begin', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body:    JSON.stringify({username})
        });
        if (!r1.ok) {
            if (statusEl) statusEl.textContent = 'Error: ' + (await _err_msg(r1));
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
                                  type: 'public-key',
                                  id:   _b64url_decode(c.id)
                              })),
            userVerification: 'preferred',
            timeout:          60000
        }});

        /* Step 3 — send the assertion to the server.  The server verifies the
         * ECDSA signature, checks the sign count, and sets the session cookie. */
        const r2 = await fetch(_API + '/auth/login/complete', {
            method:  'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                credentialId:      _b64url(assertion.rawId),
                authenticatorData: _b64url(assertion.response.authenticatorData),
                clientDataJSON:    _b64url(assertion.response.clientDataJSON),
                signature:         _b64url(assertion.response.signature)
            })
        });
        if (r2.ok) {
            const data = await r2.json();
            Module.showCounterPanel(data.username);
        } else {
            if (statusEl) statusEl.textContent = 'Login failed: ' + (await _err_msg(r2));
        }
    } catch (err) {
        if (statusEl) statusEl.textContent = 'Login error: ' + err.message;
    }
}

/* ---------------------------------------------------------------------- */
/* Logout                                                                  */
/* ---------------------------------------------------------------------- */

async function authLogout() {
    /* Fire and forget — the server deletes the session row and returns
     * Set-Cookie: session=; Max-Age=0 to clear the browser's cookie.
     * Navigate back to the auth panel immediately regardless of outcome. */
    try {
        await fetch(_API + '/auth/logout', {method: 'POST'});
    } catch (_) {}
    Module.showAuthPanel();
}
