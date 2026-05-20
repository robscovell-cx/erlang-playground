#include <emscripten.h>
#include <emscripten/fetch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


char g_session_token[128] = {0};
char g_username[256]      = {0};

/* ---------- registration ------------------------------------------------- */

EM_ASYNC_JS(void, auth_register_async, (), {
    /* b64url/b64url_decode avoid /\// regex (triggers C // comment) */
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

        const allowCreds = (opts.allowCredentials || []).map(c => ({
            type: "public-key",
            id: b64url_decode(c.id)
        }));

        const assertion = await navigator.credentials.get({publicKey: {
            challenge: b64url_decode(opts.challenge),
            rpId: opts.rpId,
            allowCredentials: allowCreds,
            userVerification: "preferred",
            timeout: 60000
        }});

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

EMSCRIPTEN_KEEPALIVE void auth_register(void) {
    auth_register_async();
}

EMSCRIPTEN_KEEPALIVE void auth_login(void) {
    auth_login_async(g_session_token, sizeof(g_session_token),
                     g_username,      sizeof(g_username));
}

EMSCRIPTEN_KEEPALIVE void auth_logout(void) {
    auth_logout_async(g_session_token);
    memset(g_session_token, 0, sizeof(g_session_token));
    memset(g_username,      0, sizeof(g_username));
}

EMSCRIPTEN_KEEPALIVE int auth_is_logged_in(void) {
    return g_session_token[0] != '\0';
}
