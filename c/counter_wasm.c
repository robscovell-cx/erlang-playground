#include <emscripten.h>
#include <emscripten/fetch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define API_BASE "http://localhost:8080"

/*
 * Read the session token from the JS auth module into a C buffer.
 * auth.js stores it in window.__sessionToken; this EM_JS bridge copies it
 * into WASM memory so do_fetch() can attach it as a Bearer header.
 * Returns 1 if a token is present, 0 if the user is not logged in.
 */
EM_JS(int, js_copy_session_token, (char *buf, int len), {
    const tok = window.__sessionToken || "";
    if (!tok) return 0;
    stringToUTF8(tok, buf, len);
    return 1;
});

static void on_success(emscripten_fetch_t *fetch) {
    if (fetch->status == 401) {
        /* Session expired or revoked server-side. Clear the JS token and
         * return to the auth panel so the user can log in again. */
        EM_ASM({
            window.__sessionToken = "";
            Module.showAuthPanel();
        });
        emscripten_fetch_close(fetch);
        return;
    }
    char *val = malloc(fetch->numBytes + 1);
    memcpy(val, fetch->data, fetch->numBytes);
    val[fetch->numBytes] = '\0';
    EM_ASM({
        document.getElementById('counter-value').textContent = UTF8ToString($0);
        document.getElementById('status').textContent = "";
    }, val);
    free(val);
    emscripten_fetch_close(fetch);
}

static void on_error(emscripten_fetch_t *fetch) {
    EM_ASM(
        document.getElementById('status').textContent = 'Connection error';
    );
    emscripten_fetch_close(fetch);
}

static void do_fetch(const char *method, const char *url) {
    emscripten_fetch_attr_t attr;
    emscripten_fetch_attr_init(&attr);
    strcpy(attr.requestMethod, method);
    attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
    attr.onsuccess  = on_success;
    attr.onerror    = on_error;

    static char token_buf[128];
    static char auth_header[160];
    if (js_copy_session_token(token_buf, sizeof(token_buf))) {
        snprintf(auth_header, sizeof(auth_header), "Bearer %s", token_buf);
        static const char *headers[] = {"Authorization", auth_header, NULL};
        attr.requestHeaders = headers;
    }

    emscripten_fetch(&attr, url);
}

EMSCRIPTEN_KEEPALIVE void increment()     { do_fetch("POST", API_BASE "/increment"); }
EMSCRIPTEN_KEEPALIVE void decrement()     { do_fetch("POST", API_BASE "/decrement"); }
EMSCRIPTEN_KEEPALIVE void reset_counter() { do_fetch("POST", API_BASE "/reset"); }
EMSCRIPTEN_KEEPALIVE void refresh()       { do_fetch("GET",  API_BASE "/value"); }
