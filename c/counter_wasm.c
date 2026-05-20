#include <emscripten.h>
#include <emscripten/fetch.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define API_BASE "http://localhost:8080"

extern char g_session_token[128];

static void on_success(emscripten_fetch_t *fetch) {
    if (fetch->status == 401) {
        memset(g_session_token, 0, 128);
        EM_ASM(Module.showAuthPanel());
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

    static char auth_header[160];
    if (g_session_token[0] != '\0') {
        snprintf(auth_header, sizeof(auth_header), "Bearer %s", g_session_token);
        static const char *headers[] = {"Authorization", auth_header, NULL};
        attr.requestHeaders = headers;
    }

    emscripten_fetch(&attr, url);
}

EMSCRIPTEN_KEEPALIVE void increment()     { do_fetch("POST", API_BASE "/increment"); }
EMSCRIPTEN_KEEPALIVE void decrement()     { do_fetch("POST", API_BASE "/decrement"); }
EMSCRIPTEN_KEEPALIVE void reset_counter() { do_fetch("POST", API_BASE "/reset"); }
EMSCRIPTEN_KEEPALIVE void refresh()       { do_fetch("GET",  API_BASE "/value"); }
