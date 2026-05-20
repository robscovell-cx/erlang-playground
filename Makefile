CC           = cc
CFLAGS       = -Wall -Wextra
ERLC         = erlc
EMCC         = emcc
EMFLAGS      = -O2 -sFETCH \
               -sEXPORTED_FUNCTIONS='["_increment","_decrement","_reset_counter","_refresh"]' \
               -sEXPORTED_RUNTIME_METHODS='["UTF8ToString","stringToUTF8"]'
COUNTER_PORT = 9090
HTTP_PORT    = 8080
BUILD        = build
ERLDIR       = erlang
CDIR         = c
FRONTEND_SRC = frontend
FRONTEND_BUILD = $(BUILD)/frontend

C_BINS = $(BUILD)/counter_client $(BUILD)/counter_tests
BEAMS  = $(BUILD)/counter.beam $(BUILD)/counter_server.beam $(BUILD)/counter_http.beam \
         $(BUILD)/auth.beam $(BUILD)/auth_http.beam \
         $(BUILD)/webauthn.beam $(BUILD)/webauthn_cbor.beam

.PHONY: all wasm serve test clean

all: $(BUILD) $(C_BINS) $(BEAMS)

$(BUILD):
	mkdir -p $(BUILD)

$(FRONTEND_BUILD):
	mkdir -p $(FRONTEND_BUILD)

$(BUILD)/counter_client: $(CDIR)/counter_client.c $(CDIR)/counter_proto.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/counter_tests: $(CDIR)/counter_tests.c $(CDIR)/counter_proto.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/%.beam: $(ERLDIR)/%.erl | $(BUILD)
	$(ERLC) -o $(BUILD) $<

## Build the WASM module and copy frontend files into build/frontend/.
wasm: $(FRONTEND_BUILD)
	$(EMCC) $(CDIR)/counter_wasm.c \
	    -o $(FRONTEND_BUILD)/counter.js $(EMFLAGS)
	cp $(FRONTEND_SRC)/index.html $(FRONTEND_BUILD)/
	cp $(FRONTEND_SRC)/auth.js    $(FRONTEND_BUILD)/

## Start the Erlang HTTP server. It serves the API and the frontend from build/frontend/.
serve: all wasm
	@lsof -ti:$(HTTP_PORT) | xargs kill -9 2>/dev/null; true
	erl -noshell -pa $(BUILD) -s counter_http start

test: all
	@lsof -ti:$(COUNTER_PORT) | xargs kill -9 2>/dev/null; true
	@erl -noshell -pa $(BUILD) -s counter_server start & \
	SERVER=$$!; \
	sleep 1; \
	$(BUILD)/counter_tests; \
	RESULT=$$?; \
	kill $$SERVER 2>/dev/null; \
	exit $$RESULT

clean:
	rm -rf $(BUILD) erl_crash.dump
