CC           = cc
CFLAGS       = -Wall -Wextra
ERLC         = erlc
COUNTER_PORT = 9090
BUILD        = build

C_BINS = $(BUILD)/counter_client $(BUILD)/counter_tests $(BUILD)/wc
BEAMS  = $(BUILD)/counter.beam $(BUILD)/counter_server.beam

.PHONY: all clean test

all: $(BUILD) $(C_BINS) $(BEAMS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/counter_client: counter_client.c counter_proto.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/counter_tests: counter_tests.c counter_proto.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/wc: wc.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/%.beam: %.erl | $(BUILD)
	$(ERLC) -o $(BUILD) $<

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
