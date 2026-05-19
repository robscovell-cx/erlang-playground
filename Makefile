CC           = cc
CFLAGS       = -Wall -Wextra
ERLC         = erlc
COUNTER_PORT = 9090

C_BINS = counter_client counter_tests wc
BEAMS  = counter.beam counter_server.beam

.PHONY: all clean test

all: $(C_BINS) $(BEAMS)

counter_client: counter_client.c counter_proto.h
	$(CC) $(CFLAGS) -o $@ $<

counter_tests: counter_tests.c counter_proto.h
	$(CC) $(CFLAGS) -o $@ $<

wc: wc.c
	$(CC) $(CFLAGS) -o $@ $<

%.beam: %.erl
	$(ERLC) $<

test: all
	@lsof -ti:$(COUNTER_PORT) | xargs kill -9 2>/dev/null; true
	@erl -noshell -s counter_server start & \
	SERVER=$$!; \
	sleep 1; \
	./counter_tests; \
	RESULT=$$?; \
	kill $$SERVER 2>/dev/null; \
	exit $$RESULT

clean:
	rm -f $(C_BINS) $(BEAMS) erl_crash.dump
