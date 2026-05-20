-module(counter_server).
-export([start/0]).

%% Start the counter gen_server then begin accepting TCP connections.
start() ->
    {ok, _} = counter:start_link(),
    {ok, LSock} = gen_tcp:listen(9090, [
        binary,
        {packet, line},    %% framing: each recv delivers one newline-terminated line
        {active, false},   %% blocking recv rather than message-based
        {reuseaddr, true}
    ]),
    io:format("counter_server listening on port 9090~n"),
    accept_loop(LSock).

%% Accept connections forever; spawn a handler process per client so the
%% server can serve multiple clients concurrently.
accept_loop(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    spawn(fun() -> client_loop(Sock) end),
    accept_loop(LSock).

%% Read one line at a time from the client socket, dispatch to the counter
%% gen_server, and send back a response line.
client_loop(Sock) ->
    case gen_tcp:recv(Sock, 0) of
        {ok, <<"increment\n">>} ->
            counter:increment(default),
            gen_tcp:send(Sock, "ok\n"),
            client_loop(Sock);
        {ok, <<"decrement\n">>} ->
            counter:decrement(default),
            gen_tcp:send(Sock, "ok\n"),
            client_loop(Sock);
        {ok, <<"reset\n">>} ->
            counter:reset(default),
            gen_tcp:send(Sock, "ok\n"),
            client_loop(Sock);
        {ok, <<"value\n">>} ->
            V = counter:value(default),
            gen_tcp:send(Sock, [integer_to_list(V), "\n"]),
            client_loop(Sock);
        {ok, _} ->
            gen_tcp:send(Sock, "error: unknown command\n"),
            client_loop(Sock);
        {error, closed} ->
            ok
    end.
