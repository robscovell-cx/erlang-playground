-module(counter_http).
-export([start/0]).

-define(HTTP_PORT, 8080).
-define(FRONTEND_DIR, "build/frontend").

start() ->
    {ok, _} = counter:start_link(),
    {ok, LSock} = gen_tcp:listen(?HTTP_PORT, [
        binary, {active, false}, {reuseaddr, true}
    ]),
    io:format("counter_http listening on http://localhost:~w~n", [?HTTP_PORT]),
    accept_loop(LSock).

accept_loop(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    spawn(fun() -> handle_client(Sock) end),
    accept_loop(LSock).

%% Switch to HTTP packet mode to let the runtime parse the request line,
%% then drain remaining headers, then switch back to raw for sending.
handle_client(Sock) ->
    inet:setopts(Sock, [{packet, http_bin}]),
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, {http_request, Method, {abs_path, Path}, _}} ->
            skip_headers(Sock),
            inet:setopts(Sock, [{packet, raw}]),
            gen_tcp:send(Sock, route(Method, Path));
        _ ->
            ok
    end,
    gen_tcp:close(Sock).

skip_headers(Sock) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, http_eoh} -> ok;
        {ok, _}        -> skip_headers(Sock);
        _              -> ok
    end.

%% CORS preflight — browsers send OPTIONS before cross-origin POSTs.
route('OPTIONS', _) ->
    response(200, "text/plain", <<>>);
route('GET', <<"/">>) ->
    serve_file("index.html");
route('GET', <<"/value">>) ->
    respond_value();
route('POST', <<"/increment">>) ->
    counter:increment(), respond_value();
route('POST', <<"/decrement">>) ->
    counter:decrement(), respond_value();
route('POST', <<"/reset">>) ->
    counter:reset(), respond_value();
route('GET', <<"/", File/binary>>) ->
    serve_file(binary_to_list(File));
route(_, _) ->
    response(404, "text/plain", <<"Not Found">>).

respond_value() ->
    response(200, "text/plain",
             list_to_binary(integer_to_list(counter:value()))).

serve_file(File) ->
    Path = ?FRONTEND_DIR ++ "/" ++ File,
    case file:read_file(Path) of
        {ok, Data} -> response(200, mime(filename:extension(File)), Data);
        {error, _} -> response(404, "text/plain", <<"Not Found">>)
    end.

mime(".html") -> "text/html";
mime(".js")   -> "application/javascript";
mime(".wasm") -> "application/wasm";
mime(_)       -> "application/octet-stream".

cors_headers() ->
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n".

response(Code, ContentType, Body) ->
    Len = byte_size(Body),
    [status_line(Code),
     "Content-Type: ", ContentType, "\r\n",
     cors_headers(),
     io_lib:format("Content-Length: ~w\r\n\r\n", [Len]),
     Body].

status_line(200) -> "HTTP/1.1 200 OK\r\n";
status_line(404) -> "HTTP/1.1 404 Not Found\r\n".
