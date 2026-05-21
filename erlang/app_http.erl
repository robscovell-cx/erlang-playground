-module(app_http).
-export([start/0]).

-define(HTTP_PORT, 8080).
-define(FRONTEND_DIR, "build/frontend").

start() ->
    {ok, _} = counter:start_link(),
    {ok, _} = auth:start_link(),
    {ok, _} = user_address:start_link(),
    {ok, LSock} = gen_tcp:listen(?HTTP_PORT, [
        binary, {active, false}, {reuseaddr, true}
    ]),
    io:format("app_http listening on http://localhost:~w~n", [?HTTP_PORT]),
    accept_loop(LSock).

accept_loop(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock),
    spawn(fun() -> handle_client(Sock) end),
    accept_loop(LSock).

handle_client(Sock) ->
    inet:setopts(Sock, [{packet, http_bin}]),
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, {http_request, Method, {abs_path, Path}, _}} ->
            {ContentLength, Token} = collect_headers(Sock, 0, undefined),
            inet:setopts(Sock, [{packet, raw}]),
            Body = read_body(Sock, ContentLength),
            gen_tcp:send(Sock, route(Method, Path, Body, Token));
        _ ->
            ok
    end,
    gen_tcp:close(Sock).

collect_headers(Sock, Len, Token) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, http_eoh} ->
            {Len, Token};
        {ok, {http_header, _, 'Content-Length', _, Val}} ->
            collect_headers(Sock, binary_to_integer(Val), Token);
        {ok, {http_header, _, 'Cookie', _, Val}} ->
            T = parse_session_cookie(Val),
            collect_headers(Sock, Len, T);
        {ok, _} ->
            collect_headers(Sock, Len, Token);
        _ ->
            {Len, Token}
    end.

%% Extract the "session" value from a Cookie header.
%% Cookie header format: "name1=val1; name2=val2; ..."
parse_session_cookie(CookieHeader) ->
    Parts = binary:split(CookieHeader, <<"; ">>, [global]),
    case [V || <<"session=", V/binary>> <- Parts] of
        [Token | _] -> Token;
        []          -> undefined
    end.

read_body(_Sock, 0)   -> <<>>;
read_body(Sock, Len) ->
    case gen_tcp:recv(Sock, Len, 5000) of
        {ok, Data} -> Data;
        _          -> <<>>
    end.

route('OPTIONS', _, _, _) ->
    response(200, "text/plain", <<>>);

%% Auth routes — delegate entirely to auth_http.
%% A new project replaces app_route/4 with its own logic; everything above
%% this clause is unchanged.
route(Method, Path, Body, Token) ->
    case auth_http:route(Method, Path, Body, Token) of
        not_auth_route     -> app_route(Method, Path, Body, Token);
        {Code, Hdrs, Resp} -> response(Code, "application/json", Hdrs, Resp)
    end.

%% User address routes — session required
app_route('GET',  <<"/user_address">>,    _, Token) -> session_guard_state(get, user_address, <<>>, Token);
app_route('POST', <<"/user_address">>, Body, Token) -> session_guard_state(put, user_address, Body, Token);

%% Counter routes — session required
app_route(Method, <<"/value">> = Path, Body, Token)     -> session_guard(Method, Path, Body, Token);
app_route(Method, <<"/increment">> = Path, Body, Token) -> session_guard(Method, Path, Body, Token);
app_route(Method, <<"/decrement">> = Path, Body, Token) -> session_guard(Method, Path, Body, Token);
app_route(Method, <<"/reset">> = Path, Body, Token)     -> session_guard(Method, Path, Body, Token);

%% Static files — no session required (must come after all API routes)
app_route('GET', <<"/">>, _, _) ->
    serve_file("index.html");
app_route('GET', <<"/", File/binary>>, _, _) ->
    serve_file(binary_to_list(File));

app_route(_, _, _, _) ->
    response(404, "text/plain", <<"Not Found">>).

session_guard(Method, Path, Body, Token) ->
    case auth:validate_session(Token) of
        {ok, User} -> counter_route(Method, Path, Body, User);
        {error, _} -> response(401, "application/json", [],
                           json:encode(#{<<"error">> => <<"Unauthorized">>}))
    end.

counter_route('GET',  <<"/value">>,     _, U) -> respond_value(U);
counter_route('POST', <<"/increment">>, _, U) -> counter:increment(U), respond_value(U);
counter_route('POST', <<"/decrement">>, _, U) -> counter:decrement(U), respond_value(U);
counter_route('POST', <<"/reset">>,     _, U) -> counter:reset(U),     respond_value(U);
counter_route(_, _, _, _)                     -> response(404, "text/plain", <<"Not Found">>).

session_guard_state(get, Mod, _, Token) ->
    case auth:validate_session(Token) of
        {ok, User} ->
            {ok, Data} = Mod:get(User),
            response(200, "application/json", json:encode(Data));
        {error, _} ->
            response(401, "application/json", [],
                     json:encode(#{<<"error">> => <<"Unauthorized">>}))
    end;
session_guard_state(put, Mod, Body, Token) ->
    case auth:validate_session(Token) of
        {ok, User} ->
            ok = Mod:put(User, json:decode(Body)),
            response(200, "application/json", <<"{}">>);
        {error, _} ->
            response(401, "application/json", [],
                     json:encode(#{<<"error">> => <<"Unauthorized">>}))
    end.

respond_value(User) ->
    response(200, "text/plain",
             list_to_binary(integer_to_list(counter:value(User)))).

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
    response(Code, ContentType, [], Body).

response(Code, ContentType, ExtraHeaders, Body) ->
    Bin = iolist_to_binary(Body),
    Len = byte_size(Bin),
    [status_line(Code),
     "Content-Type: ", ContentType, "\r\n",
     cors_headers(),
     [[Name, ": ", Value, "\r\n"] || {Name, Value} <- ExtraHeaders],
     io_lib:format("Content-Length: ~w\r\n\r\n", [Len]),
     Bin].

status_line(200) -> "HTTP/1.1 200 OK\r\n";
status_line(201) -> "HTTP/1.1 201 Created\r\n";
status_line(400) -> "HTTP/1.1 400 Bad Request\r\n";
status_line(401) -> "HTTP/1.1 401 Unauthorized\r\n";
status_line(404) -> "HTTP/1.1 404 Not Found\r\n";
status_line(409) -> "HTTP/1.1 409 Conflict\r\n";
status_line(500) -> "HTTP/1.1 500 Internal Server Error\r\n".
