#!/usr/bin/env escript
%% Reads a schema YAML file and emits a Mnesia-backed Erlang module and a
%% plain-JavaScript form module.
%%
%% Usage: escript erlang/gen_schema.escript schema/<name>.yaml

main([YamlFile]) ->
    {ok, Text} = file:read_file(YamlFile),
    Lines = string:split(binary_to_list(Text), "\n", all),
    {Table, Fields} = parse_yaml(Lines, undefined, [], #{}),
    emit_erlang(Table, Fields),
    emit_javascript(Table, Fields);
main(_) ->
    io:format("usage: escript gen_schema.escript <schema.yaml>~n"),
    halt(1).

%% ---------------------------------------------------------------------------
%% Minimal YAML parser — flat field lists only
%% ---------------------------------------------------------------------------

parse_yaml([], Table, Fields, Current) ->
    {Table, finish_fields(Fields, Current)};
parse_yaml([Line | Rest], Table, Fields, Current) ->
    Trimmed = string:strip(Line, right),
    case Trimmed of
        ""                  -> parse_yaml(Rest, Table, Fields, Current);
        "#" ++ _            -> parse_yaml(Rest, Table, Fields, Current);
        "  - " ++ KV        ->
            %% Start of a new field entry
            Fields2 = finish_fields(Fields, Current),
            {K, V} = split_kv(KV),
            parse_yaml(Rest, Table, Fields2, #{K => V});
        "    " ++ KV        ->
            %% Additional key in current field
            {K, V} = split_kv(KV),
            parse_yaml(Rest, Table, Fields, Current#{K => V});
        RootKV              ->
            %% Root-level key:value (e.g. "table: user_address")
            {K, V} = split_kv(RootKV),
            NewTable = case K of
                "table" -> V;
                _       -> Table
            end,
            parse_yaml(Rest, NewTable, Fields, Current)
    end.

finish_fields(Fields, Current) when map_size(Current) =:= 0 -> Fields;
finish_fields(Fields, Current) -> Fields ++ [Current].

split_kv(S) ->
    case string:split(S, ":", leading) of
        [K, V] -> {string:strip(K), strip_quotes(string:strip(V))};
        [K]    -> {string:strip(K), ""}
    end.

strip_quotes(S) ->
    S2 = string:strip(S),
    case S2 of
        [$" | Rest] ->
            case lists:reverse(Rest) of
                [$" | Inner] -> lists:reverse(Inner);
                _            -> S2
            end;
        _ -> S2
    end.

%% ---------------------------------------------------------------------------
%% Erlang module emitter
%% ---------------------------------------------------------------------------

emit_erlang(Table, Fields) ->
    OutFile = "erlang/" ++ Table ++ ".erl",
    Names = [maps:get("name", F) || F <- Fields],
    Attrs = string:join(["username" | Names], ", "),
    DefaultMap = fields_to_map(Names, "<<>>"),
    GetMap = fields_to_get_map(Table, Names),
    PutFields = fields_to_put(Table, Names),

    Src = io_lib:format(
        "%% GENERATED -- do not edit. Regenerate: make gen~n"
        "-module(~s).~n"
        "-record(~s, {~s}).~n"
        "-export([start_link/0, get/1, put/2]).~n"
        "~n"
        "start_link() ->~n"
        "    ok = ensure_table(),~n"
        "    {ok, self()}.~n"
        "~n"
        "ensure_table() ->~n"
        "    case mnesia:create_table(~s, [~n"
        "        {attributes, record_info(fields, ~s)},~n"
        "        {disc_copies, [node()]}~n"
        "    ]) of~n"
        "        {atomic, ok}                        -> ok;~n"
        "        {aborted, {already_exists, ~s}} -> ok~n"
        "    end,~n"
        "    mnesia:wait_for_tables([~s], 5000).~n"
        "~n"
        "get(Username) ->~n"
        "    Default = #{~s},~n"
        "    case mnesia:dirty_read(~s, Username) of~n"
        "        []    -> {ok, Default};~n"
        "        [Rec] -> {ok, #{~s}}~n"
        "    end.~n"
        "~n"
        "put(Username, Data) ->~n"
        "    Rec = #~s{~n"
        "        username = Username,~n"
        "        ~s~n"
        "    },~n"
        "    mnesia:dirty_write(Rec).~n"
        "~n"
        "coerce(undefined)              -> <<>>;~n"
        "coerce(V) when is_binary(V)    -> V;~n"
        "coerce(V) when is_list(V)      -> list_to_binary(V);~n"
        "coerce(_)                      -> <<>>.~n",
        [Table, Table, Attrs,
         Table, Table, Table, Table,
         DefaultMap,
         Table, GetMap,
         Table, PutFields]),
    ok = file:write_file(OutFile, Src),
    io:format("wrote ~s~n", [OutFile]).

fields_to_map(Names, Default) ->
    Parts = [io_lib:format("<<\"~s\">> => ~s", [N, Default]) || N <- Names],
    string:join([lists:flatten(P) || P <- Parts], ", ").

fields_to_get_map(Table, Names) ->
    Parts = [io_lib:format("<<\"~s\">> => coerce(Rec#~s.~s)", [N, Table, N])
             || N <- Names],
    string:join([lists:flatten(P) || P <- Parts], ",\n             ").

fields_to_put(_Table, Names) ->
    Parts = [io_lib:format("~s = maps:get(<<\"~s\">>, Data, <<>>)", [N, N])
             || N <- Names],
    string:join([lists:flatten(P) || P <- Parts], ",\n        ").

%% ---------------------------------------------------------------------------
%% JavaScript module emitter
%% ---------------------------------------------------------------------------

emit_javascript(Table, Fields) ->
    OutFile = "frontend/" ++ Table ++ "_form.js",
    Cap = capitalize(Table),
    FieldsJS = fields_to_js(Fields),
    BuildFn  = build_form_fn(Table, Cap),
    LoadFn   = load_fn(Table, Cap),
    SaveFn   = save_fn(Table, Cap),

    Src = io_lib:format(
        "// GENERATED -- do not edit. Regenerate: make gen~n"
        "~n"
        "const _~sFields = [~n~s~n];~n"
        "~n~s~n~s~n~s",
        [Cap, FieldsJS, BuildFn, LoadFn, SaveFn]),
    ok = file:write_file(OutFile, Src),
    io:format("wrote ~s~n", [OutFile]).

fields_to_js(Fields) ->
    Parts = [io_lib:format("    {name: '~s', label: '~s', required: ~s}",
                           [maps:get("name", F),
                            maps:get("label", F, maps:get("name", F)),
                            maps:get("required", F, "false")])
             || F <- Fields],
    string:join([lists:flatten(P) || P <- Parts], ",\n").

build_form_fn(Table, Cap) ->
    io_lib:format(
        "function build~sForm() {~n"
        "    const form = document.getElementById('~s-fields');~n"
        "    if (!form) return;~n"
        "    form.innerHTML = '';~n"
        "    _~sFields.forEach(f => {~n"
        "        const label = document.createElement('label');~n"
        "        label.textContent = f.label;~n"
        "        label.style.cssText = 'display:block;font-size:0.72rem;color:#8b949e;"
        "text-transform:uppercase;letter-spacing:0.1em;margin-top:16px;margin-bottom:4px';~n"
        "        const input = document.createElement('input');~n"
        "        input.type = 'text';~n"
        "        input.id = '~s_' + f.name;~n"
        "        input.placeholder = f.label;~n"
        "        input.style.cssText = 'width:100%;background:#0d1117;border:1px solid #30363d;"
        "border-radius:8px;color:#c9d1d9;font-size:0.9rem;padding:10px 14px;outline:none;"
        "box-sizing:border-box';~n"
        "        form.appendChild(label);~n"
        "        form.appendChild(input);~n"
        "    });~n"
        "}~n",
        [Cap, Table, Cap, Table]).

load_fn(Table, Cap) ->
    io_lib:format(
        "async function load~s() {~n"
        "    try {~n"
        "        const r = await fetch('/~s');~n"
        "        if (!r.ok) return;~n"
        "        const data = await r.json();~n"
        "        _~sFields.forEach(f => {~n"
        "            const el = document.getElementById('~s_' + f.name);~n"
        "            if (el) el.value = data[f.name] || '';~n"
        "        });~n"
        "    } catch (_) {}~n"
        "}~n",
        [Cap, Table, Cap, Table]).

save_fn(Table, Cap) ->
    io_lib:format(
        "async function save~s() {~n"
        "    const statusEl = document.getElementById('~s-status');~n"
        "    const data = {};~n"
        "    for (const f of _~sFields) {~n"
        "        const val = (document.getElementById('~s_' + f.name)?.value || '').trim();~n"
        "        if (f.required && !val) {~n"
        "            if (statusEl) statusEl.textContent = f.label + ' is required';~n"
        "            return;~n"
        "        }~n"
        "        data[f.name] = val;~n"
        "    }~n"
        "    try {~n"
        "        const r = await fetch('/~s', {~n"
        "            method:  'POST',~n"
        "            headers: {'Content-Type': 'application/json'},~n"
        "            body:    JSON.stringify(data)~n"
        "        });~n"
        "        if (statusEl) statusEl.textContent = r.ok ? 'Saved' : 'Save failed';~n"
        "    } catch (_) {~n"
        "        if (statusEl) statusEl.textContent = 'Connection error';~n"
        "    }~n"
        "}~n",
        [Cap, Table, Cap, Table, Table]).

%% ---------------------------------------------------------------------------
%% String helpers
%% ---------------------------------------------------------------------------

capitalize([]) -> [];
capitalize([H | T]) ->
    Cap = [string:to_upper([H]) | capitalize_parts(T)],
    lists:flatten(Cap).

capitalize_parts([]) -> [];
capitalize_parts([$_ | [H | T]]) ->
    [string:to_upper([H]) | capitalize_parts(T)];
capitalize_parts([H | T]) ->
    [H | capitalize_parts(T)].
