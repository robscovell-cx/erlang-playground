-module(counter).
-behaviour(gen_server).

-record(counter, {key, value = 0}).

-export([start_link/0, increment/1, decrement/1, reset/1, value/1]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% Public API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

increment(User) -> gen_server:cast(?MODULE, {update, User, +1}).
decrement(User) -> gen_server:cast(?MODULE, {update, User, -1}).
reset(User)     -> gen_server:cast(?MODULE, {reset,  User}).
value(User)     -> gen_server:call(?MODULE, {value,  User}).

%% Callbacks

init([]) ->
    ok = ensure_mnesia(),
    {ok, ok}.

handle_call({value, User}, _From, State) ->
    {reply, read_value(User), State}.

handle_cast({update, User, Delta}, State) ->
    {atomic, _} = mnesia:transaction(fun() ->
        mnesia:write(#counter{key = User, value = read_value_txn(User) + Delta})
    end),
    {noreply, State};
handle_cast({reset, User}, State) ->
    {atomic, _} = mnesia:transaction(fun() ->
        mnesia:write(#counter{key = User, value = 0})
    end),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

%% Internal

ensure_mnesia() ->
    case mnesia:create_schema([node()]) of
        ok                                -> ok;
        {error, {_, {already_exists, _}}} -> ok
    end,
    case mnesia:start() of
        ok                                 -> ok;
        {error, {already_started, mnesia}} -> ok
    end,
    case mnesia:create_table(counter, [
        {attributes, record_info(fields, counter)},
        {disc_copies, [node()]}
    ]) of
        {atomic, ok}                         -> ok;
        {aborted, {already_exists, counter}} -> ok
    end,
    mnesia:wait_for_tables([counter], 5000).

read_value(User) ->
    {atomic, V} = mnesia:transaction(fun() -> read_value_txn(User) end),
    V.

read_value_txn(User) ->
    case mnesia:read(counter, User) of
        []                    -> 0;
        [#counter{value = V}] -> V
    end.
