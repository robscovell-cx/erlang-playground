-module(counter).
-behaviour(gen_server).

-record(counter, {key = default, value = 0}).

-export([start_link/0, increment/0, decrement/0, reset/0, value/0]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% Public API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

increment() -> gen_server:cast(?MODULE, {update, +1}).
decrement() -> gen_server:cast(?MODULE, {update, -1}).
reset()     -> gen_server:cast(?MODULE, reset).
value()     -> gen_server:call(?MODULE, value).

%% Callbacks

init([]) ->
    ok = ensure_mnesia(),
    {ok, ok}.  %% state is a placeholder; the counter lives in Mnesia

handle_call(value, _From, State) ->
    {reply, read_value(), State}.

handle_cast({update, Delta}, State) ->
    {atomic, _} = mnesia:transaction(fun() ->
        mnesia:write(#counter{value = read_value_txn() + Delta})
    end),
    {noreply, State};
handle_cast(reset, State) ->
    {atomic, _} = mnesia:transaction(fun() ->
        mnesia:write(#counter{})  %% default value = 0
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
        ok                                       -> ok;
        {error, {already_started, mnesia}}       -> ok
    end,
    case mnesia:create_table(counter, [
        {attributes, record_info(fields, counter)},
        {disc_copies, [node()]}
    ]) of
        {atomic, ok}                         -> ok;
        {aborted, {already_exists, counter}} -> ok
    end,
    mnesia:wait_for_tables([counter], 5000).

read_value() ->
    {atomic, V} = mnesia:transaction(fun() -> read_value_txn() end),
    V.

%% Must be called inside a transaction.
read_value_txn() ->
    case mnesia:read(counter, default) of
        []                    -> 0;
        [#counter{value = V}] -> V
    end.
