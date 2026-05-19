-module(counter).
-behaviour(gen_server).

-export([start_link/0, increment/0, decrement/0, reset/0, value/0]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

%% Public API

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, 0, []).

increment() ->
    gen_server:cast(?MODULE, increment).

decrement() ->
    gen_server:cast(?MODULE, decrement).

reset() ->
    gen_server:cast(?MODULE, reset).

value() ->
    gen_server:call(?MODULE, value).

%% Callbacks

init(InitialValue) ->
    {ok, InitialValue}.

handle_call(value, _From, State) ->
    {reply, State, State}.

handle_cast(increment, State) ->
    {noreply, State + 1};
handle_cast(decrement, State) ->
    {noreply, State - 1};
handle_cast(reset, _State) ->
    {noreply, 0}.

terminate(_Reason, _State) ->
    ok.
