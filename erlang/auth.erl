-module(auth).
-behaviour(gen_server).

-record(webauthn_user,       {username, created_at}).
-record(webauthn_credential, {credential_id, username, public_key, sign_count, created_at}).
-record(webauthn_challenge,  {challenge, username, kind, created_at}).
-record(webauthn_session,    {token, username, expires_at}).

-export([start_link/0,
         create_challenge/2, consume_challenge/2,
         register_credential/4, find_credential/1, credentials_for_user/1,
         update_sign_count/2,
         create_session/1, validate_session/1, delete_session/1,
         user_exists/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CHALLENGE_TTL,   300).
-define(SESSION_TTL,    3600).
-define(PURGE_INTERVAL, 3_600_000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% Public API — direct Mnesia access (thread-safe dirty ops)

create_challenge(Username, Kind) ->
    Raw = crypto:strong_rand_bytes(32),
    B64 = base64:encode(Raw, #{mode => urlsafe, padding => false}),
    ok  = mnesia:dirty_write(#webauthn_challenge{
              challenge  = Raw,
              username   = Username,
              kind       = Kind,
              created_at = erlang:system_time(second)}),
    {ok, B64}.

consume_challenge(B64, Kind) ->
    Raw = base64:decode(B64, #{mode => urlsafe, padding => false}),
    case mnesia:dirty_read(webauthn_challenge, Raw) of
        [] ->
            {error, not_found};
        [#webauthn_challenge{kind = Kind, username = U, created_at = CA}] ->
            mnesia:dirty_delete({webauthn_challenge, Raw}),
            case erlang:system_time(second) - CA < ?CHALLENGE_TTL of
                true  -> {ok, U};
                false -> {error, expired}
            end;
        [_] ->
            {error, not_found}
    end.

register_credential(Username, CredId, PubKey, SignCount) ->
    case mnesia:dirty_read(webauthn_user, Username) of
        [] -> mnesia:dirty_write(#webauthn_user{
                  username   = Username,
                  created_at = erlang:system_time(second)});
        [_] -> ok
    end,
    mnesia:dirty_write(#webauthn_credential{
        credential_id = CredId,
        username      = Username,
        public_key    = PubKey,
        sign_count    = SignCount,
        created_at    = erlang:system_time(second)}).

find_credential(CredIdRaw) ->
    case mnesia:dirty_read(webauthn_credential, CredIdRaw) of
        []    -> {error, not_found};
        [Rec] -> {ok, #{credential_id => Rec#webauthn_credential.credential_id,
                        username       => Rec#webauthn_credential.username,
                        public_key     => Rec#webauthn_credential.public_key,
                        sign_count     => Rec#webauthn_credential.sign_count}}
    end.

credentials_for_user(Username) ->
    Records = mnesia:dirty_index_read(webauthn_credential, Username,
                                       #webauthn_credential.username),
    [#{credential_id => R#webauthn_credential.credential_id,
       username      => R#webauthn_credential.username,
       public_key    => R#webauthn_credential.public_key,
       sign_count    => R#webauthn_credential.sign_count}
     || R <- Records].

update_sign_count(CredId, NewCount) ->
    case mnesia:dirty_read(webauthn_credential, CredId) of
        [Rec] -> mnesia:dirty_write(Rec#webauthn_credential{sign_count = NewCount});
        []    -> ok
    end.

create_session(Username) ->
    Token = base64:encode(crypto:strong_rand_bytes(32),
                           #{mode => urlsafe, padding => false}),
    ok = mnesia:dirty_write(#webauthn_session{
             token      = Token,
             username   = Username,
             expires_at = erlang:system_time(second) + ?SESSION_TTL}),
    {ok, Token}.

validate_session(undefined) -> {error, invalid};
validate_session(Token) ->
    case mnesia:dirty_read(webauthn_session, Token) of
        [] ->
            {error, invalid};
        [#webauthn_session{expires_at = Exp, username = U}] ->
            case erlang:system_time(second) < Exp of
                true  -> {ok, U};
                false ->
                    mnesia:dirty_delete({webauthn_session, Token}),
                    {error, expired}
            end
    end.

delete_session(undefined) -> ok;
delete_session(Token) ->
    mnesia:dirty_delete({webauthn_session, Token}).

user_exists(Username) ->
    mnesia:dirty_read(webauthn_user, Username) =/= [].

%% gen_server callbacks

init([]) ->
    ok = ensure_tables(),
    erlang:send_after(?PURGE_INTERVAL, self(), purge_sessions),
    {ok, #{}}.

handle_call(_Req, _From, State) -> {reply, ok, State}.
handle_cast(_Msg, State)        -> {noreply, State}.

handle_info(purge_sessions, State) ->
    Now = erlang:system_time(second),
    {atomic, _} = mnesia:transaction(fun() ->
        Expired = mnesia:select(webauthn_session,
            [{#webauthn_session{token = '$1', username = '_', expires_at = '$2'},
              [{'<', '$2', Now}], ['$1']}]),
        [mnesia:delete({webauthn_session, T}) || T <- Expired]
    end),
    erlang:send_after(?PURGE_INTERVAL, self(), purge_sessions),
    {noreply, State};
handle_info(_, State) ->
    {noreply, State}.

terminate(_Reason, _State) -> ok.

ensure_tables() ->
    Tables = [
        {webauthn_user,       record_info(fields, webauthn_user),       []},
        {webauthn_credential, record_info(fields, webauthn_credential), [{index, [username]}]},
        {webauthn_challenge,  record_info(fields, webauthn_challenge),  []},
        {webauthn_session,    record_info(fields, webauthn_session),    []}
    ],
    lists:foreach(fun({Name, Fields, Extra}) ->
        Opts = [{attributes, Fields}, {disc_copies, [node()]}] ++ Extra,
        case mnesia:create_table(Name, Opts) of
            {atomic, ok}                      -> ok;
            {aborted, {already_exists, Name}} -> ok
        end
    end, Tables),
    ok = mnesia:wait_for_tables(
        [webauthn_user, webauthn_credential, webauthn_challenge, webauthn_session],
        5000).
