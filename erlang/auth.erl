%% This gen_server owns the four Mnesia tables that together implement passkey
%% authentication. It starts Mnesia, creates or opens the tables, and runs an
%% hourly background job to purge expired sessions.
%%
%% Most of the exported API functions access Mnesia directly (dirty_read /
%% dirty_write) rather than going through gen_server calls. Those operations
%% are inherently thread-safe for single-node disc_copies tables, so there is
%% no benefit to serialising them through the gen_server process. The
%% gen_server is only needed for two things:
%%   1. Initialising the tables exactly once at startup.
%%   2. Scheduling the periodic session purge via erlang:send_after.
-module(auth).
-behaviour(gen_server).

%% One row per registered user.
-record(webauthn_user,       {username, created_at}).

%% One row per registered credential (key pair). A user can have multiple
%% credentials if they use different devices. The secondary index on `username`
%% lets us look up all credentials for a user without a full table scan.
-record(webauthn_credential, {credential_id, username, public_key, sign_count, created_at}).

%% Temporary rows created at the start of each ceremony (registration or login)
%% and deleted when consumed. The raw 32-byte random value is the primary key;
%% the base64url-encoded version is what travels over the wire.
-record(webauthn_challenge,  {challenge, username, kind, created_at}).

%% One row per active login session. Identified by a random Bearer token.
-record(webauthn_session,    {token, username, expires_at}).

-export([start_link/0,
         create_challenge/2, consume_challenge/2,
         register_credential/4, find_credential/1, credentials_for_user/1,
         update_sign_count/2,
         create_session/1, validate_session/1, delete_session/1,
         user_exists/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CHALLENGE_TTL,   300).      %% challenges expire after 5 minutes
-define(SESSION_TTL,    3600).      %% sessions expire after 1 hour
-define(PURGE_INTERVAL, 3_600_000). %% purge job runs every hour (milliseconds)

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% ---------------------------------------------------------------------------
%% Challenge management
%%
%% A "challenge" is a random value the server generates and sends to the
%% browser. The authenticator must include this value in its signed response,
%% proving the response was produced for this specific request and not
%% replayed from an earlier one.
%% ---------------------------------------------------------------------------

%% Generate a fresh challenge, persist it, and return the base64url form.
%% We store the raw bytes as the key so lookup is a simple binary comparison.
create_challenge(Username, Kind) ->
    Raw = crypto:strong_rand_bytes(32),
    B64 = base64:encode(Raw, #{mode => urlsafe, padding => false}),
    ok  = mnesia:dirty_write(#webauthn_challenge{
              challenge  = Raw,
              username   = Username,
              kind       = Kind,
              created_at = erlang:system_time(second)}),
    {ok, B64}.

%% Look up a challenge by its base64url value, verify it hasn't expired and
%% was issued for the correct ceremony kind, then delete it. One-time use
%% prevents replay attacks even within the TTL window.
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
            %% Row exists but kind doesn't match (e.g. someone sent a
            %% registration challenge to the login endpoint).
            {error, not_found}
    end.

%% ---------------------------------------------------------------------------
%% Credential management
%%
%% A credential is an asymmetric key pair. The private key lives on the
%% authenticator and never leaves it. We store only the public key (plus the
%% opaque credential ID that identifies which key to use).
%% ---------------------------------------------------------------------------

%% Persist a newly registered credential. Also creates the user record on first
%% registration (a user may later register additional devices).
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

%% Look up a credential by its raw (not base64) ID. Returns a plain map so
%% callers don't need to know the internal record structure.
find_credential(CredIdRaw) ->
    case mnesia:dirty_read(webauthn_credential, CredIdRaw) of
        []    -> {error, not_found};
        [Rec] -> {ok, #{credential_id => Rec#webauthn_credential.credential_id,
                        username       => Rec#webauthn_credential.username,
                        public_key     => Rec#webauthn_credential.public_key,
                        sign_count     => Rec#webauthn_credential.sign_count}}
    end.

%% Return all credentials for a user (used to build the allowCredentials list
%% sent to the browser at login, so the authenticator knows which key to use).
credentials_for_user(Username) ->
    Records = mnesia:dirty_index_read(webauthn_credential, Username,
                                       #webauthn_credential.username),
    [#{credential_id => R#webauthn_credential.credential_id,
       username      => R#webauthn_credential.username,
       public_key    => R#webauthn_credential.public_key,
       sign_count    => R#webauthn_credential.sign_count}
     || R <- Records].

%% After a successful assertion, persist the new sign count. The sign count is
%% a monotonically-increasing counter the authenticator maintains; storing the
%% latest value lets us detect cloned credentials on the next login attempt.
update_sign_count(CredId, NewCount) ->
    case mnesia:dirty_read(webauthn_credential, CredId) of
        [Rec] -> mnesia:dirty_write(Rec#webauthn_credential{sign_count = NewCount});
        []    -> ok
    end.

%% ---------------------------------------------------------------------------
%% Session management
%%
%% After a successful assertion we issue a Bearer token that the browser sends
%% with every subsequent counter API request. This is simpler than re-running
%% the full WebAuthn ceremony on every request.
%% ---------------------------------------------------------------------------

%% Create a new session and return the opaque token. The token is a random
%% 32-byte value encoded as base64url — unguessable without the database.
create_session(Username) ->
    Token = base64:encode(crypto:strong_rand_bytes(32),
                           #{mode => urlsafe, padding => false}),
    ok = mnesia:dirty_write(#webauthn_session{
             token      = Token,
             username   = Username,
             expires_at = erlang:system_time(second) + ?SESSION_TTL}),
    {ok, Token}.

%% Validate a Bearer token from an incoming HTTP request. Returns the username
%% so the caller can use it as the Mnesia key for the per-user counter.
validate_session(undefined) -> {error, invalid};
validate_session(Token) ->
    case mnesia:dirty_read(webauthn_session, Token) of
        [] ->
            {error, invalid};
        [#webauthn_session{expires_at = Exp, username = U}] ->
            case erlang:system_time(second) < Exp of
                true  -> {ok, U};
                false ->
                    %% Clean up lazily on access rather than only via the purge job.
                    mnesia:dirty_delete({webauthn_session, Token}),
                    {error, expired}
            end
    end.

delete_session(undefined) -> ok;
delete_session(Token) ->
    mnesia:dirty_delete({webauthn_session, Token}).

user_exists(Username) ->
    mnesia:dirty_read(webauthn_user, Username) =/= [].

%% ---------------------------------------------------------------------------
%% gen_server callbacks
%% ---------------------------------------------------------------------------

init([]) ->
    ok = ensure_tables(),
    %% Schedule the first purge. Subsequent ones are re-scheduled in handle_info.
    erlang:send_after(?PURGE_INTERVAL, self(), purge_sessions),
    {ok, #{}}.

handle_call(_Req, _From, State) -> {reply, ok, State}.
handle_cast(_Msg, State)        -> {noreply, State}.

%% Delete all session rows whose expires_at is in the past. Using a Mnesia
%% transaction with select lets us find expired rows without a full table scan.
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

%% ---------------------------------------------------------------------------
%% Mnesia setup
%% ---------------------------------------------------------------------------

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
    %% Block until Mnesia has loaded the tables from disk. Without this, the
    %% first requests could arrive before data is available.
    ok = mnesia:wait_for_tables(
        [webauthn_user, webauthn_credential, webauthn_challenge, webauthn_session],
        5000).
