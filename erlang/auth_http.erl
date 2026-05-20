%% HTTP route handlers for the two WebAuthn ceremonies (registration and
%% authentication) plus session check and logout. Each function receives the raw
%% request body binary and returns {HttpStatusCode, ExtraHeaders, JsonBody}.
%%
%% counter_http.erl routes /auth/* requests here and wraps the result in an
%% HTTP response. Auth routes are deliberately unauthenticated — you need to
%% register or log in before you have a session.
%%
%% Sessions are maintained via an HttpOnly cookie named "session". HttpOnly means
%% the value is invisible to JavaScript (no XSS exfiltration), and SameSite=Strict
%% prevents cross-site request forgery. The WASM counter code does not need to
%% attach any Authorization header — the browser sends the cookie automatically.
-module(auth_http).
-export([handle_register_begin/1, handle_register_complete/1,
         handle_login_begin/1,    handle_login_complete/1,
         handle_logout/1]).

%% ---------------------------------------------------------------------------
%% Registration — step 1
%%
%% The browser sends a username. We check the user doesn't already exist, then
%% create a random challenge and send it back along with RP metadata and a
%% random user ID. The browser passes these to navigator.credentials.create().
%%
%% The user ID is a random 16-byte value, NOT the username. The WebAuthn spec
%% warns against using PII (Personally Identifiable Information) for user.id:
%% the value is stored on the authenticator and could be leaked if the device
%% is examined. A random ID carries no information about the user's identity.
%% ---------------------------------------------------------------------------
handle_register_begin(Body) ->
    try
        #{<<"username">> := Username} = json:decode(Body),
        case auth:user_exists(Username) of
            true  -> {409, [], json_err(<<"user_exists">>)};
            false ->
                {ok, ChallengeB64} = auth:create_challenge(Username, registration),
                UserId = base64:encode(crypto:strong_rand_bytes(16),
                                       #{mode => urlsafe, padding => false}),
                {200, [], json:encode(#{
                    <<"challenge">> => ChallengeB64,
                    <<"userId">>    => UserId,
                    <<"rpId">>      => <<"localhost">>,   %% must match ?RP_ID in webauthn.erl
                    <<"rpName">>    => <<"Counter App">>
                })}
        end
    catch _:_ -> {400, [], json_err(<<"bad_request">>)}
    end.

%% ---------------------------------------------------------------------------
%% Registration — step 2
%%
%% The browser sends back the authenticator's response. We verify it, extract
%% the public key, store it, and immediately create a session — so the user is
%% logged in without a separate login step after registering.
%%
%% The challenge is consumed here (deleted from Mnesia) so it cannot be reused,
%% even if an attacker captures the request and replays it.
%% ---------------------------------------------------------------------------
handle_register_complete(Body) ->
    try
        #{<<"username">>          := Username,
          <<"challenge">>         := ChallengeB64,
          <<"attestationObject">> := AttObjB64,
          <<"clientDataJSON">>    := ClientDataB64} = json:decode(Body),

        %% consume_challenge deletes the row from Mnesia and checks the TTL.
        %% The returned username must match the one in the request — a mismatch
        %% would mean the challenge was issued for a different user.
        case auth:consume_challenge(ChallengeB64, registration) of
            {error, E} -> {400, [], json_err(atom_to_binary(E))};
            {ok, Username} ->
                %% webauthn:verify_registration checks the clientDataJSON fields,
                %% CBOR-decodes the attestationObject, validates the authData
                %% structure (rpIdHash, flags), extracts the public key, and
                %% verifies the attestation signature if present.
                case webauthn:verify_registration(Username, ChallengeB64, AttObjB64, ClientDataB64) of
                    {error, Reason} ->
                        {400, [], json_err(err_bin(Reason))};
                    {ok, #{cred_id := CredId, public_key := PubKey, sign_count := SC}} ->
                        %% Store the credential. PubKey is the uncompressed 65-byte
                        %% EC point (04 || X || Y) — this is all we need for future
                        %% signature verification.
                        ok = auth:register_credential(Username, CredId, PubKey, SC),
                        %% Issue a session immediately. The token is sent as an
                        %% HttpOnly cookie, not in the response body, so JavaScript
                        %% cannot read or exfiltrate it.
                        {ok, Token} = auth:create_session(Username),
                        {201, [set_cookie(Token)],
                              json:encode(#{<<"status">>   => <<"ok">>,
                                            <<"username">> => Username})}
                end;
            {ok, _OtherUser} ->
                {400, [], json_err(<<"challenge_user_mismatch">>)}
        end
    catch _:_ -> {400, [], json_err(<<"bad_request">>)}
    end.

%% ---------------------------------------------------------------------------
%% Authentication (login) — step 1
%%
%% The browser sends a username. We look up all registered credentials for that
%% user (a user could have registered from multiple devices) and send them back
%% as `allowCredentials` so the browser can find the matching private key on the
%% authenticator. We also send a fresh challenge.
%% ---------------------------------------------------------------------------
handle_login_begin(Body) ->
    try
        #{<<"username">> := Username} = json:decode(Body),
        case auth:user_exists(Username) of
            false -> {404, [], json_err(<<"user_not_found">>)};
            true  ->
                Creds = auth:credentials_for_user(Username),
                {ok, ChallengeB64} = auth:create_challenge(Username, authentication),
                %% Credential IDs must be base64url-encoded for the JSON wire format.
                %% The browser decodes them back to bytes before passing to the
                %% WebAuthn API.
                AllowCreds = [#{<<"type">> => <<"public-key">>,
                                <<"id">>   => base64:encode(
                                                maps:get(credential_id, C),
                                                #{mode => urlsafe, padding => false})}
                              || C <- Creds],
                {200, [], json:encode(#{
                    <<"challenge">>        => ChallengeB64,
                    <<"rpId">>             => <<"localhost">>,
                    <<"allowCredentials">> => AllowCreds
                })}
        end
    catch _:_ -> {400, [], json_err(<<"bad_request">>)}
    end.

%% ---------------------------------------------------------------------------
%% Authentication (login) — step 2
%%
%% The browser sends the authenticator's assertion: the credential ID it used,
%% the authenticatorData, the clientDataJSON, and the signature over both.
%%
%% We don't ask the client to send the challenge explicitly — instead we extract
%% it from clientDataJSON, which the authenticator embedded there and signed.
%% Extracting from clientDataJSON rather than trusting a client-supplied value
%% is important: the signature covers clientDataJSON, so the challenge in it
%% cannot have been tampered with.
%% ---------------------------------------------------------------------------
handle_login_complete(Body) ->
    try
        #{<<"credentialId">>       := CredIdB64,
          <<"authenticatorData">>  := AuthDataB64,
          <<"clientDataJSON">>     := ClientDataB64,
          <<"signature">>          := SigB64} = json:decode(Body),

        %% Decode clientDataJSON to pull out the challenge the browser embedded.
        ClientDataRaw = base64:decode(ClientDataB64, #{mode => urlsafe, padding => false}),
        #{<<"challenge">> := ChallengeB64} = json:decode(ClientDataRaw),

        case auth:consume_challenge(ChallengeB64, authentication) of
            {error, E} -> {400, [], json_err(atom_to_binary(E))};
            {ok, Username} ->
                CredIdRaw = base64:decode(CredIdB64, #{mode => urlsafe, padding => false}),
                case auth:find_credential(CredIdRaw) of
                    {error, not_found} -> {401, [], json_err(<<"credential_not_found">>)};
                    {ok, StoredCred} ->
                        %% verify_assertion checks the clientDataJSON fields, the
                        %% authData header (rpIdHash, UP flag), constructs the signed
                        %% payload (authData ++ sha256(clientDataJSON)), and verifies
                        %% the ECDSA signature with the stored public key.
                        case webauthn:verify_assertion(ChallengeB64, AuthDataB64,
                                                       ClientDataB64, SigB64, StoredCred) of
                            {error, Reason} ->
                                {401, [], json_err(err_bin(Reason))};
                            {ok, NewCount} ->
                                %% Update the sign count before creating the session.
                                ok = auth:update_sign_count(CredIdRaw, NewCount),
                                {ok, Token} = auth:create_session(Username),
                                {200, [set_cookie(Token)],
                                      json:encode(#{<<"username">> => Username})}
                        end
                end
        end
    catch _:_ -> {400, [], json_err(<<"bad_request">>)}
    end.

%% ---------------------------------------------------------------------------
%% Logout
%%
%% Delete the session row and instruct the browser to clear the cookie by
%% returning a Set-Cookie with Max-Age=0.
%% ---------------------------------------------------------------------------
handle_logout(Token) ->
    ok = auth:delete_session(Token),
    {200, [clear_cookie()], json:encode(#{<<"status">> => <<"ok">>})}.

%% ---------------------------------------------------------------------------
%% Cookie helpers
%%
%% HttpOnly  — invisible to JavaScript; cannot be stolen by XSS.
%% SameSite=Strict — not sent on cross-site navigations; prevents CSRF.
%% Path=/    — sent for all routes on this origin.
%% Note: add "; Secure" here when deploying over HTTPS.
%% ---------------------------------------------------------------------------
set_cookie(Token) ->
    {<<"Set-Cookie">>,
     <<"session=", Token/binary, "; HttpOnly; SameSite=Strict; Path=/">>}.

clear_cookie() ->
    {<<"Set-Cookie">>,
     <<"session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0">>}.

json_err(Msg) -> json:encode(#{<<"error">> => Msg}).

err_bin(A) when is_atom(A)   -> atom_to_binary(A);
err_bin(T) when is_tuple(T)  -> list_to_binary(io_lib:format("~p", [T]));
err_bin(B) when is_binary(B) -> B;
err_bin(X)                   -> list_to_binary(io_lib:format("~p", [X])).
