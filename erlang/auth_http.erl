-module(auth_http).
-export([handle_register_begin/1, handle_register_complete/1,
         handle_login_begin/1,    handle_login_complete/1,
         handle_logout/1]).

handle_register_begin(Body) ->
    try
        #{<<"username">> := Username} = json:decode(Body),
        case auth:user_exists(Username) of
            true  -> {409, json_err(<<"user_exists">>)};
            false ->
                {ok, ChallengeB64} = auth:create_challenge(Username, registration),
                {200, json:encode(#{
                    <<"challenge">> => ChallengeB64,
                    <<"rpId">>      => <<"localhost">>,
                    <<"rpName">>    => <<"Counter App">>
                })}
        end
    catch _:_ -> {400, json_err(<<"bad_request">>)}
    end.

handle_register_complete(Body) ->
    try
        #{<<"username">>          := Username,
          <<"challenge">>         := ChallengeB64,
          <<"attestationObject">> := AttObjB64,
          <<"clientDataJSON">>    := ClientDataB64} = json:decode(Body),
        case auth:consume_challenge(ChallengeB64, registration) of
            {error, E} -> {400, json_err(atom_to_binary(E))};
            {ok, Username} ->
                case webauthn:verify_registration(Username, ChallengeB64, AttObjB64, ClientDataB64) of
                    {error, Reason} ->
                        {400, json_err(err_bin(Reason))};
                    {ok, #{cred_id := CredId, public_key := PubKey, sign_count := SC}} ->
                        ok = auth:register_credential(Username, CredId, PubKey, SC),
                        {201, json:encode(#{<<"status">> => <<"ok">>})}
                end;
            {ok, _OtherUser} ->
                {400, json_err(<<"challenge_user_mismatch">>)}
        end
    catch _:_ -> {400, json_err(<<"bad_request">>)}
    end.

handle_login_begin(Body) ->
    try
        #{<<"username">> := Username} = json:decode(Body),
        case auth:user_exists(Username) of
            false -> {404, json_err(<<"user_not_found">>)};
            true  ->
                Creds = auth:credentials_for_user(Username),
                {ok, ChallengeB64} = auth:create_challenge(Username, authentication),
                AllowCreds = [#{<<"type">> => <<"public-key">>,
                                <<"id">>   => base64:encode(
                                                maps:get(credential_id, C),
                                                #{mode => urlsafe, padding => false})}
                              || C <- Creds],
                {200, json:encode(#{
                    <<"challenge">>       => ChallengeB64,
                    <<"rpId">>            => <<"localhost">>,
                    <<"allowCredentials">>=> AllowCreds
                })}
        end
    catch _:_ -> {400, json_err(<<"bad_request">>)}
    end.

handle_login_complete(Body) ->
    try
        #{<<"credentialId">>  := CredIdB64,
          <<"authenticatorData">> := AuthDataB64,
          <<"clientDataJSON">>    := ClientDataB64,
          <<"signature">>         := SigB64} = json:decode(Body),

        ClientDataRaw = base64:decode(ClientDataB64, #{mode => urlsafe, padding => false}),
        #{<<"challenge">> := ChallengeB64} = json:decode(ClientDataRaw),

        case auth:consume_challenge(ChallengeB64, authentication) of
            {error, E} -> {400, json_err(atom_to_binary(E))};
            {ok, Username} ->
                CredIdRaw = base64:decode(CredIdB64, #{mode => urlsafe, padding => false}),
                case auth:find_credential(CredIdRaw) of
                    {error, not_found} -> {401, json_err(<<"credential_not_found">>)};
                    {ok, StoredCred} ->
                        case webauthn:verify_assertion(ChallengeB64, AuthDataB64,
                                                       ClientDataB64, SigB64, StoredCred) of
                            {error, Reason} ->
                                {401, json_err(err_bin(Reason))};
                            {ok, NewCount} ->
                                ok = auth:update_sign_count(CredIdRaw, NewCount),
                                {ok, Token} = auth:create_session(Username),
                                {200, json:encode(#{<<"token">>    => Token,
                                                    <<"username">> => Username})}
                        end
                end
        end
    catch _:_ -> {400, json_err(<<"bad_request">>)}
    end.

handle_logout(Token) ->
    ok = auth:delete_session(Token),
    {200, json:encode(#{<<"status">> => <<"ok">>})}.

json_err(Msg) -> json:encode(#{<<"error">> => Msg}).

err_bin(A) when is_atom(A)   -> atom_to_binary(A);
err_bin(T) when is_tuple(T)  -> list_to_binary(io_lib:format("~p", [T]));
err_bin(B) when is_binary(B) -> B;
err_bin(X)                   -> list_to_binary(io_lib:format("~p", [X])).
