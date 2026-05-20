-module(webauthn).
-export([verify_registration/4, verify_assertion/5]).

-define(ORIGIN, <<"http://localhost:8080">>).
-define(RP_ID,  <<"localhost">>).

verify_registration(Username, ExpectedChallengeB64, AttObjB64, ClientDataB64) ->
    try
        ClientDataRaw = b64url_decode(ClientDataB64),
        ClientData    = json:decode(ClientDataRaw),
        check(<<"webauthn.create">> =:= maps:get(<<"type">>, ClientData), bad_type),
        check(?ORIGIN =:= maps:get(<<"origin">>, ClientData), bad_origin),
        check_challenge(ExpectedChallengeB64, maps:get(<<"challenge">>, ClientData)),

        AttObjRaw = b64url_decode(AttObjB64),
        {ok, AttObj}    = webauthn_cbor:decode(AttObjRaw),
        AuthDataRaw     = maps:get(<<"authData">>, AttObj),

        <<RpIdHash:32/binary, Flags:8, _SignCount:32,
          _AAGUID:16/binary, CredIdLen:16,
          CredId:CredIdLen/binary, CoseBytes/binary>> = AuthDataRaw,

        check(RpIdHash =:= crypto:hash(sha256, ?RP_ID), bad_rp_id),
        check((Flags band 1) =:= 1, user_presence_required),
        check(((Flags bsr 6) band 1) =:= 1, no_attested_credential_data),

        {ok, CoseMap} = webauthn_cbor:decode(CoseBytes),
        {ok, PubKey}  = extract_ec_pubkey(CoseMap),

        Fmt     = maps:get(<<"fmt">>, AttObj),
        AttStmt = maps:get(<<"attStmt">>, AttObj),
        ok = verify_att_stmt(Fmt, AttStmt, AuthDataRaw, ClientDataRaw, PubKey),

        {ok, #{cred_id => CredId, public_key => PubKey,
               sign_count => 0, username => Username}}
    catch
        throw:Reason -> {error, Reason};
        _:Reason     -> {error, Reason}
    end.

verify_assertion(ExpectedChallengeB64, AuthDataB64, ClientDataB64, SigB64, StoredCred) ->
    try
        ClientDataRaw = b64url_decode(ClientDataB64),
        ClientData    = json:decode(ClientDataRaw),
        check(<<"webauthn.get">> =:= maps:get(<<"type">>, ClientData), bad_type),
        check(?ORIGIN =:= maps:get(<<"origin">>, ClientData), bad_origin),
        check_challenge(ExpectedChallengeB64, maps:get(<<"challenge">>, ClientData)),

        AuthDataRaw = b64url_decode(AuthDataB64),
        <<RpIdHash:32/binary, Flags:8, SignCount:32, _/binary>> = AuthDataRaw,
        check(RpIdHash =:= crypto:hash(sha256, ?RP_ID), bad_rp_id),
        check((Flags band 1) =:= 1, user_presence_required),

        Sig        = b64url_decode(SigB64),
        StoredKey  = maps:get(public_key, StoredCred),
        SignedData = <<AuthDataRaw/binary, (crypto:hash(sha256, ClientDataRaw))/binary>>,
        check(crypto:verify(ecdsa, sha256, SignedData, Sig, [StoredKey, prime256v1]),
              invalid_signature),

        StoredCount = maps:get(sign_count, StoredCred),
        ok = check_sign_count(SignCount, StoredCount),
        {ok, SignCount}
    catch
        throw:Reason -> {error, Reason};
        _:Reason     -> {error, Reason}
    end.

check(true, _)      -> ok;
check(false, Reason) -> throw(Reason).

check_challenge(ExpB64, ActB64) ->
    check(b64url_decode(ExpB64) =:= b64url_decode(ActB64), challenge_mismatch).

verify_att_stmt(<<"none">>, _, _, _, _) ->
    ok;
verify_att_stmt(<<"packed">>, AttStmt, AuthDataRaw, ClientDataRaw, PubKey) ->
    check(maps:get(<<"alg">>, AttStmt) =:= -7, unsupported_alg),
    Sig        = maps:get(<<"sig">>, AttStmt),
    SignedData = <<AuthDataRaw/binary, (crypto:hash(sha256, ClientDataRaw))/binary>>,
    check(crypto:verify(ecdsa, sha256, SignedData, Sig, [PubKey, prime256v1]),
          invalid_attestation_signature),
    ok;
verify_att_stmt(Fmt, _, _, _, _) ->
    throw({unsupported_attestation_format, Fmt}).

extract_ec_pubkey(#{-2 := X, -3 := Y})
        when byte_size(X) =:= 32, byte_size(Y) =:= 32 ->
    {ok, <<16#04, X/binary, Y/binary>>};
extract_ec_pubkey(_) ->
    {error, unsupported_cose_key}.

check_sign_count(0, _)                          -> ok;
check_sign_count(New, Stored) when New > Stored -> ok;
check_sign_count(_, _)                          -> throw(sign_count_replay).

b64url_decode(B) -> base64:decode(B, #{mode => urlsafe, padding => false}).
