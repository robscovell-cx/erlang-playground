%% WebAuthn (Web Authentication, W3C spec) is a challenge-response protocol
%% that lets a hardware authenticator (Touch ID, Windows Hello, a security key)
%% prove identity without a password. The private key never leaves the device;
%% only the public key is stored on the server.
%%
%% Two ceremonies:
%%   Registration  — create a new credential (key pair) on the authenticator
%%                   and give the public key to the server.
%%   Authentication (assertion) — sign a fresh server challenge with the private
%%                   key; the server verifies with the stored public key.
%%
%% Both ceremonies follow the same structure: the browser collects data from the
%% authenticator, the server checks every field to make sure nothing was tampered
%% with in transit.
-module(webauthn).
-export([verify_registration/4, verify_assertion/5]).

%% Deployment configuration — change these two lines for a new project.
%% ORIGIN is scheme+host+port as the browser sees it.
%% RP_ID  is just the host (or a registrable domain suffix of it).
%% Both must also be updated in auth_http.erl (the rpId sent to the browser).
-define(ORIGIN, <<"http://localhost:8080">>).
-define(RP_ID,  <<"localhost">>).

%% ---------------------------------------------------------------------------
%% Registration verification
%%
%% Called after the browser runs navigator.credentials.create(). The
%% authenticator produces two blobs: clientDataJSON (a JSON description of
%% what the browser asked for) and an attestationObject (CBOR; contains the
%% new public key and a proof of device authenticity).
%%
%% Arguments:
%%   Username        — already-validated username from our server
%%   ExpectedChallB64 — the random challenge we sent; must appear in clientDataJSON
%%   AttObjB64       — base64url attestationObject from the authenticator
%%   ClientDataB64   — base64url clientDataJSON from the browser
%% ---------------------------------------------------------------------------
verify_registration(Username, ExpectedChallengeB64, AttObjB64, ClientDataB64) ->
    try
        %% clientDataJSON is a plain JSON object the browser constructs to bind
        %% the ceremony to a specific origin and challenge. We verify it first
        %% because it's the simplest check and fails fast on obvious mismatches.
        ClientDataRaw = b64url_decode(ClientDataB64),
        ClientData    = json:decode(ClientDataRaw),
        check(<<"webauthn.create">> =:= maps:get(<<"type">>, ClientData), bad_type),
        check(?ORIGIN =:= maps:get(<<"origin">>, ClientData), bad_origin),
        %% The challenge ties this response to the specific request we issued.
        %% Without this check an attacker could replay a captured registration.
        check_challenge(ExpectedChallengeB64, maps:get(<<"challenge">>, ClientData)),

        %% The attestationObject is CBOR-encoded. It contains:
        %%   "fmt"      — attestation statement format ("none", "packed", …)
        %%   "attStmt"  — the attestation statement (empty for "none")
        %%   "authData" — raw binary with the public key and device flags
        AttObjRaw = b64url_decode(AttObjB64),
        {ok, AttObj}    = webauthn_cbor:decode(AttObjRaw),
        AuthDataRaw     = maps:get(<<"authData">>, AttObj),

        %% authData binary layout (fixed-width fields, no CBOR here):
        %%   32 bytes  — SHA-256 of the RP ID ("localhost")
        %%    1 byte   — flags byte (bit 0 = User Present, bit 6 = Attested Credential Data)
        %%    4 bytes  — signature counter (big-endian uint32)
        %%   16 bytes  — AAGUID (authenticator model identifier; we ignore it)
        %%    2 bytes  — credential ID length
        %%   N bytes   — credential ID (the stable identifier for this key pair)
        %%   remainder — COSE-encoded public key
        <<RpIdHash:32/binary, Flags:8, _SignCount:32,
          _AAGUID:16/binary, CredIdLen:16,
          CredId:CredIdLen/binary, CoseBytes/binary>> = AuthDataRaw,

        %% Binding the credential to our RP ID prevents credentials issued for
        %% example.com from being accepted by attacker.com — even if the
        %% attacker intercepts the data in transit.
        check(RpIdHash =:= crypto:hash(sha256, ?RP_ID), bad_rp_id),

        %% Bit 0 (User Present) must be set — the authenticator confirmed that a
        %% human interacted with it (e.g. touched a fingerprint sensor).
        check((Flags band 1) =:= 1, user_presence_required),

        %% Bit 6 (Attested Credential Data) must be set in registration — it
        %% signals that the authData includes the new credential's public key.
        check(((Flags bsr 6) band 1) =:= 1, no_attested_credential_data),

        %% The COSE key is another CBOR map. For ES256 (algorithm -7) the map
        %% contains integer keys; -2 = X coordinate, -3 = Y coordinate (both
        %% 32-byte big-endian integers for the P-256 curve).
        {ok, CoseMap} = webauthn_cbor:decode(CoseBytes),
        {ok, PubKey}  = extract_ec_pubkey(CoseMap),

        %% Verify the attestation statement. "none" means the authenticator chose
        %% not to prove its model/origin — acceptable for our use case.
        %% "packed" (self-attestation) means the device signed authData with the
        %% new private key, proving it generated the key pair itself.
        Fmt     = maps:get(<<"fmt">>, AttObj),
        AttStmt = maps:get(<<"attStmt">>, AttObj),
        ok = verify_att_stmt(Fmt, AttStmt, AuthDataRaw, ClientDataRaw, PubKey),

        {ok, #{cred_id => CredId, public_key => PubKey,
               sign_count => 0, username => Username}}
    catch
        throw:Reason -> {error, Reason};
        _:Reason     -> {error, Reason}
    end.

%% ---------------------------------------------------------------------------
%% Assertion (login) verification
%%
%% Called after the browser runs navigator.credentials.get(). The authenticator
%% signs a server challenge with the private key it holds for this credential.
%% We verify that signature using the public key we stored at registration time.
%%
%% Arguments:
%%   ExpectedChallB64 — the random challenge we sent
%%   AuthDataB64      — base64url authenticatorData (shorter than registration; no key)
%%   ClientDataB64    — base64url clientDataJSON
%%   SigB64           — base64url DER-encoded ECDSA signature
%%   StoredCred       — map from auth:find_credential/1 with public_key and sign_count
%% ---------------------------------------------------------------------------
verify_assertion(ExpectedChallengeB64, AuthDataB64, ClientDataB64, SigB64, StoredCred) ->
    try
        ClientDataRaw = b64url_decode(ClientDataB64),
        ClientData    = json:decode(ClientDataRaw),
        check(<<"webauthn.get">> =:= maps:get(<<"type">>, ClientData), bad_type),
        check(?ORIGIN =:= maps:get(<<"origin">>, ClientData), bad_origin),
        check_challenge(ExpectedChallengeB64, maps:get(<<"challenge">>, ClientData)),

        %% Assertion authData has the same header as registration but no
        %% credential data section — just rpIdHash, flags, and sign count.
        AuthDataRaw = b64url_decode(AuthDataB64),
        <<RpIdHash:32/binary, Flags:8, SignCount:32, _/binary>> = AuthDataRaw,
        check(RpIdHash =:= crypto:hash(sha256, ?RP_ID), bad_rp_id),
        check((Flags band 1) =:= 1, user_presence_required),

        %% The signed payload is authData concatenated with the SHA-256 of
        %% clientDataJSON. This is what the authenticator's private key signed.
        Sig        = b64url_decode(SigB64),
        StoredKey  = maps:get(public_key, StoredCred),
        SignedData = <<AuthDataRaw/binary, (crypto:hash(sha256, ClientDataRaw))/binary>>,

        %% ES256: ECDSA with SHA-256 on the P-256 curve.
        %% StoredKey is the uncompressed 65-byte EC point (04 || X || Y) we
        %% stored at registration. "prime256v1" is OpenSSL's name for P-256.
        check(crypto:verify(ecdsa, sha256, SignedData, Sig, [StoredKey, prime256v1]),
              invalid_signature),

        %% The sign count is a monotonically increasing counter maintained by the
        %% authenticator. If a new count is not greater than the stored one, the
        %% credential may have been cloned — reject it. Count 0 is a special case:
        %% platform authenticators (like Touch ID) often don't implement a counter.
        StoredCount = maps:get(sign_count, StoredCred),
        ok = check_sign_count(SignCount, StoredCount),
        {ok, SignCount}
    catch
        throw:Reason -> {error, Reason};
        _:Reason     -> {error, Reason}
    end.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

check(true, _)       -> ok;
check(false, Reason) -> throw(Reason).

%% Both the expected challenge (what we stored) and the actual challenge (what
%% the browser put in clientDataJSON) are base64url strings, but browsers may
%% use standard or URL-safe alphabet. Decode both to raw bytes before comparing
%% to avoid false mismatches from encoding differences.
check_challenge(ExpB64, ActB64) ->
    check(b64url_decode(ExpB64) =:= b64url_decode(ActB64), challenge_mismatch).

%% Attestation statement verification.
%% "none" — authenticator declined to attest; we accept it unconditionally.
verify_att_stmt(<<"none">>, _, _, _, _) ->
    ok;
%% "packed" self-attestation — the authenticator signed the concatenation of
%% authData and clientDataJSON hash with the same private key it just created.
verify_att_stmt(<<"packed">>, AttStmt, AuthDataRaw, ClientDataRaw, PubKey) ->
    check(maps:get(<<"alg">>, AttStmt) =:= -7, unsupported_alg),  %% -7 = ES256
    Sig        = maps:get(<<"sig">>, AttStmt),
    SignedData = <<AuthDataRaw/binary, (crypto:hash(sha256, ClientDataRaw))/binary>>,
    check(crypto:verify(ecdsa, sha256, SignedData, Sig, [PubKey, prime256v1]),
          invalid_attestation_signature),
    ok;
verify_att_stmt(Fmt, _, _, _, _) ->
    throw({unsupported_attestation_format, Fmt}).

%% Extract the P-256 public key from a COSE_Key map.
%% COSE integer key -2 = x coordinate, -3 = y coordinate.
%% The uncompressed EC point format prefixes the concatenated coordinates with 0x04.
extract_ec_pubkey(#{-2 := X, -3 := Y})
        when byte_size(X) =:= 32, byte_size(Y) =:= 32 ->
    {ok, <<16#04, X/binary, Y/binary>>};
extract_ec_pubkey(_) ->
    {error, unsupported_cose_key}.

%% Sign count 0 means the authenticator doesn't implement the counter (common
%% for platform authenticators like Touch ID). Any non-zero count must exceed
%% the stored value, otherwise the credential has been cloned.
check_sign_count(0, _)                          -> ok;
check_sign_count(New, Stored) when New > Stored -> ok;
check_sign_count(_, _)                          -> throw(sign_count_replay).

b64url_decode(B) -> base64:decode(B, #{mode => urlsafe, padding => false}).
