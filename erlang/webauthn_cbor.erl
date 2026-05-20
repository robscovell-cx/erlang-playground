%% WebAuthn uses CBOR (Concise Binary Object Representation, RFC 7049) to encode
%% two key structures: the attestationObject (produced during registration) and
%% the COSE public key embedded inside it. This module is a minimal decoder that
%% handles only the CBOR major types that WebAuthn actually uses.
%%
%% CBOR encoding: every item starts with a one-byte initial byte (IB).
%%   - High 3 bits = major type (what kind of value follows)
%%   - Low 5 bits  = additional info (how to read the argument / length)
%%
%% Major types used here:
%%   0 = unsigned integer   1 = negative integer
%%   2 = byte string        3 = text string
%%   4 = array              5 = map
-module(webauthn_cbor).
-export([decode/1]).

%% Entry point: decode a single top-level CBOR item from a binary.
%% Fails if there are leftover bytes — a partial parse means corrupt data.
decode(Bin) ->
    try
        {Value, <<>>} = decode_item(Bin),
        {ok, Value}
    catch
        _:_ -> {error, cbor_decode_failed}
    end.

%% Split the initial byte into major type and additional-info, then decode.
decode_item(<<IB:8, Rest/binary>>) ->
    Major   = IB bsr 5,       %% top 3 bits
    AddInfo = IB band 16#1f,  %% bottom 5 bits
    {Arg, Rest2} = decode_argument(AddInfo, Rest),
    decode_value(Major, Arg, Rest2).

%% The additional-info field encodes the argument (a length or integer value).
%% Values 0-23 are stored inline; 24/25/26/27 mean read 1/2/4/8 following bytes.
decode_argument(AI, Rest) when AI < 24  -> {AI, Rest};
decode_argument(24, <<V:8,  R/binary>>) -> {V, R};
decode_argument(25, <<V:16, R/binary>>) -> {V, R};
decode_argument(26, <<V:32, R/binary>>) -> {V, R};
decode_argument(27, <<V:64, R/binary>>) -> {V, R}.

%% Major type 0: unsigned integer — the argument IS the value.
decode_value(0, V, Rest)  -> {V, Rest};
%% Major type 1: negative integer — value is -(1 + argument).
decode_value(1, V, Rest)  -> {-(1 + V), Rest};
%% Major type 2: byte string — argument is byte count, consume that many bytes.
decode_value(2, Len, Bin) ->
    <<Bytes:Len/binary, Rest/binary>> = Bin,
    {Bytes, Rest};
%% Major type 3: text string — same layout as byte string; we keep it as binary.
decode_value(3, Len, Bin) ->
    <<Str:Len/binary, Rest/binary>> = Bin,
    {Str, Rest};
%% Major type 4: array — argument is item count; decode that many items in order.
decode_value(4, Count, Bin) ->
    {Items, Rest} = decode_sequence(Count, Bin, []),
    {Items, Rest};
%% Major type 5: map — argument is pair count; decode Count*2 items then pair them.
%% COSE keys (integers like -2, -3) and attestationObject keys (binaries like
%% <<"fmt">>) are both left as-is, so callers can pattern-match directly.
decode_value(5, Count, Bin) ->
    {Pairs, Rest} = decode_sequence(Count * 2, Bin, []),
    {pairs_to_map(Pairs, #{}), Rest}.

decode_sequence(0, Bin, Acc) -> {lists:reverse(Acc), Bin};
decode_sequence(N, Bin, Acc) ->
    {V, Rest} = decode_item(Bin),
    decode_sequence(N - 1, Rest, [V | Acc]).

pairs_to_map([], M) -> M;
pairs_to_map([K, V | T], M) -> pairs_to_map(T, M#{K => V}).
