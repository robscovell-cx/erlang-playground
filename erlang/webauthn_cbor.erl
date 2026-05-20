-module(webauthn_cbor).
-export([decode/1]).

decode(Bin) ->
    try
        {Value, <<>>} = decode_item(Bin),
        {ok, Value}
    catch
        _:_ -> {error, cbor_decode_failed}
    end.

decode_item(<<IB:8, Rest/binary>>) ->
    Major   = IB bsr 5,
    AddInfo = IB band 16#1f,
    {Arg, Rest2} = decode_argument(AddInfo, Rest),
    decode_value(Major, Arg, Rest2).

decode_argument(AI, Rest) when AI < 24  -> {AI, Rest};
decode_argument(24, <<V:8,  R/binary>>) -> {V, R};
decode_argument(25, <<V:16, R/binary>>) -> {V, R};
decode_argument(26, <<V:32, R/binary>>) -> {V, R};
decode_argument(27, <<V:64, R/binary>>) -> {V, R}.

decode_value(0, V, Rest)  -> {V, Rest};
decode_value(1, V, Rest)  -> {-(1 + V), Rest};
decode_value(2, Len, Bin) ->
    <<Bytes:Len/binary, Rest/binary>> = Bin,
    {Bytes, Rest};
decode_value(3, Len, Bin) ->
    <<Str:Len/binary, Rest/binary>> = Bin,
    {Str, Rest};
decode_value(4, Count, Bin) ->
    {Items, Rest} = decode_sequence(Count, Bin, []),
    {Items, Rest};
decode_value(5, Count, Bin) ->
    {Pairs, Rest} = decode_sequence(Count * 2, Bin, []),
    {pairs_to_map(Pairs, #{}), Rest}.

decode_sequence(0, Bin, Acc) -> {lists:reverse(Acc), Bin};
decode_sequence(N, Bin, Acc) ->
    {V, Rest} = decode_item(Bin),
    decode_sequence(N - 1, Rest, [V | Acc]).

pairs_to_map([], M) -> M;
pairs_to_map([K, V | T], M) -> pairs_to_map(T, M#{K => V}).
