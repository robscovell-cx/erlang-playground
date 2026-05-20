%% GENERATED -- do not edit. Regenerate: make gen
-module(user_address).
-record(user_address, {username, line1, line2, city, state, postcode, country}).
-export([start_link/0, get/1, put/2]).

start_link() ->
    ok = ensure_table(),
    {ok, self()}.

ensure_table() ->
    case mnesia:create_table(user_address, [
        {attributes, record_info(fields, user_address)},
        {disc_copies, [node()]}
    ]) of
        {atomic, ok}                        -> ok;
        {aborted, {already_exists, user_address}} -> ok
    end,
    mnesia:wait_for_tables([user_address], 5000).

get(Username) ->
    Default = #{<<"line1">> => <<>>, <<"line2">> => <<>>, <<"city">> => <<>>, <<"state">> => <<>>, <<"postcode">> => <<>>, <<"country">> => <<>>},
    case mnesia:dirty_read(user_address, Username) of
        []    -> {ok, Default};
        [Rec] -> {ok, #{<<"line1">> => coerce(Rec#user_address.line1),
             <<"line2">> => coerce(Rec#user_address.line2),
             <<"city">> => coerce(Rec#user_address.city),
             <<"state">> => coerce(Rec#user_address.state),
             <<"postcode">> => coerce(Rec#user_address.postcode),
             <<"country">> => coerce(Rec#user_address.country)}}
    end.

put(Username, Data) ->
    Rec = #user_address{
        username = Username,
        line1 = maps:get(<<"line1">>, Data, <<>>),
        line2 = maps:get(<<"line2">>, Data, <<>>),
        city = maps:get(<<"city">>, Data, <<>>),
        state = maps:get(<<"state">>, Data, <<>>),
        postcode = maps:get(<<"postcode">>, Data, <<>>),
        country = maps:get(<<"country">>, Data, <<>>)
    },
    mnesia:dirty_write(Rec).

coerce(undefined)              -> <<>>;
coerce(V) when is_binary(V)    -> V;
coerce(V) when is_list(V)      -> list_to_binary(V);
coerce(_)                      -> <<>>.
