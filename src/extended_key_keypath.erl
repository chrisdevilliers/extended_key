-module(extended_key_keypath).

-export([
         to_list/1
        ]).

-define(HARDENED_KEY_START, 16#80000000).


to_list(<<"m">>) -> {xprv, []};
to_list(<<"M">>) -> {xpub, []};
to_list(<<"m/", Path/binary>>) -> {xprv, to_list(Path)};
to_list(<<"M/", Path/binary>>) -> {xpub, to_list(Path)};
to_list(Path) when is_binary(Path) ->
    Parts = binary:split(Path, <<"/">>, [global]),
    lists:map(fun convert_to_integer/1, Parts).


convert_to_integer(Item) ->
    case binary:last(Item) of
        B when B=:=$h; B=:=$H; B=:=$' ->
            Part = binary:part(Item, {0, size(Item)-1}),
            erlang:binary_to_integer(Part) + ?HARDENED_KEY_START;
        _ ->
            erlang:binary_to_integer(Item)
    end.
