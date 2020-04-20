-module(ek_binary).

-export([
         take/2,
         unsigned_sum/2
        ]).


take(Binary, Count) when is_binary(Binary), is_integer(Count), Count>=0, Count=<byte_size(Binary) ->
    <<Bin:Count/binary, _Rest/binary>> = Binary,
    Bin.


unsigned_sum(Bin1, Bin2) ->
    binary:decode_unsigned(Bin1) + binary:decode_unsigned(Bin2).
