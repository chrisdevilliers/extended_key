-module(ek_base58).

-export([
         encode/1,
         decode/1,
         version_encode_check/1,
         version_decode_check/1
        ]).


encode(Binary) ->
    list_to_binary(base58:binary_to_base58(Binary)).


decode(<<>>) -> <<>>;
decode(Base58) ->
    base58:base58_to_binary(binary_to_list(Base58)).


version_encode_check(Binary) ->
    <<Checksum:32, _Rest/binary>> = ek_crypto:sha256(ek_crypto:sha256(Binary)),
    encode(<<Binary/binary, Checksum:32>>).


version_decode_check(Base58Check) ->
    BinaryCheck = decode(Base58Check),
    case size(BinaryCheck)-4 of
        N when N>=0 ->
            <<Binary:N/binary, Checksum:32>> = BinaryCheck,
            case ek_crypto:sha256(ek_crypto:sha256(Binary)) of
                <<Checksum:32, _/binary>> -> Binary;
                _                         -> throw(checksum_mismatch)
            end;
        _ ->
            throw(checksum_missing)
    end.
