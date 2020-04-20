-module(ek_secp256k1).

-export([
         n/0,
         valid_xprv/2,
         valid_xpub/2,
         compress_pubkey/1,
         decompress_pubkey/1,
         derive_pubkey/2,
         pubkey_tweak_add/2
        ]).

-define(N, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).


n() -> ?N.


valid_xprv(Key, Il) when is_binary(Key), is_binary(Il) ->
    Key2 = binary:decode_unsigned(Key),
    Il2 = binary:decode_unsigned(Il),
    Key2>0 andalso Il2>=1 andalso Il2=<?N.


valid_xpub(Key, Il) when is_binary(Key), is_binary(Il) ->
    Result = libsecp256k1:ec_pubkey_verify(Key),
    Il2 = binary:decode_unsigned(Il),
    Result=:=ok andalso Il2>=1 andalso Il2=<?N.


compress_pubkey(<<4:8, X:256, Y:256>>) when Y rem 2 =:= 0 ->
    <<2:8, X:256>>;

compress_pubkey(<<4:8, X:256, Y:256>>) when Y rem 2 =:= 1 ->
    <<3:8, X:256>>;

compress_pubkey(_) ->
    {error, invalid_uncompressed_pubkey}.


decompress_pubkey(<<Prefix:8, _Rest/binary>> = Pubkey) when Prefix=:=2; Prefix=:=3 ->
    {ok, Pubkey2} = libsecp256k1:ec_pubkey_decompress(Pubkey),
    Pubkey2.


derive_pubkey(Privkey, Type) when is_binary(Privkey), Type=:=compressed; Type=:=uncompressed ->
    {ok, Pubkey} = libsecp256k1:ec_pubkey_create(Privkey, Type),
    Pubkey.


pubkey_tweak_add(Pubkey, Point) when is_binary(Pubkey), is_binary(Point) ->
    {ok, Result} = libsecp256k1:ec_pubkey_tweak_add(Pubkey, Point),
    Result.
