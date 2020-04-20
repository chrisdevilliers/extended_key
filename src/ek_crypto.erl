-module(ek_crypto).

-export([
         hash160/1,
         sha256/1,
         sha512/1,
         hmac_sha512/2
        ]).


hash160(Data) ->
    crypto:hash(ripemd160, crypto:hash(sha256, Data)).


sha256(Data) ->
    crypto:hash(sha256, Data).


sha512(Data) ->
    crypto:hash(sha512, Data).


hmac_sha512(Key, Data) ->
    crypto:hmac(sha512, Key, Data).
