-module(extended_key).

-export([
         master_private_key/1,
         derive_path/2,
         derive_private_child_key/2,
         derive_public_child_key/2,
         extended_key_id/1,
         neuter/1,
         serialize/2,
         encode_base58/1
        ]).

-define(HARDENED_INDEX_START, 16#80000000).
-define(N, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).


master_private_key(Seed) ->
    {PrivateKey, ChainCode} = master_key(Seed),
    #{private_key        => PrivateKey,
      public_key         => point(PrivateKey),
      chain_code         => ChainCode,
      depth              => 0,
      parent_fingerprint => 0,
      child_index        => 0}.


derive_path(MasterKey, Path) ->
    Elements = binary:split(Path, <<"/">>, [global, trim_all]),
    ExtendedKey0 = case hd(Elements) of
        <<"m">> -> MasterKey;
        <<"M">> -> neuter(MasterKey)
    end,
    lists:foldl(fun(Element, ExtendedKey) ->
                        Index = case binary:last(Element) of
                            H when H=:=$h; H=:=$H; H=:=$' ->
                                erlang:binary_to_integer(binary:part(Element, 0, size(Element)-1)) + ?HARDENED_INDEX_START;
                            _ ->
                                erlang:binary_to_integer(Element)
                        end,
                        case ExtendedKey of
                            #{private_key:=_PrivateKey} -> derive_private_child_key(ExtendedKey, Index);
                            _                           -> derive_public_child_key(ExtendedKey, Index)
                        end
                end,
                ExtendedKey0,
                tl(Elements)).


derive_private_child_key(#{private_key:=PrivateKey, chain_code:=ChainCode, depth:=Depth} = ParentKey, Index) ->
    {ChildPrivateKey, ChildChainCode} = ckd_priv({PrivateKey, ChainCode}, Index),
    #{private_key        => ChildPrivateKey,
      public_key         => point(ChildPrivateKey),
      chain_code         => ChildChainCode,
      depth              => Depth + 1,
      parent_fingerprint => fingerprint(extended_key_id(ParentKey)),
      child_index        => Index}.


derive_public_child_key(#{private_key:=_PrivateKey} = ParentKey, Index) ->
    neuter(derive_private_child_key(ParentKey, Index));

derive_public_child_key(#{public_key:=PublicKey, chain_code:=ChainCode, depth:=Depth} = ParentKey, Index) ->
    {ChildPublicKey, ChildChainCode} = ckd_pub({PublicKey, ChainCode}, Index),
    #{public_key         => ChildPublicKey,
      chain_code         => ChildChainCode,
      depth              => Depth + 1,
      parent_fingerprint => fingerprint(extended_key_id(ParentKey)),
      child_index        => Index}.


extended_key_id(#{public_key:=PublicKey}) ->
    crypto:hash(ripemd160, crypto:hash(sha256, ser_P(PublicKey))).


neuter(#{private_key:=_PrivateKey} = ExtendedKey) ->
    maps:remove(private_key, ExtendedKey);

neuter(ExtendedKey) ->
    ExtendedKey.


serialize(Version, #{private_key:=PrivateKey, chain_code:=ChainCode, depth:=Depth, parent_fingerprint:=ParentFingerprint, child_index:=ChildIndex}) ->
    PrivateKey_ = ser_256(PrivateKey),
    serialize(Version, Depth, ParentFingerprint, ser_32(ChildIndex), ChainCode, <<0:8, PrivateKey_/binary>>);

serialize(Version, #{public_key:=PublicKey, chain_code:=ChainCode, depth:=Depth, parent_fingerprint:=ParentFingerprint, child_index:=ChildIndex}) ->
    serialize(Version, Depth, ParentFingerprint, ser_32(ChildIndex), ChainCode, ser_P(PublicKey)).


% FIXME
encode_base58(#{private_key:=_PrivateKey} = ExtendedKey) ->
    ek_base58:version_encode_check(serialize(16#0488ADE4, ExtendedKey));

encode_base58(ExtendedKey) ->
    ek_base58:version_encode_check(serialize(16#0488B21E, ExtendedKey)).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


ckd_priv({K_par, C_par}, Idx) ->
    I = case Idx >= ?HARDENED_INDEX_START of
        true  -> crypto:hmac(sha512, C_par, [<<0:8>>, ser_256(K_par), ser_32(Idx)]);
        false -> crypto:hmac(sha512, C_par, [ser_P(point(K_par)), ser_32(Idx)])
    end,
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ >= ?N -> throw(error); true -> ok end,
    K_i = (I_L_ + K_par) rem ?N,
    if K_i == 0 -> throw(error); true -> ok end,
    C_i = I_R,
    {K_i, C_i}.


ckd_pub({_, _}, Idx) when Idx >= ?HARDENED_INDEX_START ->
    throw(undefined_for_hardened_children);

ckd_pub({K_par, C_par}, Idx) ->
    I = crypto:hmac(sha512, C_par, [ser_P(K_par), ser_32(Idx)]),
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ >= ?N -> throw(error); true -> ok end,
    K_i = case libsecp256k1:ec_pubkey_tweak_add(uncompressed_pubkey(K_par), I_L) of
        {ok, K_i_} ->
            ok = libsecp256k1:ec_pubkey_verify(K_i_),  % does this check for the point at infinity?
            coordinate_pair(K_i_);
        _ ->
            throw(error)
    end,
    C_i = I_R,
    {K_i, C_i}.


fingerprint(ExtendedKeyId) ->
    <<Fingerprint:32, _/binary>> = ExtendedKeyId,
    Fingerprint.


serialize(Version, Depth, ParentFingerprint, ChildNumber, ChainCode, KeyData) ->
    <<Version:32, Depth:8, ParentFingerprint:32, ChildNumber:4/binary, ChainCode:32/binary, KeyData:33/binary>>.


master_key(Seed) ->
    I = crypto:hmac(sha512, <<"Bitcoin seed">>, Seed),
    {I_L, I_R} = split(I),
    I_L_ = parse_256(I_L),
    if I_L_ == 0 orelse I_L_ >= ?N -> throw(error); true -> ok end,
    K = I_L_,
    C = I_R,
    {K, C}.


split(I) ->
    I_L = binary:part(I, 0, 32),
    I_R = binary:part(I, 32, 32),
    {I_L, I_R}.


point(P) ->
    PrivKey = <<P:256>>,
    {ok, PubKey} = libsecp256k1:ec_pubkey_create(PrivKey, uncompressed),
    coordinate_pair(PubKey).


coordinate_pair(<<4:8, X:256, Y:256>>) ->
    {X, Y}.


uncompressed_pubkey({X, Y}) ->
    <<4:8, X:256, Y:256>>.


ser_32(I) ->
    <<I:32>>.


ser_256(P) ->
    <<P:256>>.


ser_P({X, Y}) ->
    Header = if Y rem 2 == 0 -> <<2:8>>; true -> <<3:8>> end,
    X_ = ser_256(X),
    <<Header/binary, X_/binary>>.


parse_256(P) ->
    <<N:256>> = P,
    N.
