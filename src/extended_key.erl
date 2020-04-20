-module(extended_key).

-export([
         seed/0,
         seed/1,
         master/1,
         master/2,
         derive_path/2,
         derive_child/2,
         neuter/1,
         to_string/1,
         from_string/1,
         public/1,
         private/1,
         hardened/1,
         normal/1,
         network/1
        ]).

-define(HARDENED_KEY_START, 16#80000000).

-define(MAINNET_XPUB_VERSION, <<16#04, 16#88, 16#B2, 16#1E>>).
-define(MAINNET_XPRV_VERSION, <<16#04, 16#88, 16#AD, 16#E4>>).
-define(TESTNET_XPUB_VERSION, <<16#04, 16#35, 16#87, 16#CF>>).
-define(TESTNET_XPRV_VERSION, <<16#04, 16#35, 16#83, 16#94>>).

-record(extended_key, {
           version            :: binary(),
           key                :: binary(),
           chain_code         :: binary(),
           parent_fingerprint :: binary(),
           depth              :: integer(),
           child_num          :: integer()
          }).


seed() ->
    seed(32).


seed(ByteSize) ->
    crypto:strong_rand_bytes(ByteSize).


master(Seed) ->
    master(Seed, mainnet).


master(Seed, Network) when byte_size(Seed)>=16, byte_size(Seed)=<64 ->
    <<Key:32/binary, ChainCode:32/binary>> = ek_crypto:hmac_sha512(<<"Bitcoin seed">>, Seed),
    #extended_key{
       version            = version(xprv, Network),
       key                = Key,
       chain_code         = ChainCode,
       parent_fingerprint = <<0:32>>,
       depth              = 0,
       child_num          = 0
      };
 
master(_Seed, _Network) -> {error, invalid_seed}.


derive_path(#extended_key{version=Version} = Master, Path) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?TESTNET_XPRV_VERSION ->
    case ek_keypath:to_list(Path) of
        {xprv, Keypath} -> do_derive_path(Master, Keypath);
        {xpub, Keypath} -> neuter(do_derive_path(Master, Keypath))
    end;

derive_path(#extended_key{version=Version} = Master, Path) when Version=:=?MAINNET_XPUB_VERSION; Version=:=?TESTNET_XPUB_VERSION ->
    case ek_keypath:to_list(Path) of
        {xprv, _}       -> {error, parent_pubkey_to_child_privkey};
        {xpub, Keypath} -> do_derive_path(Master, Keypath)
    end.


derive_child(#extended_key{depth=Depth, version=Version} = Parent, ChildIndex) when Depth<255 ->
    case child_key_and_chain_code(Parent, ChildIndex) of
        {ok, ChildKey, ChildChainCode} ->
            #extended_key{
               version            = Version,
               key                = ChildKey,
               chain_code         = ChildChainCode,
               parent_fingerprint = parent_fingerprint(Parent),
               depth              = Depth + 1,
               child_num          = ChildIndex
              };
        Error ->
            Error
    end;

derive_child(_Parent, _ChildIndex) -> {error, invalid_depth}.


neuter(#extended_key{version=Version, key=Key} = ExtendedKey) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?TESTNET_XPRV_VERSION ->
    ExtendedKey#extended_key{
      version = version(xpub, network(ExtendedKey)),
      key     = ek_secp256k1:derive_pubkey(Key, compressed)
     };

neuter(#extended_key{version=Version} = ExtendedKey) when Version=:=?MAINNET_XPUB_VERSION; Version=:=?TESTNET_XPUB_VERSION -> ExtendedKey.


to_string({error, Error}) -> {error, Error};
to_string(#extended_key{} = ExtendedKey) ->
    ek_base58:version_encode_check(serialize(ExtendedKey)).


from_string(KeyString) when is_binary(KeyString) ->
    deserialize(ek_base58:version_decode_check(KeyString)).


public(#extended_key{version=Version}) when Version=:=?MAINNET_XPUB_VERSION; Version=:=?TESTNET_XPUB_VERSION -> true;
public(#extended_key{}) -> false.


private(#extended_key{version=Version}) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?TESTNET_XPRV_VERSION -> true;
private(#extended_key{}) -> false.


hardened(#extended_key{child_num=ChildNum}) when ChildNum>=?HARDENED_KEY_START -> true;
hardened(#extended_key{}) -> false.


normal(#extended_key{child_num=ChildNum}) when ChildNum>=0, ChildNum<?HARDENED_KEY_START -> true;
normal(#extended_key{}) -> false.


network(#extended_key{version=Version}) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?MAINNET_XPUB_VERSION ->
    mainnet;
network(#extended_key{version=Version}) when Version=:=?TESTNET_XPRV_VERSION; Version=:=?TESTNET_XPUB_VERSION ->
    testnet.


deserialize(<<Version:4/binary, Depth:8, Fingerprint:4/binary, ChildNum:32, ChainCode:32/binary, KeyData:33/binary>>) ->
    Key = case private(#extended_key{version=Version}) of
        true  -> binary:part(KeyData, 1, byte_size(KeyData)-1);  % all but first byte
        false -> KeyData
    end,
    #extended_key{
       version            = Version,
       key                = Key,
       chain_code         = ChainCode,
       child_num          = ChildNum,
       parent_fingerprint = Fingerprint,
       depth              = Depth
      };

deserialize(_) -> {error, invalid_data}.


serialize(#extended_key{version=Version, key=Key, chain_code=ChainCode, parent_fingerprint=Fingerprint, depth=Depth, child_num=ChildNum} = ExtendedKey) ->
    KeyData = case private(ExtendedKey) of
        true  -> <<0, Key:32/binary>>;
        false -> Key
    end,
    <<Version:4/binary, Depth:8, Fingerprint:4/binary, ChildNum:32, ChainCode:32/binary, KeyData:33/binary>>.


% Private parent key → private child key - hardened child
% Private parent key → private child key - normal child
child_key_and_chain_code(#extended_key{version=Version, key=ParentKey} = Parent, ChildIndex) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?TESTNET_XPRV_VERSION ->
    {ok, Il, ChildChainCode} = il_and_ir(Parent, ChildIndex),
    Rem = ek_binary:unsigned_sum(Il, ParentKey) rem ek_secp256k1:n(),
    ChildKey = <<Rem:256>>,

    case ek_secp256k1:valid_xprv(ChildKey, Il) of
        true  -> {ok, ChildKey, ChildChainCode};
        false -> {error, invalid_child}
    end;

% Public parent key → public child key - hardened child
% Public parent key → public child key - normal child
child_key_and_chain_code(#extended_key{version=Version, key=ParentKey} = Parent, ChildIndex) when Version=:=?MAINNET_XPUB_VERSION; Version=:=?TESTNET_XPUB_VERSION ->
    DeriveChildKey = fun(PK, Il) ->
                             ek_secp256k1:compress_pubkey(
                               ek_secp256k1:pubkey_tweak_add(
                                 ek_secp256k1:decompress_pubkey(PK), 
                                 Il
                               )
                             )
                     end,

    case il_and_ir(Parent, ChildIndex) of
        {ok, Il, ChildChainCode} ->
            case DeriveChildKey(ParentKey, Il) of
                ChildKey when is_binary(ChildKey) ->
                    case ek_secp256k1:valid_xpub(ChildKey, Il) of
                        true -> {ok, ChildKey, ChildChainCode};
                        _    -> error
                    end;
                _ -> error
            end;
        _ -> error
    end.


parent_fingerprint(#extended_key{key=Key, version=Version}) when Version=:=?MAINNET_XPRV_VERSION; Version=:=?TESTNET_XPRV_VERSION ->
    ek_binary:take(ek_crypto:hash160(ek_secp256k1:derive_pubkey(Key, compressed)), 4);

parent_fingerprint(#extended_key{key=Key, version=Version}) when Version=:=?MAINNET_XPUB_VERSION; Version=:=?TESTNET_XPUB_VERSION ->
    ek_binary:take(ek_crypto:hash160(Key), 4).


i_data(#extended_key{version=Version, key=ParentKey}, ChildIndex) when ChildIndex>=?HARDENED_KEY_START, 
                                                                       Version=:=?MAINNET_XPRV_VERSION orelse Version=:=?TESTNET_XPRV_VERSION ->
    <<0, ParentKey:32/binary, ChildIndex:32>>;

i_data(#extended_key{version=Version, key=ParentKey}, ChildIndex) when ChildIndex>=0 andalso ChildIndex<?HARDENED_KEY_START,
                                                                       Version=:=?MAINNET_XPRV_VERSION orelse Version=:=?TESTNET_XPRV_VERSION ->
    Pubkey = ek_secp256k1:derive_pubkey(ParentKey, compressed),
    <<Pubkey:33/binary, ChildIndex:32>>;

i_data(#extended_key{version=Version}, ChildIndex) when ChildIndex>=?HARDENED_KEY_START, 
                                                        Version=:=?MAINNET_XPUB_VERSION orelse Version=:=?TESTNET_XPUB_VERSION ->
    {error, 'HCKD_from_public'};

i_data(#extended_key{version=Version, key=ParentKey}, ChildIndex) when ChildIndex>=0 andalso ChildIndex<?HARDENED_KEY_START,
                                                                       Version=:=?MAINNET_XPUB_VERSION orelse Version=:=?TESTNET_XPUB_VERSION ->
    <<ParentKey:33/binary, ChildIndex:32>>.


il_and_ir(#extended_key{chain_code=ParentChainCode} = Parent, ChildIndex) ->
    case i_data(Parent, ChildIndex) of
        Data when is_binary(Data) ->
            <<Il:32/binary, Ir:32/binary>> = ek_crypto:hmac_sha512(ParentChainCode, Data),
            {ok, Il, Ir};
        {error, Error} ->
            {error, Error}
    end.


do_derive_path({error, Error}, _) -> {error, Error};
do_derive_path(Key, []) -> Key;
do_derive_path(Key, [ChildIndex | Rest]) ->
    do_derive_path(derive_child(Key, ChildIndex), Rest).


version(xprv, mainnet) -> ?MAINNET_XPRV_VERSION;
version(xpub, mainnet) -> ?MAINNET_XPUB_VERSION;
version(xprv, testnet) -> ?TESTNET_XPRV_VERSION;
version(xpub, testnet) -> ?TESTNET_XPUB_VERSION.
