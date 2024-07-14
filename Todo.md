# Todo
- [ ] export key images as blob
    - [ ] convert json to binary
    - [ ] encrypt
        - [x] chacha20 -> CryptoDome
        - [x] cn_fast_hash
            - [x] keccak_256
        - [x] ed25519
        - [ ] cn_slow_hash
- [ ] encrypt/decrypt seed phrase, or probably more key, check in `monero/src/cryptonote_basic/cryptonote_format_utils.cpp` from monero
    - [ ] add `cn_slow_hash` implementation from `monero/src/crypto/slow-hash.c` from monero
    - [ ] add `sc_add` implementation from `monero/src/crypto/crypto-ops.c` from monero
    - [ ] add `sc_sub` implementation from `monero/src/crypto/crypto-ops.c` from monero
- [ ] strip not needed functionality
- [ ] remove dependencies where possible
    - [?] pynacl~=1.4, assume is needed to sign
    - [?] pysocks~=1.7, assume is not needed how we are offline and airgapped
    - [?] requests, assume we don't need it as long we don't need any daemon/rpc on device
    - [?] ipaddress
    - [?] varint, think this was needed but double check
    - [?] pycryptodomex~=3.14, pretty sure it get's used, but maybe fork pycryptodomex and shake it down to what we really need


For posponing reasons links to code in monero related to encrypt and cn_slow_hash:
- wallet/wallet2.cpp +14657
- wallet/wallet2.cpp +14699
- crypto/chacha.h +73
- crypto/chacha.h +91
- crypto/hash.h +73
- crypto/slow-hash.c +874
- crypto/slow-hash.c +1571
- crypto/slow-hash.c +1776

Don't know if this is helpful, but doesn't seem like that:
- https://www.cs.cmu.edu/~dga/crypto/xmr/cryptonight.png
