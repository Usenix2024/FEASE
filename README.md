# FEASE: Fast-and-Expressive-Asymmetric-Searchable-Encryption

This is the code repository accompanying our paper "FEASE: Fast and Expressive Asymmetric Searchable Encryption".

Asymmetric Searchable Encryption (ASE) enables keyword search on encrypted data and has a large number of practical applications. This paper presents a fast and expressive ASE scheme named FEASE that allows data users to search for any monotonic Boolean search queries, which achieves the state-of-the-art efficiency in the expressive ASE field. Besides, we also propose two applications of FEASE: 1) The first expressive Public-Key Authenticated Encryption with Keyword Search (PAEKS) and 2) A fast and expressive Anonymous Key-Policy Attribute-Based Encryption (KP-ABE) scheme. Both of them share the same efficiency and expressiveness of FEASE. 

We implement our schemes and demonstrate that they perform better than the state-of-the-art (Cui et al., TDSC 2016, Meng et al., ProvSec 2017) on all parameters of practical interest, and our anonymous KP-ABE scheme is even comparable to the non-anonymous KP-ABE schemes in FAME (Agrawal et al., CCS 2017) and FABEO (Riepel et al., CCS 2022). 

The code uses the Charm library and Python and builds upon the code of [FABEO] https://github.com/DoreenRiepel/FABEO (2022). We provide the implementation of the following schemes:

1. CWDWL 2016 [1]
2. MZNLHS 2017 [2]
3. FAME KP-ABE 2017 [3]
4. FABEO KP-ABE 2022 [4]
5. FEASE
6. FEASE - PAEKS
7. FEASE - KPABE

All schemes are implemented using asymmetric pairing groups.

The schemes have been tested with Charm 0.50 and Python 3.9.16 on Ubuntu 22.04. (Note that Charm may not compile on newer Linux systems due to the incompatibility of OpenSSL versions 1.0 and 1.1.).

## Manual Installation

Charm 0.50 can also be installed directly from [this] (https://github.com/JHUISI/charm) page, or by running

```sh
pip install -r requirements.txt
```
Once you have Charm, run
```sh
make && pip install . && python samples/run_cp_schemes.py
```

## References

1. Cui H, Wan Z, Deng R H, et al. Efficient and expressive keyword search over encrypted data in cloud. IEEE Transactions on Dependable and Secure Computing, 2016, 15(3): 409-422.
2. Meng R, Zhou Y, Ning J, et al. An efficient key-policy attribute-based searchable encryption in prime-order groups. Provable Security: 11th International Conference, ProvSec 2017, Xi'an, China, October 23-25, 2017, Proceedings 11. Springer International Publishing, 2017: 39-56.
3. Agrawal S, Chase M. FAME: fast attribute-based message encryption. Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security. 2017: 665-682.
4. Riepel D, Wee H. FABEO: Fast Attribute-Based Encryption with Optimal Security. CCS '22: Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security, November 2022, Pages 2491–2504.
