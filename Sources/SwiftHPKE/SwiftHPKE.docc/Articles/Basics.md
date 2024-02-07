# Basics

## 

The basic concepts in SwiftHPKE are CipherSuite, Sender and Recipient, represented by the ``SwiftHPKE/CipherSuite`` structure and the ``SwiftHPKE/Sender`` and ``SwiftHPKE/Recipient`` classes.

A CipherSuite combines a *Key Encapsulation Mechanism* (``SwiftHPKE/KEM``), a *Key Derivation Function* (``SwiftHPKE/KDF``)
and a *Authenticated Encryption with Associated Data* (``SwiftHPKE/AEAD``) algorithm.

There are 5 different KEM's, 3 different KDF's and 4 different AEAD's giving 60 CipherSuite combinations.

A `Sender` is based on a specific `CipherSuite` and a `Sender` instance can encrypt (seal)
a sequence of plaintexts in one of four modes:

* Base mode
* Preshared key mode
* Authenticated mode
* Authenticated, preshared key mode

A `Recipient` is also based on a specific `CipherSuite` and a `Recipient` instance can decrypt (open)
a sequence of ciphertexts in the four modes shown above.

A `CipherSuite` instance can encrypt (seal) a single plaintext message and decrypt (open) a single
ciphertext message without the need for a `Sender` instance and a `Recipient` instance.

