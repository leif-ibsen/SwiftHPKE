# ``SwiftHPKE/PrivateKey``

## Overview

There are five different private key types corresponding to the five KEM's

* P256 - the key is a 32 byte value corresponding to a NIST curve secp256r1 private key
* P384 - the key is a 48 byte value corresponding to a NIST curve secp384r1 private key
* P521 - the key is a 66 byte value corresponding to a NIST curve secp521r1 private key
* X25519 - the key is a 32 byte value corresponding to a curve X25519 private key
* X448 - the key is a 56 byte value corresponding to a curve X448 private key

## Topics

### Properties

- ``bytes``
- ``publicKey``
- ``asn1``
- ``pem``
- ``der``
- ``description``

### Constructors

- ``init(kem:bytes:)``
- ``init(der:)``
- ``init(pem:)``

### Methods

- ``==(_:_:)``
