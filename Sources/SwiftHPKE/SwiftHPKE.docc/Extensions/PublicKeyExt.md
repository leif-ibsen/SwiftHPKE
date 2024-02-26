# ``SwiftHPKE/PublicKey``

The public key

## Overview

There are five different public key types corresponding to the five KEM's

* P256 - the key is a 65 byte value corresponding to a NIST secp256r1 uncompressed curve point
* P384 - the key is a 97 byte value corresponding to a NIST secp384r1 uncompressed curve point
* P521 - the key is a 133 byte value corresponding to a NIST secp521r1 uncompressed curve point
* X25519 - the key is a 32 byte value corresponding to a curve X25519 public key
* X448 - the key is a 56 byte value corresponding to a curve X448 public key

## Topics

### Properties

- ``bytes``
- ``asn1``
- ``pem``
- ``der``
- ``description``

### Constructors

- ``init(kem:bytes:)``
- ``init(der:)``
- ``init(pem:)``

### Equality

- ``==(_:_:)``

