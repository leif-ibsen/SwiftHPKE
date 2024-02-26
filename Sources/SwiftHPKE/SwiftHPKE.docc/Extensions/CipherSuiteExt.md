# ``SwiftHPKE/CipherSuite``

The cipher suite

## Overview

A CipherSuite instance combines a *Key Encapsulation Mechanism* (``SwiftHPKE/KEM``), a *Key Derivation Function* (``SwiftHPKE/KDF``)
and a *AEAD Encryption Algorithm* (``SwiftHPKE/AEAD``).
It can encrypt or decrypt a single message in one of four modes:

* Base mode
* Preshared key mode
* Authenticated mode
* Authenticated, preshared key mode

## Topics

### Properties

- ``kem``
- ``kdf``
- ``aead``
- ``description``

### Conctructor

- ``init(kem:kdf:aead:)``

### Generate Keys

- ``deriveKeyPair(ikm:)``
- ``makeKeyPair()``

### Base mode

- ``seal(publicKey:info:pt:aad:)``
- ``open(privateKey:info:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:)``
- ``receiveExport(privateKey:info:context:L:encap:)``

### Preshared key mode

- ``seal(publicKey:info:psk:pskId:pt:aad:)``
- ``open(privateKey:info:psk:pskId:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:psk:pskId:)``
- ``receiveExport(privateKey:info:context:L:psk:pskId:encap:)``

### Authenticated mode

- ``seal(publicKey:info:authentication:pt:aad:)``
- ``open(privateKey:info:authentication:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:authentication:)``
- ``receiveExport(privateKey:info:context:L:authentication:encap:)``

### Authenticated, preshared key mode

- ``seal(publicKey:info:authentication:psk:pskId:pt:aad:)``
- ``open(privateKey:info:authentication:psk:pskId:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:authentication:psk:pskId:)``
- ``receiveExport(privateKey:info:context:L:authentication:psk:pskId:encap:)``

