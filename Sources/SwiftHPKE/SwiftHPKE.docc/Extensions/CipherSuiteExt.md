# ``SwiftHPKE/CipherSuite``

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

### Methods

- ``deriveKeyPair(ikm:)``
- ``makeKeyPair()``

### Methods - base mode

- ``seal(publicKey:info:pt:aad:)``
- ``open(privateKey:info:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:)``
- ``receiveExport(privateKey:info:context:L:encap:)``

### Methods - preshared key mode

- ``seal(publicKey:info:psk:pskId:pt:aad:)``
- ``open(privateKey:info:psk:pskId:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:psk:pskId:)``
- ``receiveExport(privateKey:info:context:L:psk:pskId:encap:)``

### Methods - authenticated mode

- ``seal(publicKey:info:authentication:pt:aad:)``
- ``open(privateKey:info:authentication:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:authentication:)``
- ``receiveExport(privateKey:info:context:L:authentication:encap:)``

### Methods - authenticated, preshared key mode

- ``seal(publicKey:info:authentication:psk:pskId:pt:aad:)``
- ``open(privateKey:info:authentication:psk:pskId:ct:aad:encap:)``
- ``sendExport(publicKey:info:context:L:authentication:psk:pskId:)``
- ``receiveExport(privateKey:info:context:L:authentication:psk:pskId:encap:)``

