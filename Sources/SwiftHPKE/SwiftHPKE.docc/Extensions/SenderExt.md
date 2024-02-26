# ``SwiftHPKE/Sender``

The sender

## Overview

Based on its ``SwiftHPKE/CipherSuite``, a `Sender` instance can encrypt a sequence of messages in one of four modes:

* Base mode
* Preshared key mode
* Authenticated mode
* Authenticated, preshared key mode
 
A `Sender` instance can also generate an export secret that only the recipient can know.

## Topics

### Properties

- ``encapsulatedKey``

### Constructors

- ``init(suite:publicKey:info:)``
- ``init(suite:publicKey:info:psk:pskId:)``
- ``init(suite:publicKey:info:authentication:)``
- ``init(suite:publicKey:info:authentication:psk:pskId:)``

### Methods

- ``seal(pt:aad:)``
- ``sendExport(context:L:)``
