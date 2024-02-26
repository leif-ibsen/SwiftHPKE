# ``SwiftHPKE/Recipient``

The recipient

## Overview

Based on its ``SwiftHPKE/CipherSuite``, a `Recipient` instance can decrypt a sequence of messages in one of four modes:

* Base mode
* Preshared key mode
* Authenticated mode
* Authenticated, preshared key mode

> Important:
The decryption of the messages must be done in the order in which they were encrypted.

A `Recipient` instance can also retrieve a generated export secret.

## Topics

### Constructors

- ``init(suite:privateKey:info:encap:)``
- ``init(suite:privateKey:info:psk:pskId:encap:)``
- ``init(suite:privateKey:info:authentication:encap:)``
- ``init(suite:privateKey:info:authentication:psk:pskId:encap:)``

### Methods

- ``open(ct:aad:)``
- ``receiveExport(context:L:)``

