# ``SwiftHPKE``

Hybrid Public Key Encryption

## Overview

SwiftHPKE implements the Hybrid Public Key Encryption standard as defined in [RFC 9180].

The basic concepts in SwiftHPKE are `CipherSuite`, `Sender` and `Recipient`, represented by the ``SwiftHPKE/CipherSuite`` structure and the ``SwiftHPKE/Sender`` and ``SwiftHPKE/Recipient`` classes.

A CipherSuite combines a *Key Encapsulation Mechanism* (``SwiftHPKE/KEM``), a *Key Derivation Function* (``SwiftHPKE/KDF``)
and a *Authenticated Encryption with Associated Data* (``SwiftHPKE/AEAD``) algorithm.

There are 5 different KEM's, 3 different KDF's and 4 different AEAD's giving 60 CipherSuite combinations.

Encryption and decryption takes place in one of four modes:

* Base mode
* Preshared key mode
* Authenticated mode
* Authenticated, preshared key mode

### Stateless Single-shot API

A `CipherSuite` instance can encrypt (seal) a single plaintext message and decrypt (open) a single
ciphertext message without the need for a `Sender` instance and a `Recipient` instance.

**Example**

```swift
// Encryption and decryption of a single message in base mode

import SwiftHPKE

// The CipherSuite to use
let theSuite = CipherSuite(kem: .X448, kdf: .KDF512, aead: .AESGCM256)

// The recipient keys
let (recipientPub, recipientPriv) = try theSuite.makeKeyPair()

let plainText = Bytes("Hi, there".utf8)
let (encapsulatedKey, cipherText) = try theSuite.seal(publicKey: recipientPub, info: [1, 2, 3], pt: plainText, aad: [4, 5, 6])
let decrypted = try theSuite.open(privateKey: recipientPriv, info: [1, 2, 3], ct: cipherText, aad: [4, 5, 6], encap: encapsulatedKey)
print(String(bytes: decrypted, encoding: .utf8)!)
```
giving:
```swift
Hi, there
```

### Stateful Multi-message API

A `Sender` is based on a specific `CipherSuite` and a `Sender` instance can encrypt (seal)
a sequence of plaintexts in one of the four modes shown above.

A `Recipient` is also based on a specific `CipherSuite` and a `Recipient` instance can decrypt (open)
a sequence of ciphertexts in the four modes.

**Example**

```swift
// Encryption and decryption of several messages in authenticated mode

import SwiftHPKE

// The CipherSuite to use
let theSuite = CipherSuite(kem: .P384, kdf: .KDF384, aead: .CHACHAPOLY)

let plainText1 = Bytes("Hi, there 1".utf8)
let plainText2 = Bytes("Hi, there 2".utf8)
let plainText3 = Bytes("Hi, there 3".utf8)

// The Sender and Recipient keys
let (senderPub, senderPriv) = try theSuite.makeKeyPair()
let (recipientPub, recipientPriv) = try theSuite.makeKeyPair()

// Create the Sender instance
let sender = try Sender(suite: theSuite, publicKey: recipientPub, info: [1, 2, 3], authentication: senderPriv)

let cipherText1 = try sender.seal(pt: plainText1, aad: [4, 5])
let cipherText2 = try sender.seal(pt: plainText2, aad: [6, 7])
let cipherText3 = try sender.seal(pt: plainText3, aad: [8, 9])

// Create the Recipient instance
let recipient = try Recipient(suite: theSuite, privateKey: recipientPriv, info: [1, 2, 3], authentication: senderPub, encap: sender.encapsulatedKey)

let decrypted1 = try recipient.open(ct: cipherText1, aad: [4, 5])
let decrypted2 = try recipient.open(ct: cipherText2, aad: [6, 7])
let decrypted3 = try recipient.open(ct: cipherText3, aad: [8, 9])

print(String(bytes: decrypted1, encoding: .utf8)!)
print(String(bytes: decrypted2, encoding: .utf8)!)
print(String(bytes: decrypted3, encoding: .utf8)!)
```
giving:
```swift
Hi, there 1
Hi, there 2
Hi, there 3
```

> Important:
The messages must be decrypted in the order in which they were encrypted.

### Usage

To use SwiftHPKE, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftHPKE", from: "2.5.0"),
]
```

SwiftHPKE itself depends on the ASN1, BigInt and Digest packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.5.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.17.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.6.0"),
],
```

> Important:
SwiftHPKE requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.
>
> SwiftHPKE uses Apple’s CryptoKit framework. Therefore, for macOS the version must be at least 10.15,
for iOS the version must be at least 13, and for watchOS the version must be at least 8.

## Topics

### Classes

- ``SwiftHPKE/Recipient``
- ``SwiftHPKE/Sender``

### Structures

- ``SwiftHPKE/CipherSuite``
- ``SwiftHPKE/PrivateKey``
- ``SwiftHPKE/PublicKey``
- ``SwiftHPKE/Base64``

### Type Aliases

- ``SwiftHPKE/Byte``
- ``SwiftHPKE/Bytes``

### Enumerations

- ``SwiftHPKE/AEAD``
- ``SwiftHPKE/KDF``
- ``SwiftHPKE/KEM``
- ``SwiftHPKE/HPKEException``

### Additional Information

- <doc:KeyManagement>
- <doc:SecretExport>
- <doc:CryptoKit>
- <doc:Performance>
- <doc:References>

