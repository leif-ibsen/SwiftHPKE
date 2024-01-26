# Encryption and Decryption

## 
A *CipherSuite* instance can encrypt (seal) a single plaintext message and decrypt (open) a single ciphertext message.

### Example
```Swift
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
```Swift
Hi, there
```
Using a *Sender* instance and a *Recipient* instance it is possible to encrypt a sequence of plaintext messages
and decrypt a sequence of ciphertext messages.

### Example
```Swift
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
```Swift
Hi, there 1
Hi, there 2
Hi, there 3
```
