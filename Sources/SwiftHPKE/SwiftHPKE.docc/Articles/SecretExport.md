# Secret Export

## 
Given the recipient's public key, a sender can generate a secret that only the recipient can know.

### Example 1
```swift
import SwiftHPKE

// The aead need not be .EXPORTONLY, any aead will work

let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .EXPORTONLY)
let (recipientPubKey, recipientPrivKey) = try theSuite.makeKeyPair()

// Generate the secret

let (encapsulated, secret) = try theSuite.sendExport(publicKey: recipientPubKey, info: [], context: [1, 2, 3], L: 10)
print("Generated secret:", secret)

// The recipient retrieves the secret by means of the encapsulated key

let retrievedSecret = try theSuite.receiveExport(privateKey: recipientPrivKey, info: [], context: [1, 2, 3], L: 10, encap: encapsulated)
print("Retrieved secret:", retrievedSecret)
```
giving (for example):
```swift
Generated secret: [172, 169, 119, 121, 167, 53, 213, 12, 0, 29]
Retrieved secret: [172, 169, 119, 121, 167, 53, 213, 12, 0, 29]
```

### Example 2
```swift
import SwiftHPKE

// The aead need not be .EXPORTONLY, any aead will work

let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .EXPORTONLY)
let (recipientPubKey, recipientPrivKey) = try theSuite.makeKeyPair()
let sender = try Sender(suite: theSuite, publicKey: recipientPubKey, info: [])

// Generate the secret

let secret = try sender.sendExport(context: [1, 2, 3], L: 10)
print("Generated secret:", secret)

// The recipient retrieves the secret by means of the encapsulated key

let receiver = try Recipient(suite: theSuite, privateKey: recipientPrivKey, info: [], encap: sender.encapsulatedKey)
let retrievedSecret = try receiver.receiveExport(context: [1, 2, 3], L: 10)
print("Retrieved secret:", retrievedSecret)
```
giving (for example):
```swift
Generated secret: [3, 230, 139, 128, 86, 4, 81, 78, 110, 135]
Retrieved secret: [3, 230, 139, 128, 86, 4, 81, 78, 110, 135]
```
The above examples use Base mode. Preshared key mode, Authenticated mode and Authenticated, preshared key mode
can also be used.
