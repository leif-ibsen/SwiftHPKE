# Creating Public and Private Keys

## 

Given a *CipherSuite* instance it is possible to generate new public- and private keys.
### Example
```swift
import SwiftHPKE

let suite = CipherSuite(kem: .X25519, kdf: .KDF256, aead: .CHACHAPOLY)
let (pubKey, privKey) = try suite.makeKeyPair()

// See the key ASN1 structures

print(pubKey)
print(privKey)
```
giving (for example):
```swift
Sequence (2):
  Sequence (1):
    Object Identifier: 1.3.101.110
  Bit String (256): 11100111 11100111 00010111 11110101 10101000 10010101 01001010 00100010 00011010 10001001 11001011 11010001 11101101 10000101 01110101 11011111 11010110 00001101 01001110 10100100 00111011 00110100 01110000 01011000 00111111 01011011 10001010 11111010 01101000 10010011 10100001 00001101

Sequence (3):
  Integer: 0
  Sequence (1):
    Object Identifier: 1.3.101.110
  Octet String (34): 04 20 b0 e5 94 7d f8 72 04 8f 90 79 5f d5 b7 e4 6e ca 56 18 58 30 2e 4e 79 83 d6 46 bb 42 70 2a 34 68
```
