# Apple CryptoKit Compatibility

## 

The SwiftHPKE keys of type .P256, .P384, .P521 and .X25519 correspond to Apple
CryptoKit keys of type P256, P384, P521 and Curve25519. Keys of type .X448 is not supported in CryptoKit.

To convert CryptoKit P256 keys (similarly for P384 and P521) - say *ckPriv* and *ckPub* to SwiftHPKE keys:
```swift
let hpkePriv = try PrivateKey(der: Bytes(ckPriv.derRepresentation))
let hpkePub = try PublicKey(der: Bytes(ckPub.derRepresentation))
```
To convert CryptoKit Curve25519 keys - say *ckPriv* and *ckPub* to SwiftHPKE keys:
```swift
let hpkePriv = try PrivateKey(kem: .X25519, bytes: Bytes(ckPriv.rawRepresentation))
let hpkePub = try PublicKey(kem: .X25519, bytes: Bytes(ckPub.rawRepresentation))
```
To convert SwiftHPKE .P256 keys (similarly for .P384 and .P521) - say *hpkePriv* and *hpkePub* to CryptoKit keys:
```swift
let ckPriv = try CryptoKit.P256.KeyAgreement.PrivateKey(derRepresentation: hpkePriv.der)
let ckPub = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: hpkePub.der)
```
To convert SwiftHPKE .X25519 keys - say *hpkePriv* and *hpkePub* to CryptoKit keys:
```swift
let ckPriv = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hpkePriv.bytes)
let ckPub = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: hpkePub.bytes)
```
