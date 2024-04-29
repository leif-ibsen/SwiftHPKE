//
//  KEM.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 22/06/2023.
//

import Foundation
import BigInt

/// The key encapsulation mechanisms
public enum KEM: CustomStringConvertible, CaseIterable {
    
    /// Textual description of `self`
    public var description: String {
        switch self {
        case .P256:
            return "P256"
        case .P384:
            return "P384"
        case .P521:
            return "P521"
        case .X25519:
            return "X25519"
        case .X448:
            return "X448"
        }
    }

    /// P256 - HKDF-SHA256
    case P256
    /// P384 - HKDF-SHA384
    case P384
    /// P521 - HKDF-SHA512
    case P521
    /// X25519 - HKDF-SHA256
    case X25519
    /// X448 - HKDF-SHA512
    case X448
}

struct KEMStructure {
    
    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }
    
    let kem: KEM
    let kdfStructure: KDFStructure
    let Nsecret: Int
    let Nsk: Int
    let Npk: Int
    let bitmask: Byte
    
    init(_ kem: KEM) {
        self.kem = kem
        switch kem {
        case .P256:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x10]
            self.kdfStructure = KDFStructure(.KDF256, suite_id)
            self.Nsecret = 32
            self.Npk = CurveP256.publicKeySize
            self.Nsk = CurveP256.privateKeySize
            self.bitmask = 0xff
        case .P384:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x11]
            self.kdfStructure = KDFStructure(.KDF384, suite_id)
            self.Nsecret = 48
            self.Npk = CurveP384.publicKeySize
            self.Nsk = CurveP384.privateKeySize
            self.bitmask = 0xff
        case .P521:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x12]
            self.kdfStructure = KDFStructure(.KDF512, suite_id)
            self.Nsecret = 64
            self.Npk = CurveP521.publicKeySize
            self.Nsk = CurveP521.privateKeySize
            self.bitmask = 0x01
        case .X25519:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x20]
            self.kdfStructure = KDFStructure(.KDF256, suite_id)
            self.Nsecret = 32
            self.Npk = Curve25519.keySize
            self.Nsk = Curve25519.keySize
            self.bitmask = 0x00
        case .X448:
            let suite_id = Bytes("KEM".utf8) + [0x00, 0x21]
            self.kdfStructure = KDFStructure(.KDF512, suite_id)
            self.Nsecret = 56
            self.Npk = Curve448.keySize
            self.Nsk = Curve448.keySize
            self.bitmask = 0x00
        }
    }
    
    func deriveKeyPair(_ ikm: Bytes) throws -> (pubKey: PublicKey, privKey: PrivateKey) {
        let dkp_prk = self.kdfStructure.labeledExtract([], Bytes("dkp_prk".utf8), ikm)
        var privKey: PrivateKey
        switch self.kem {
        case .P256:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= CurveP256.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes = self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            privKey = try PrivateKey(kem: .P256, bytes: sk.asMagnitudeBytes())
        case .P384:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= CurveP384.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes = self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            privKey = try PrivateKey(kem: .P384, bytes: sk.asMagnitudeBytes())
        case .P521:
            var sk = BInt.ZERO
            var counter = 0
            while sk.isZero || sk >= CurveP521.order {
                if counter > 255 {
                    throw HPKEException.derivedKeyError
                }
                var bytes = self.kdfStructure.labeledExpand(dkp_prk, Bytes("candidate".utf8), [Byte(counter & 0xff)], self.Nsk)
                bytes[0] &= self.bitmask
                sk = BInt(magnitude: bytes)
                counter += 1
            }
            privKey = try PrivateKey(kem: .P521, bytes: sk.asMagnitudeBytes())
        case .X25519:
            let sk = self.kdfStructure.labeledExpand(dkp_prk, Bytes("sk".utf8), [], self.Nsk)
            privKey = try PrivateKey(kem: .X25519, bytes: sk)
        case .X448:
            let sk = self.kdfStructure.labeledExpand(dkp_prk, Bytes("sk".utf8), [], self.Nsk)
            privKey = try PrivateKey(kem: .X448, bytes: sk)
        }
        return (privKey.publicKey, privKey)
    }
    
    func generateKeyPair(_ ikm: Bytes) throws  -> (pubKey: PublicKey, privKey: PrivateKey) {
        var IKM: Bytes
        if ikm.count > 0 {
            IKM = ikm
        } else {
            IKM = Bytes(repeating: 0, count: self.Nsk)
            KEMStructure.randomBytes(&IKM)
        }
        return try deriveKeyPair(IKM)
    }

    func DH(_ sk: PrivateKey, _ pk: PublicKey) throws -> Bytes {
        switch self.kem {
        case .P256:
            let Z = Curve.p256.multiply(pk.w!, sk.s!)
            return Curve.p256.align(Z.x.asMagnitudeBytes())
        case .P384:
            let Z = Curve.p384.multiply(pk.w!, sk.s!)
            return Curve.p384.align(Z.x.asMagnitudeBytes())
        case .P521:
            let Z = Curve.p521.multiply(pk.w!, sk.s!)
            return Curve.p521.align(Z.x.asMagnitudeBytes())
        case .X25519:
            return try Curve25519.X25519(sk.bytes, pk.bytes)
        case .X448:
            return try Curve448.X448(sk.bytes, pk.bytes)
        }
    }

    func extractAndExpand(_ dh: Bytes, _ kem_context: Bytes) -> Bytes {
        let eae_prk = self.kdfStructure.labeledExtract([], Bytes("eae_prk".utf8), dh)
        return self.kdfStructure.labeledExpand(eae_prk, Bytes("shared_secret".utf8), kem_context, self.Nsecret)
    }
    
    func encap(_ pkR: PublicKey, _ ikm: Bytes) throws -> (sharedSecret: Bytes, enc: Bytes) {
        let (pkE, skE) = try generateKeyPair(ikm)
        let dh = try DH(skE, pkR)
        let enc = pkE.bytes
        let pkRm = pkR.bytes
        let kem_context = enc + pkRm
        let shared_secret = extractAndExpand(dh, kem_context)
        return (shared_secret, enc)
    }

    func decap(_ enc: Bytes, _ skR: PrivateKey) throws -> Bytes {
        let pkE = try PublicKey(kem: self.kem, bytes: enc)
        let dh = try DH(skR, pkE)
        let pkRm = skR.publicKey.bytes
        let kem_context = enc + pkRm
        let shared_secret = extractAndExpand(dh, kem_context)
        return shared_secret
    }

    func authEncap(_ pkR: PublicKey, _ skS: PrivateKey, _ ikm: Bytes) throws -> (sharedSecret: Bytes, enc: Bytes) {
        let (pkE, skE) = try generateKeyPair(ikm)
        let dh = try DH(skE, pkR) + DH(skS, pkR)
        let enc = pkE.bytes
        let pkRm = pkR.bytes
        let pkSm = skS.publicKey.bytes
        let kem_context = enc + pkRm + pkSm
        let shared_secret = extractAndExpand(dh, kem_context)
        return (shared_secret, enc)
    }

    func authDecap(_ enc: Bytes, _ skR: PrivateKey, _ pkS: PublicKey) throws -> Bytes {
        let pkE = try PublicKey(kem: self.kem, bytes: enc)
        let dh = try DH(skR, pkE) + DH(skR, pkS)
        let pkRm = skR.publicKey.bytes
        let pkSm = pkS.bytes
        let kem_context = enc + pkRm + pkSm
        let shared_secret = extractAndExpand(dh, kem_context)
        return shared_secret
    }

}
