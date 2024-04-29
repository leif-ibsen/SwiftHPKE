//
//  CryptoKitBaseTest.swift
//  
//
//  Created by Leif Ibsen on 26/04/2024.
//

import XCTest
@testable import SwiftHPKE
import CryptoKit

@available(macOS 14.0, *)
final class CryptoKitBaseTest: XCTestCase {

    let msg = "Hi, there!"
    let theInfo: Bytes = [1, 2, 3]
    let theAuth: Bytes = [4, 5, 6]

    // CryptoKit seals, SwiftHPKE opens
    func doTest25519_1(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let hpSuite = CipherSuite(kem: .X25519, kdf: .KDF256, aead: .AESGCM128)
        
        let (hpPub, hpPriv) = try hpSuite.makeKeyPair()
        let ckPub = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: hpPub.bytes)
        var ckSender = try CryptoKit.HPKE.Sender(recipientKey: ckPub, ciphersuite: ckSuite, info: Data(info))
        
        let ct = try ckSender.seal(Data(msg.utf8), authenticating: auth)
        let hpRecipient = try Recipient(suite: hpSuite, privateKey: hpPriv, info: info, encap: Bytes(ckSender.encapsulatedKey))
        let pt = try hpRecipient.open(ct: Bytes(ct), aad: auth)

        XCTAssertEqual(pt, Bytes(msg.utf8))
    }
    
    // SwiftHPKE seals, CryptoKit opens
    func doTest25519_2(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let hpSuite = CipherSuite(kem: .X25519, kdf: .KDF256, aead: .AESGCM128)
        let ckPriv = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let ckPub = ckPriv.publicKey
        
        let hpPub = try PublicKey(kem: .X25519, bytes: Bytes(ckPub.rawRepresentation))
        let hpSender = try Sender(suite: hpSuite, publicKey: hpPub, info: info)
        
        let ct = try hpSender.seal(pt: Bytes(msg.utf8), aad: auth)
        var ckRecipient = try CryptoKit.HPKE.Recipient(privateKey: ckPriv, ciphersuite: ckSuite, info: Data(info), encapsulatedKey: Data(hpSender.encapsulatedKey))
        let pt = try ckRecipient.open(ct, authenticating: auth)
        
        XCTAssertEqual(pt, Data(msg.utf8))
    }

    // CryptoKit seals, SwiftHPKE opens
    func doTest256_1(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let hpSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
        
        let (hpPub, hpPriv) = try hpSuite.makeKeyPair()
        let ckPub = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: hpPub.der)
        var ckSender = try CryptoKit.HPKE.Sender(recipientKey: ckPub, ciphersuite: ckSuite, info: Data(info))
        
        let ct = try ckSender.seal(Data(msg.utf8), authenticating: auth)
        let hpRecipient = try Recipient(suite: hpSuite, privateKey: hpPriv, info: info, encap: Bytes(ckSender.encapsulatedKey))
        let pt = try hpRecipient.open(ct: Bytes(ct), aad: auth)

        XCTAssertEqual(pt, Bytes(msg.utf8))
    }

    // SwiftHPKE seals, CryptoKit opens
    func doTest256_2(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128)
        let hpSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .AESGCM128)
        let ckPriv = CryptoKit.P256.KeyAgreement.PrivateKey()
        let ckPub = ckPriv.publicKey
        
        let hpPub = try PublicKey(der: Bytes(ckPub.derRepresentation))
        let hpSender = try Sender(suite: hpSuite, publicKey: hpPub, info: info)
        
        let ct = try hpSender.seal(pt: Bytes(msg.utf8), aad: auth)
        var ckRecipient = try CryptoKit.HPKE.Recipient(privateKey: ckPriv, ciphersuite: ckSuite, info: Data(info), encapsulatedKey: Data(hpSender.encapsulatedKey))
        let pt = try ckRecipient.open(ct, authenticating: auth)
        
        XCTAssertEqual(pt, Data(msg.utf8))
    }

    // CryptoKit seals, SwiftHPKE opens
    func doTest384_1(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P384_HKDF_SHA384, kdf: .HKDF_SHA384, aead: .AES_GCM_256)
        let hpSuite = CipherSuite(kem: .P384, kdf: .KDF384, aead: .AESGCM256)
        
        let (hpPub, hpPriv) = try hpSuite.makeKeyPair()
        let ckPub = try CryptoKit.P384.KeyAgreement.PublicKey(derRepresentation: hpPub.der)
        var ckSender = try CryptoKit.HPKE.Sender(recipientKey: ckPub, ciphersuite: ckSuite, info: Data(info))
        
        let ct = try ckSender.seal(Data(msg.utf8), authenticating: auth)
        let hpRecipient = try Recipient(suite: hpSuite, privateKey: hpPriv, info: info, encap: Bytes(ckSender.encapsulatedKey))
        let pt = try hpRecipient.open(ct: Bytes(ct), aad: auth)

        XCTAssertEqual(pt, Bytes(msg.utf8))
    }

    // SwiftHPKE seals, CryptoKit opens
    func doTest384_2(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P384_HKDF_SHA384, kdf: .HKDF_SHA384, aead: .AES_GCM_256)
        let hpSuite = CipherSuite(kem: .P384, kdf: .KDF384, aead: .AESGCM256)
        let ckPriv = CryptoKit.P384.KeyAgreement.PrivateKey()
        let ckPub = ckPriv.publicKey
        
        let hpPub = try PublicKey(der: Bytes(ckPub.derRepresentation))
        let hpSender = try Sender(suite: hpSuite, publicKey: hpPub, info: info)
        
        let ct = try hpSender.seal(pt: Bytes(msg.utf8), aad: auth)
        var ckRecipient = try CryptoKit.HPKE.Recipient(privateKey: ckPriv, ciphersuite: ckSuite, info: Data(info), encapsulatedKey: Data(hpSender.encapsulatedKey))
        let pt = try ckRecipient.open(ct, authenticating: auth)
        
        XCTAssertEqual(pt, Data(msg.utf8))
    }

    // CryptoKit seals, SwiftHPKE opens
    func doTest521_1(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P521_HKDF_SHA512, kdf: .HKDF_SHA512, aead: .AES_GCM_256)
        let hpSuite = CipherSuite(kem: .P521, kdf: .KDF512, aead: .AESGCM256)
        
        let (hpPub, hpPriv) = try hpSuite.makeKeyPair()
        let ckPub = try CryptoKit.P521.KeyAgreement.PublicKey(derRepresentation: hpPub.der)
        var ckSender = try CryptoKit.HPKE.Sender(recipientKey: ckPub, ciphersuite: ckSuite, info: Data(info))
        
        let ct = try ckSender.seal(Data(msg.utf8), authenticating: auth)
        let hpRecipient = try Recipient(suite: hpSuite, privateKey: hpPriv, info: info, encap: Bytes(ckSender.encapsulatedKey))
        let pt = try hpRecipient.open(ct: Bytes(ct), aad: auth)

        XCTAssertEqual(pt, Bytes(msg.utf8))
    }
    
    // SwiftHPKE seals, CryptoKit opens
    func doTest521_2(_ info: Bytes, _ auth: Bytes) throws {
        let ckSuite = CryptoKit.HPKE.Ciphersuite(kem: .P521_HKDF_SHA512, kdf: .HKDF_SHA512, aead: .AES_GCM_256)
        let hpSuite = CipherSuite(kem: .P521, kdf: .KDF512, aead: .AESGCM256)
        let ckPriv = CryptoKit.P521.KeyAgreement.PrivateKey()
        let ckPub = ckPriv.publicKey
        
        let hpPub = try PublicKey(der: Bytes(ckPub.derRepresentation))
        let hpSender = try Sender(suite: hpSuite, publicKey: hpPub, info: info)
        
        let ct = try hpSender.seal(pt: Bytes(msg.utf8), aad: auth)
        var ckRecipient = try CryptoKit.HPKE.Recipient(privateKey: ckPriv, ciphersuite: ckSuite, info: Data(info), encapsulatedKey: Data(hpSender.encapsulatedKey))
        let pt = try ckRecipient.open(ct, authenticating: auth)
        
        XCTAssertEqual(pt, Data(msg.utf8))
    }

    func test25519() throws {
        try doTest25519_1(theInfo, theAuth)
        try doTest25519_2(theInfo, theAuth)
        try doTest25519_1([], [])
        try doTest25519_2([], [])
    }

    func test256() throws {
        try doTest256_1(theInfo, theAuth)
        try doTest256_2(theInfo, theAuth)
        try doTest256_1([], [])
        try doTest256_2([], [])
    }

    func test384() throws {
        try doTest384_1(theInfo, theAuth)
        try doTest384_2(theInfo, theAuth)
        try doTest384_1([], [])
        try doTest384_2([], [])
    }

    func test521() throws {
        try doTest521_1(theInfo, theAuth)
        try doTest521_2(theInfo, theAuth)
        try doTest521_1([], [])
        try doTest521_2([], [])
    }

}
