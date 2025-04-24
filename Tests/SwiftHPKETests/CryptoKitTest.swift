//
//  CryptoKitTest.swift
//  
//
//  Created by Leif Ibsen on 14/08/2023.
//

import XCTest
@testable import SwiftHPKE
import CryptoKit
import struct Digest.Base64

@available(macOS 14.0, *)
final class CryptoKitTest: XCTestCase {

    let msg = "Hi, there!"
    
    // HPKE uses Base64 line size = 76
    // CryptoKit uses Base64 line size = 64
    // Convert from SwiftECC size to CryptoKit size
    func from76to64(_ s: String) -> String {
        return Base64.pemEncode(Base64.pemDecode(s, "PUBLIC KEY")!, "PUBLIC KEY", 64)
    }

    func testKeysP256() throws {
        let ckPrivKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        let ckPrivKeyDer = Bytes(ckPrivKey.derRepresentation)
        let ckPrivKeyPem = ckPrivKey.pemRepresentation
        let ckPubKey = ckPrivKey.publicKey
        let ckPubKeyDer = Bytes(ckPubKey.derRepresentation)
        let ckPubKeyPem = ckPubKey.pemRepresentation
        let privKeyDer = try PrivateKey(der: ckPrivKeyDer)
        let privKeyPem = try PrivateKey(pem: ckPrivKeyPem)
        let pubKeyDer = try PublicKey(der: ckPubKeyDer)
        let pubKeyPem = try PublicKey(pem: ckPubKeyPem)
        XCTAssertEqual(privKeyDer, privKeyPem)
        XCTAssertEqual(pubKeyDer, pubKeyDer)
        XCTAssertEqual(ckPubKeyDer, pubKeyDer.der)
        XCTAssertEqual(ckPubKeyPem, from76to64(pubKeyPem.pem))
    }

    func testKeysP384() throws {
        let ckPrivKey = CryptoKit.P384.KeyAgreement.PrivateKey()
        let ckPrivKeyDer = Bytes(ckPrivKey.derRepresentation)
        let ckPrivKeyPem = ckPrivKey.pemRepresentation
        let ckPubKey = ckPrivKey.publicKey
        let ckPubKeyDer = Bytes(ckPubKey.derRepresentation)
        let ckPubKeyPem = ckPubKey.pemRepresentation
        let privKeyDer = try PrivateKey(der: ckPrivKeyDer)
        let privKeyPem = try PrivateKey(pem: ckPrivKeyPem)
        let pubKeyDer = try PublicKey(der: ckPubKeyDer)
        let pubKeyPem = try PublicKey(pem: ckPubKeyPem)
        XCTAssertEqual(privKeyDer, privKeyPem)
        XCTAssertEqual(pubKeyDer, pubKeyPem)
        XCTAssertEqual(ckPubKeyDer, pubKeyDer.der)
        XCTAssertEqual(ckPubKeyPem, from76to64(pubKeyPem.pem))
    }

    func testKeysP521() throws {
        let ckPrivKey = CryptoKit.P521.KeyAgreement.PrivateKey()
        let ckPrivKeyDer = Bytes(ckPrivKey.derRepresentation)
        let ckPrivKeyPem = ckPrivKey.pemRepresentation
        let ckPubKey = ckPrivKey.publicKey
        let ckPubKeyDer = Bytes(ckPubKey.derRepresentation)
        let ckPubKeyPem = ckPubKey.pemRepresentation
        let privKeyDer = try PrivateKey(der: ckPrivKeyDer)
        let privKeyPem = try PrivateKey(pem: ckPrivKeyPem)
        let pubKeyDer = try PublicKey(der: ckPubKeyDer)
        let pubKeyPem = try PublicKey(pem: ckPubKeyPem)
        XCTAssertEqual(privKeyDer, privKeyPem)
        XCTAssertEqual(pubKeyDer, pubKeyPem)
        XCTAssertEqual(ckPubKeyDer, pubKeyDer.der)
        XCTAssertEqual(ckPubKeyPem, from76to64(pubKeyPem.pem))
    }

}
