//
//  CryptoKitTest.swift
//  
//
//  Created by Leif Ibsen on 14/08/2023.
//

import XCTest
@testable import SwiftHPKE
import CryptoKit

@available(macOS 14.0, *)
final class CryptoKitTest: XCTestCase {

    let msg = "Hi, there!"

    func testKeysP256() throws {
        let ckPrivKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        let ckPrivKeyDer = Bytes(ckPrivKey.derRepresentation)
        let ckPrivKeyPem = ckPrivKey.pemRepresentation
        let ckPubKey = ckPrivKey.publicKey
        let ckPubKeyDer = Bytes(ckPubKey.derRepresentation)
        let ckPubKeyPem = ckPubKey.pemRepresentation
        let derPrivKey = try PrivateKey(der: ckPrivKeyDer)
        let pemPrivKey = try PrivateKey(pem: ckPrivKeyPem)
        let derPubKey = try PublicKey(der: ckPubKeyDer)
        let pemPubKey = try PublicKey(pem: ckPubKeyPem)
        XCTAssertEqual(derPrivKey, pemPrivKey)
        XCTAssertEqual(derPubKey, pemPubKey)
        XCTAssertEqual(ckPubKeyDer, derPubKey.der)
        XCTAssertEqual(ckPubKeyPem, pemPubKey.pem)
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
        XCTAssertEqual(ckPubKeyPem, pubKeyPem.pem)
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
        XCTAssertEqual(ckPubKeyPem, pubKeyPem.pem)
    }

}
