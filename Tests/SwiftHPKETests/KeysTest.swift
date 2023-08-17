//
//  KeysTest.swift
//  
//
//  Created by Leif Ibsen on 13/08/2023.
//

import XCTest
@testable import SwiftHPKE

final class KeysTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func doTest(_ kem: KEM) throws {
        let suite = CipherSuite(kem: kem, kdf: .KDF256, aead: .AESGCM128)
        let (pubKey, privKey) = try suite.makeKeyPair()
        let pubKeyDER = try PublicKey(der: pubKey.der)
        let privKeyDER = try PrivateKey(der: privKey.der)
        let pubKeyPEM = try PublicKey(pem: pubKey.pem)
        let privKeyPEM = try PrivateKey(pem: privKey.pem)
        XCTAssertEqual(pubKey, pubKeyDER)
        XCTAssertEqual(pubKey, pubKeyPEM)
        XCTAssertEqual(privKey, privKeyDER)
        XCTAssertEqual(privKey, privKeyPEM)
    }

    func test1() throws {
        try doTest(.P256)
        try doTest(.P384)
        try doTest(.P521)
        try doTest(.X25519)
        try doTest(.X448)
    }

}
