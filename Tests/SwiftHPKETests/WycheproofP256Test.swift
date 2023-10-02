//
//  WycheproofP256Test.swift
//  
//
//  Created by Leif Ibsen on 06/09/2023.
//

import XCTest
@testable import SwiftHPKE

// Test vectors from project Wycheproof - ecdh_secp256r1_test.json
final class WycheproofP256Test: XCTestCase {
    
    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }

    struct dhTest {

        let pubKey: Bytes
        let privKey: Bytes
        let shared: Bytes
        
        init(_ pubKey: String, _ privKey: String, _ shared: String) {
            self.pubKey = hex2bytes(pubKey)
            self.privKey = hex2bytes(privKey)
            self.shared = hex2bytes(shared)
        }
    }

    let tests256: [dhTest] = [
        // tcId = 1, normal case
        dhTest(
            "0462d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26ac333a93a9e70a81cd5a95b5bf8d13990eb741c8c38872b4a07d275a014e30cf",
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285"),
        // tcId = 2, compressed public key
        dhTest(
            "0362d5bd3372af75fe85a040715d0f502428e07046868b0bfdfa61d731afe44f26",
            "0612465c89a023ab17855b0a6bcebfd3febb53aef84138647b5352e02c10c346",
            "53020d908b0219328b658b525f26780e3ae12bcd952bb25a93bc0895e1714285"),
        // tcId = 3, shared secret has x-coordinate that satisfies x**2 = 0
        dhTest(
            "0458fd4168a87795603e2b04390285bdca6e57de6027fe211dd9d25e2212d29e62080d36bd224d7405509295eed02a17150e03b314f96da37445b0d1d29377d12c",
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "0000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 4, shared secret has x-coordinate p-3
        dhTest(
            "04a1ecc24bf0d0053d23f5fd80ddf1735a1925039dc1176c581a7e795163c8b9ba2cb5a4e4d5109f4527575e3137b83d79a9bcb3faeff90d2aca2bed71bb523e7e",
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
        // tcId = 45, y-coordinate of the public key is small
        dhTest(
            "043cbc1b31b43f17dc200dd70c2944c04c6cb1b082820c234a300b05b7763844c74fde0a4ef93887469793270eb2ff148287da9265b0334f9e2609aac16e8ad503",
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "7fffffffffffffffffffffffeecf2230ffffffffffffffffffffffffffffffff"),
        // tcId = 51, y-coordinate of the public key is large
        dhTest(
            "043cbc1b31b43f17dc200dd70c2944c04c6cb1b082820c234a300b05b7763844c7b021f5b006c778ba686cd8f14d00eb7d78256d9b4fccb061d9f6553e91752afc",
            "0a0d622a47e48f6bc1038ace438c6f528aa00ad2bd1da5f13ee46bf5f633d71a",
            "7fffffffffffffffffffffffeecf2230ffffffffffffffffffffffffffffffff"),
        // tcId = 228, point with coordinate y = 1
        dhTest(
            "0409e78d4ef60d05f750f6636209092bc43cbdd6b47e11a9de20a9feb2a50bb96c0000000000000000000000000000000000000000000000000000000000000001",
            "00809c461d8b39163537ff8f5ef5b977e4cdb980e70e38a7ee0b37cc876729e9ff",
            "28f67757acc28b1684ba76ffd534aed42d45b8b3f10b82a5699416eff7199a74"),
    ]

    func test256() throws {
        let kem = KEMStructure(.P256)
        for test in tests256 {
            let priv = try PrivateKey(kem: .P256, bytes: test.privKey)
            let pub = try PublicKey(kem: .P256, bytes: test.pubKey)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

}
