//
//  WycheproofP384Test.swift
//  
//
//  Created by Leif Ibsen on 06/09/2023.
//

import XCTest
@testable import SwiftHPKE

// Test vectors from project Wycheproof - ecdh_secp384r1_test.json
final class WycheproofP384Test: XCTestCase {

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

    let tests384: [dhTest] = [
        // tcId = 1, normal case
        dhTest(
            "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa",
            "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1fb1dee4edd64356b9f21c588b75dfd81",
            "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4de1e229da71fef0c77fe49b249190135"),
        // tcId = 2, compressed public key
        dhTest(
            "02790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64a6be15969ffa012dd9185d8796",
            "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1fb1dee4edd64356b9f21c588b75dfd81",
            "6461defb95d996b24296f5a1832b34db05ed031114fbe7d98d098f93859866e4de1e229da71fef0c77fe49b249190135"),
        // tcId = 3, shared secret has x-coordinate that satisfies x**2 = 0
        dhTest(
            "04490e96d17f4c6ceccd45def408cea33e9704a5f1b01a3de2eaaa3409fd160d78d395d6b3b003d71fd1f590fad95bf1c9d8665efc2070d059aa847125c2f707435955535c7c5df6d6c079ec806dce6b6849d337140db7ca50616f9456de1323c4",
            "00a2b6442a37f8a3759d2cb91df5eca75b14f5a6766da8035cc1943b15a8e4ebb6025f373be334080f22ab821a3535a6a7",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 49, y-coordinate of the public key is small
        dhTest(
            "04bfeb47fb40a65878e6b642f40b8e15022ade9ecfa8cb618043063494e2bc5d2df10d36f37869b58ef12dcc35e3982835fd2e55ec41fdfe8cabbbb7bcd8163645a19e9dac59630f3fe93b208094ff87cd461b53cef53482e70e2e8ea87200cc3f",
            "00a2b6442a37f8a3759d2cb91df5eca75b14f5a6766da8035cc1943b15a8e4ebb6025f373be334080f22ab821a3535a6a7",
            "0000000000000000000000000000000000000000000000000000000036a2907c00000000000000000000000000000000"),
        // tcId = 51, y-coordinate of the public key is large
        dhTest(
            "04bfeb47fb40a65878e6b642f40b8e15022ade9ecfa8cb618043063494e2bc5d2df10d36f37869b58ef12dcc35e398283502d1aa13be0201735444484327e9c9ba5e616253a69cf0c016c4df7f6b007831b9e4ac300acb7d18f1d171588dff33c0",
            "00a2b6442a37f8a3759d2cb91df5eca75b14f5a6766da8035cc1943b15a8e4ebb6025f373be334080f22ab821a3535a6a7",
            "0000000000000000000000000000000000000000000000000000000036a2907c00000000000000000000000000000000"),
        // tcId = 585, point with coordinate y = 1
        dhTest(
            "042261b2bf605c22f2f3aef6338719b2c486388ad5240719a5257315969ef01ba27f0a104c89704773a81fdabee6ab5c78000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "00c1781d86cac2c052b7e4f48cef415c5c133052f4e504397e75e4d7cd0ca149da0b4988b8a6ded5ceae4b580691376187",
            "c923fb0d4b24e996e5e0d5df151d3c26b1f61c05b17b7fb39fc8590b47eeaff34709f6f7328923bdcaf7e8e413d77ddc"),
    ]

    func test384() throws {
        let kem = KEMStructure(.P384)
        for test in tests384 {
            let priv = try PrivateKey(kem: .P384, bytes: test.privKey)
            let pub = try PublicKey(kem: .P384, bytes: test.pubKey)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

}
