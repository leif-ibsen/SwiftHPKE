//
//  Wycheproof25519Test.swift
//  
//
//  Created by Leif Ibsen on 06/09/2023.
//

import XCTest
@testable import SwiftHPKE

// Test vectors from project Wycheproof - x25519_test.json
final class WycheproofX25519Test: XCTestCase {

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

    let tests25519: [dhTest] = [
        // tcId = 1, normal case
        dhTest(
            "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
            "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
            "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"),
        // tcId = 2, public key on twist
        dhTest(
            "63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733",
            "d85d8c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211958",
            "279df67a7c4611db4708a0e8282b195e5ac0ed6f4b2f292c6fbd0acac30d1332"),
        // tcId = 34, edge case public key
        dhTest(
            "0400000000000000000000000000000000000000000000000000000000000000",
            "a8386f7f16c50731d64f82e6a170b142a4e34f31fd7768fcb8902925e7d1e25a",
            "34b7e4fa53264420d9f943d15513902342b386b172a0b0b7c8b8f2dd3d669f59"),
        // tcId = 99, non-canonical public key
        dhTest(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "c85f08e60c845f82099141a66dc4583d2b1040462c544d33d0453b20b1a6377e",
            "e9db74bc88d0d9bf046ddd13f943bccbe6dbb47d49323f8dfeedc4a694991a3c"),
        // tcId = 126, special case public key
        dhTest(
            "0000000000000000000000000000000000000000000000000000008000000000",
            "d818fd6971e546447f361d33d3dbb3eadcf02fb28f246f1d5107b9073a93cd4f",
            "7ed8f2d5424e7ebb3edbdf4abe455447e5a48b658e64abd06c218f33bd151f64"),
        // tcId = 153, special case public key
        dhTest(
            "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "b0f6c28dbdc647068a76d71805ef770f087cf76b82afdc0d26c45b71ace49768",
            "f0097fa0ba70d019126277ab15c56ecc170ca88180b2bf9d80fcda3d7d74552a"),
        // tcId = 511, private key == -1 (mod order)
        dhTest(
            "6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376",
            "a023cdd083ef5bb82f10d62e59e15a6800000000000000000000000000000050",
            "6c05871352a451dbe182ed5e6ba554f2034456ffe041a054ff9cc56b8e946376"),
        // tcId = 515, special case private key
        dhTest(
            "be3b3edeffaf83c54ae526379b23dd79f1cb41446e3687fef347eb9b5f0dc308",
            "4855555555555555555555555555555555555555555555555555555555555555",
            "cfa83e098829fe82fd4c14355f70829015219942c01e2b85bdd9ac4889ec2921"),
        // tcId = 516, spspecial case private key
        dhTest(
            "3e3e7708ef72a6dd78d858025089765b1c30a19715ac19e8d917067d208e0666",
            "b8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6a",
            "4782036d6b136ca44a2fd7674d8afb0169943230ac8eab5160a212376c06d778"),
    ]

    let tests25519smallOrder: [dhTest] = [
        // tcId = 32, public key = 0
        dhTest(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
            "0000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 33, public key = 1
        dhTest(
            "0100000000000000000000000000000000000000000000000000000000000000",
            "48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f",
            "0000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 63, public key with low order
        dhTest(
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272",
            "0000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 64, public key with low order
        dhTest(
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579",
            "0000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 154, special case public key
        dhTest(
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "18630f93598637c35da623a74559cf944374a559114c7937811041fc8605564a",
            "0000000000000000000000000000000000000000000000000000000000000000"),
    ]

    func test25519() throws {
        let kem = KEMStructure(.X25519)
        for test in tests25519 {
            let priv = try PrivateKey(kem: .X25519, bytes: test.privKey)
            let pub = try PublicKey(kem: .X25519, bytes: test.pubKey)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

    func test25519smallOrder() throws {
        let kem = KEMStructure(.X25519)
        for test in tests25519smallOrder {
            let priv = try PrivateKey(kem: .X25519, bytes: test.privKey)
            do {
                let pub = try PublicKey(kem: .X25519, bytes: test.pubKey)
                let _ = try kem.DH(priv, pub)
                XCTFail("Expected smallOrder exception")
            } catch HPKEException.smallOrder {
            } catch {
                XCTFail("Expected smallOrder exception")
            }
        }
    }

}
