//
//  Curve25519Test.swift
//  
//
//  Created by Leif Ibsen on 20/08/2023.
//

import XCTest
@testable import SwiftHPKE

// Testvectors from RFC 7748
final class Curve25519Test: XCTestCase {

    func hex2bytes(_ x: String) -> Bytes {
        let b: Bytes = Bytes(x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }

    func test1() throws {
        let curve = Curve25519()
        let k1 = hex2bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        let u1 = hex2bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        XCTAssertEqual(try curve.X25519(k1, u1), hex2bytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))
        let k2 = hex2bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        let u2 = hex2bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        XCTAssertEqual(try curve.X25519(k2, u2), hex2bytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"))
    }

    func test2() throws {
        let curve = Curve25519()
        var k = Curve25519._9
        var u = Curve25519._9
        for _ in 0 ..< 1 {
            let k1 = k
            k = try curve.X25519(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))
        for _ in 0 ..< 999 {
            let k1 = k
            k = try curve.X25519(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))
        for _ in 0 ..< 999000 {
            let k1 = k
            k = try curve.X25519(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"))
    }

}
