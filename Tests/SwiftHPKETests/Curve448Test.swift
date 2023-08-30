//
//  Curve448Test.swift
//  
//
//  Created by Leif Ibsen on 20/08/2023.
//

import XCTest
@testable import SwiftHPKE

// Testvectors from RFC 7748
final class Curve448Test: XCTestCase {

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
        let k1 = hex2bytes(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3")
        let u1 = hex2bytes(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")
        XCTAssertEqual(try Curve448.X448(k1, u1), hex2bytes(
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"))
        let k2 = hex2bytes(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f")
        let u2 = hex2bytes(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")
        XCTAssertEqual(try Curve448.X448(k2, u2), hex2bytes(
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"))
    }

    func test2() throws {
        var k = Curve448._5
        var u = Curve448._5
        for _ in 0 ..< 1 {
            let k1 = k
            k = try Curve448.X448(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes(
            "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"))
        for _ in 0 ..< 999 {
            let k1 = k
            k = try Curve448.X448(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes(
            "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"))
        for _ in 0 ..< 999000 {
            let k1 = k
            k = try Curve448.X448(k, u)
            u = k1
        }
        XCTAssertEqual(k, hex2bytes(
            "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"))
    }

}
