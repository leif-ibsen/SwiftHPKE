//
//  DHTest.swift
//  
//
//  Created by Leif Ibsen on 21/08/2023.
//

import XCTest
@testable import SwiftHPKE

// Test vectors from project Wycheproof
final class DHTest: XCTestCase {

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

        let pubPem: String
        let privPem: String
        let shared: Bytes
        
        init(_ pubPem: String, _ privPem: String, _ shared: String) {
            self.pubPem = "-----BEGIN PUBLIC KEY-----\n" + pubPem + "\n-----END PUBLIC KEY-----"
            self.privPem = "-----BEGIN PRIVATE KEY-----\n" + privPem + "\n-----END PRIVATE KEY-----"
            self.shared = hex2bytes(shared)
        }
    }
    
    let tests25519: [dhTest] = [
        dhTest(
            "MCowBQYDK2VuAyEAUEo2mZ9InNL9vAi6/z2I+gBWm6mGy6IlSP/egPmAaCk=",
            "MC4CAQAwBQYDK2VuBCIEIMip1akQka2FHGaLBzbByaApNsDTrWJnCFgIgEe6BXR1",
            "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"),
        dhTest(
            "MCowBQYDK2VuAyEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "MC4CAQAwBQYDK2VuBCIEINA+3enz57eZBF+aw3k9SpJ32t6txBvsApD4H3RPc3df",
            "b87a1722cc6c1e2feecb54e97abd5a22acc27616f78f6e315fd2b73d9f221e57"),
        dhTest(
            "MCowBQYDK2VuAyEAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "MC4CAQAwBQYDK2VuBCIEIOCovmMxXE8PCj/uYH9E0wpVvmPwlWHZr5PgocnPDtdR",
            "0c50ac2bfb6815b47d0734c5981379882a24a2de6166853c735329d978baee4d"),
    ]

    let tests448: [dhTest] = [
        dhTest(
            "MEIwBQYDK2VvAzkAPreoKbDNIPW8/AtZm2/sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk=",
            "MEYCAQAwBQYDK2VvBDoEOJqPSSXRUZ9Xdc9GsEtYANTunui66LxVZdSYwo3Zybr1dKlBl0SJc5EAY4Km8SerHZrC2MClmHJr",
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"),
        dhTest(
            "MEIwBQYDK2VvAzkA+NkUQwS9jE0fpolXAm/FwbdQIDZbCZHS6xVBpN+j8V56cChc\n04KLUpvs4CHT4DpBXk+MAuuJ7xk=",
            "MEYCAQAwBQYDK2VvBDoEOPy07Tr6ZMhLeESWXISK2IgZJBkRzWXTWivCagc8CNjh\nkbz6BLLb2U4hn3Rt+SnTKY4Dr+tztPvb",
            "3f97c3f87b967daac4e5d12eae05a80c751c3b3e1070886b083e90bb8f63cf76aea0cd4bf5032187e52b1d0513c96f1ac830debcd37887ab"),
        dhTest(
            "MEIwBQYDK2VvAzkAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "MEYCAQAwBQYDK2VvBDoEOIA/aP+YEmdquAlYLwuT6ARhWYyYe8ey5OCovmMxXE8P\nCj/uYH9E0wpVvmPwlWHZr5PgocnPDteR",
            "2754aa144ac700ad183b9c20cd2627db3c51e7644055f71f46e2b999d3e13e346454560fa72a16488561e60d6b6423ed50d1e75a4899a8bd"),
    ]

    func test25519() throws {
        let kem = KEMStructure(.X25519)
        for test in tests25519 {
            let priv = try PrivateKey(pem: test.privPem)
            let pub = try PublicKey(pem: test.pubPem)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

    func test448() throws {
        let kem = KEMStructure(.X448)
        for test in tests448 {
            let priv = try PrivateKey(pem: test.privPem)
            let pub = try PublicKey(pem: test.pubPem)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

}
