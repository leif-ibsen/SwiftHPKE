//
//  WycheproofP521Test.swift
//  
//
//  Created by Leif Ibsen on 06/09/2023.
//

import XCTest
@testable import SwiftHPKE
import struct Digest.Base64

// Test vectors from project Wycheproof - ecdh_secp521r1_test.json
final class WycheproofP521Test: XCTestCase {

    struct dhTest {

        let pubKey: Bytes
        let privKey: Bytes
        let shared: Bytes
        
        init(_ pubKey: String, _ privKey: String, _ shared: String) {
            self.pubKey = Base64.hex2bytes(pubKey)!
            self.privKey = Base64.hex2bytes(privKey)!
            self.shared = Base64.hex2bytes(shared)!
        }
    }

    let tests521: [dhTest] = [
        // tcId = 1, normal case
        dhTest(
            "040064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1613cf3077999b5ce00e04ad19cf9fd4722b0c824c069f70c3c0e7ebc5288940dfa92422152ae4a4f79183ced375afb54db1409ddf338b85bb6dbfc5950163346bb63a90a70c5aba098f7",
            "01939982b529596ce77a94bc6efd03e92c21a849eb4f87b8f619d506efc9bb22e7c61640c90d598f795b64566dc6df43992ae34a1341d458574440a7371f611c7dcd",
            "01f1e410f2c6262bce6879a3f46dfb7dd11d30eeee9ab49852102e1892201dd10f27266c2cf7cbccc7f6885099043dad80ff57f0df96acf283fb090de53df95f7d87"),
        // tcId = 2, compressed public key
        dhTest(
            "030064da3e94733db536a74a0d8a5cb2265a31c54a1da6529a198377fbd38575d9d79769ca2bdf2d4c972642926d444891a652e7f492337251adf1613cf3077999b5ce",
            "01939982b529596ce77a94bc6efd03e92c21a849eb4f87b8f619d506efc9bb22e7c61640c90d598f795b64566dc6df43992ae34a1341d458574440a7371f611c7dcd",
            "01f1e410f2c6262bce6879a3f46dfb7dd11d30eeee9ab49852102e1892201dd10f27266c2cf7cbccc7f6885099043dad80ff57f0df96acf283fb090de53df95f7d87"),
        // tcId = 3, shared secret has x-coordinate that satisfies x**2 = 0
        dhTest(
            "04014c643329691ba27459a40dfe7c4ce17b3ea14d0cd7aa47b01f1315404db51436fbbfe6de0842e0f7e1265f6ff3aca28750677d3370b2fb2a6ef497356f4b95811201051b14178639a09a41465c72d3743436ee1c191ff7388a40140b34d5317de5911ea03cdbb0329fdeb446695a3b92d437271a9f3c318b02dec4d473908158140e97",
            "00a2b6442a37f8a3759d2cb91df5eca75af6b89e27baf2f6cbf971dee5058ffa9d8dac805c7bc72f3718489d6a9cb2787af8c93a17ddeb1a19211ab23604d47b7646",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 45, ephemeral key has x-coordinate that satisfies x**2 = 0
        dhTest(
            "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d20ec9fea6b577c10d26ca1bb446f40b299e648b1ad508aad068896fee3f8e614bc63054d5772bf01a65d412e0bcaa8e965d2f5d332d7f39f846d440ae001f4f87",
            "012bc15cf3981eab6102c39f9a925aa130763d01ed6edaf14306eb0a14dd75dff504070def7b88d8b165082f69992de0ffa5ee922cb3ab39917da8524cac73f0a09c",
            "0053bf137fee8922769f8d0fe279caa4dac9c6054ad0460995588a845d0a959e24bc0fc2391a2b92f7bd400f50a11a9db37f07bef7fa8dad2a903fcf534abc8736f7"),
        // tcId = 46, ephemeral key has x-coordinate that satisfies x**2 = 1
        dhTest(
            "040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010010e59be93c4f269c0269c79e2afd65d6aeaa9b701eacc194fb3ee03df47849bf550ec636ebee0ddd4a16f1cd9406605af38f584567770e3f272d688c832e843564",
            "012bc15cf3981eab6102c39f9a925aa130763d01ed6edaf14306eb0a14dd75dff504070def7b88d8b165082f69992de0ffa5ee922cb3ab39917da8524cac73f0a09c",
            "01c95ac417c90a520149b29105cdab36f528a23efb5621520dbdafea95a7d43499c4c8be02cd1c2de000da18104fa84a1e9ece6386f0e0efa5234a24595d7c4c96f4"),
        // tcId = 539, point with coordinate y = 1
        dhTest(
            "0400703dde202ea03d1d673735002cc62cc740536104d81fc9fd8ebdb7dfa908f599d8fea46debc190a5b2ef5f4493f9b5ecd8da9407bf4fc8e1732803a74ee65f747b017c9b038d86afc941403facaa1e2a6376dec075c035ab2c1f42db5fcda3ad3fec67bcf22baf6c81b4241b4a9257f8c2126880e1d6a69a3e5ac7e98710fb24d505df",
            "01781d86cac2c052b7e4f48cef415c5c1319e07db70db92a497c2ac764e9509ac0b07322801f5ae1f28c9d7db71f79e5f51bf646790af988d62339a6d1543192e327",
            "01b248dbd8dfa667a10ab32af68fa8967c69496ebf80c11fd0efb769ea93f84f5a2968b7ed81b2fd9aa913accec701ddce0d1f8b43b1c671f547822f796efb12d559"),
    ]

    func test521() throws {
        let kem = KEMStructure(.P521)
        for test in tests521 {
            let priv = try PrivateKey(kem: .P521, bytes: test.privKey)
            let pub = try PublicKey(kem: .P521, bytes: test.pubKey)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

}
