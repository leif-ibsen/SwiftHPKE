//
//  Wycheproof448Test.swift
//  
//
//  Created by Leif Ibsen on 06/09/2023.
//

import XCTest
@testable import SwiftHPKE
import struct Digest.Base64

// Test vectors from project Wycheproof - x448_test.json
final class WycheproofX448Test: XCTestCase {

    static func xhex2bytes(_ x: String) -> Bytes {
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
            self.pubKey = Base64.hex2bytes(pubKey)!
            self.privKey = Base64.hex2bytes(privKey)!
            self.shared = Base64.hex2bytes(shared)!
        }
    }

    let tests448: [dhTest] = [
        // tcId = 1, normal case
        dhTest(
            "f8073fc01c8358362c08740c914b419847ef1e409f4e40d9440febc26f00551adb1c37c6c2a87d8283b8cb453e928a0d42793f72894e0f81",
            "e41c63d5159c89de12163fde9d04cf1f430f346b8b2c1f2a4b1f5aee63d17aec29d4b1debf8b6457e7809d2b15ff9779c97becb04b824efa",
            "acd496ceb5f68bf9c267196b405f59701a40ec88744b7e5e60bf8f81e8b13df448efe402001750edb0b695a0512f08c572a2e356493d170b"),
        // tcId = 2, public key on twist
        dhTest(
            "f8d9144304bd8c4d1fa68957026fc5c1b75020365b0991d2eb1541a4dfa3f15e7a70285cd3828b529bece021d3e03a415e4f8c02eb89ef19",
            "fcb4ed3afa64c84b7844965c848ad88819241911cd65d35a2bc26a073c08d8e191bcfa04b2dbd94e219f746df929d3298e03afeb73b4fbdb",
            "3f97c3f87b967daac4e5d12eae05a80c751c3b3e1070886b083e90bb8f63cf76aea0cd4bf5032187e52b1d0513c96f1ac830debcd37887ab"),
        // tcId = 20, public key on twist
        dhTest(
            "ffffff030000f8ffff1f0000c0ffffff000000feffff070000f0ffff3f000080ffffff010000fcffff0f0000e0ffff7f000000ffffff0300",
            "24cc1c2bd03321210d80e7ba12bac1851cffafcd787383d7383faff669d51e07554d006af14baae0818e7d270445670e53f22b7effbfa689",
            "efe4b32d8ccf5f42e48d7cfe3817a7b82a13a7b76805394d7775c649a8880c2379ed546f37c0ebd9ebb5dcb0d260b7c3d241703797b1f54a"),
        // tcId = 34, edge case public key
        dhTest(
            "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "28110debb1242a869407f21a1a07616326e2bba0ae3ddca3d43edde9f3e7b799045f9ac3793d4a9277dadeadc41bec0290f81f744f7377df",
            "021ea3e58bb9ff27a1109079a8c5a05bb09760864bca1650ed3d825640c5134d0631f529d79510f062883b1217beda88f52801fd5bfae91e"),
        // tcId = 55, edge case public key
        dhTest(
            "fffffffffffffffffffffffffffffffffffffffffffffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "2c7cd8e41330954cecdc9caf7e079a6f09e4b40637dd6e40252d771f965484a7fc208e13fdc492025cabe98aa55336a7dba36ac3ae4d838f",
            "887492e4557c0b6ecab34ecc6bdf0608febe33fb05b2aa4ab8d89ec6b476515c90a66e1cfd3cde5b3240ef8fbe0bb53cfa6b2532d0c94caf"),
        // tcId = 74, non-canonical public key
        dhTest(
            "03000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "fca784f039798be596afeedaec5b3868f0c8298927721fb82ad04546b7e4c4f42fa1fc3fc7d12f43f5a2e8a96362fcc71a34b44b559e0b96",
            "a729e6ece3db18b7e9423be4e7fae18caa291e61ce84b608569ab461b270724fd92f3e2b8086fe067673ca7ac05357ee701d69e4056d5b4b"),
        // tcId = 75, non-canonical public key
        dhTest(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "742b8c0b0ab0104a9ef9634c0aad023f35e41fb953717121ce4c2aebc1a128e7c0431cd1347a6241685f7174a8512d417ebaaa46ee780a8a",
            "d92b02d7bb9952f4ca826b2b51f1a3d4de1fd4459f0d019853f3a960d54f3354d8e40fb28d1be65637bb7dba0571ff83797b7106c7497459"),
        // tcId = 89, edge case for shared secret
        dhTest(
            "b91a0c5ad497d95f15df62e4231edaaaab21d82953fcde09eab164209745aab6fe9d353a0da328fa8147939e63ad56d1c0d2c0bddd95da50",
            "70ef97865bee47cf00de84606408e2701ad8bf6ed311039764a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a976bf",
            "0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 503, private key == -1 (mod order)
        dhTest(
            "a71742c472d8eee636a974dd98f554ad2f89911f80abdb3d8fa03bbb981917b19d925581bcce7193c8839f6b2e0ff6c1da7c202970b3da46",
            "be58b958ddcc5bb1a9ccdbc43ccc1fa7d0102f6a70488ad590b3f26ffdffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            "caba0271ea05eabf9d92314311cedf54df44739623a60004dd62d5ccac1f4302644b2f0b75e35b11a1831a87548238b9c36e71e5f7c57d10"),
        // tcId = 507, special case private key
        dhTest(
            "a667c6ac3de44c8d89c8f82025dab50470fa2da4efa153fb03adb167cef143cdffb825e927e0badfd720f28c1033f3e9d86de7158f00718c",
            "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffa9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "b2ba5057f1f1183b1970b7844537784670da55c5e3207de1d0f76427b2663811426107941022d9bf85a373a7840eb017cf8fa23e53067a7d"),
        // tcId = 508, special case private key
        dhTest(
            "f8de0d52427ddc57d9fe1d9bf9f3704d7d43a2633307374a8b05bb6e422a7085a8dbee3ccc28ad328ea3c8cea637ad3c2913ae4ffc1f7638",
            "00000000000000000000000000000000000000000000000000000000565555555555555555555555555555555555555555555555555555d5",
            "5666a72276a9c4f3849f62888d8590e0aee115e9a231b1ca743ee7a02af7377e4030521091d173941c9a701753eca4d5823fbd86747dc0fa"),
    ]

    let tests448smallOrder: [dhTest] = [
        // tcId = 32, public key = 0
        dhTest(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "04f04638d565bea83ac37703510d647568dbac58218813748a227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd4de",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 33, public key = 1
        dhTest(
            "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "281f41a8a853441f1d5014bc6c616e564fce4372ac2216814f232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e4818cf",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 63, public key with low order
        dhTest(
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ac23f2c29dd7910ebdb47efc5ccb345dc9392bb5def5018dc8cb410635f56e63ab92bcdac4177c6bd3450b098493b68bb54ea47b769334c4",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 64, public key with low order
        dhTest(
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "c05bd19c61d1c2c0e79414345cfb9c138eed88054fac8f74b2c4b5e1e817aaad629d159903bef40c10c85a8b90b8433c7f35248d72bea2d1",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        // tcId = 131, special case public key
        dhTest(
            "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "582bf63ee54d47ae5517cf74fdfed1d4bcd544c95e61c8c95605ea323a4d1820fdc40fafb1a5cbe4f4ce1f89a99f99a3361961e5b30bd896",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    ]

    func test448() throws {
        let kem = KEMStructure(.X448)
        for test in tests448 {
            let priv = try PrivateKey(kem: .X448, bytes: test.privKey)
            let pub = try PublicKey(kem: .X448, bytes: test.pubKey)
            XCTAssertEqual(try kem.DH(priv, pub), test.shared)
        }
    }

    func test448smallOrder() throws {
        let kem = KEMStructure(.X448)
        for test in tests448smallOrder {
            let priv = try PrivateKey(kem: .X448, bytes: test.privKey)
            do {
                let pub = try PublicKey(kem: .X448, bytes: test.pubKey)
                let _ = try kem.DH(priv, pub)
                XCTFail("Expected smallOrder exception")
            } catch HPKEException.smallOrder {
            } catch {
                XCTFail("Expected smallOrder exception")
            }
        }
    }

}
