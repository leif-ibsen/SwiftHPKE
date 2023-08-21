//
//  KeysTest.swift
//  
//
//  Created by Leif Ibsen on 13/08/2023.
//

import XCTest
@testable import SwiftHPKE
import BigInt

final class KeysTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func doTestDER(_ kem: KEM) throws {
        let suite = CipherSuite(kem: kem, kdf: .KDF256, aead: .AESGCM128)
        let (pubKey, privKey) = try suite.makeKeyPair()
        let pubKeyDER = try PublicKey(der: pubKey.der)
        let privKeyDER = try PrivateKey(der: privKey.der)
        XCTAssertEqual(pubKey, pubKeyDER)
        XCTAssertEqual(privKey, privKeyDER)
    }

    func doTestPEM(_ kem: KEM) throws {
        let suite = CipherSuite(kem: kem, kdf: .KDF256, aead: .AESGCM128)
        let (pubKey, privKey) = try suite.makeKeyPair()
        let pubKeyPEM = try PublicKey(pem: pubKey.pem)
        let privKeyPEM = try PrivateKey(pem: privKey.pem)
        XCTAssertEqual(pubKey, pubKeyPEM)
        XCTAssertEqual(privKey, privKeyPEM)
    }

    func testDER() throws {
        try doTestDER(.P256)
        try doTestDER(.P384)
        try doTestDER(.P521)
        try doTestDER(.X25519)
        try doTestDER(.X448)
    }
    
    func testPEM() throws {
        try doTestPEM(.P256)
        try doTestPEM(.P384)
        try doTestPEM(.P521)
        try doTestPEM(.X25519)
        try doTestPEM(.X448)
    }
    
    func testPriv() throws {
        do {
            let _ = try PrivateKey(kem: .P256, bytes: CurveP256.order.asMagnitudeBytes())
            XCTFail("Expected privateKeyParameter exception")
        } catch HPKEException.privateKeyParameter {
        } catch {
            XCTFail("Expected privateKeyParameter exception")
        }
        do {
            let _ = try PrivateKey(kem: .P384, bytes: CurveP384.order.asMagnitudeBytes())
            XCTFail("Expected privateKeyParameter exception")
        } catch HPKEException.privateKeyParameter {
        } catch {
            XCTFail("Expected privateKeyParameter exception")
        }
        do {
            let _ = try PrivateKey(kem: .P521, bytes: CurveP521.order.asMagnitudeBytes())
            XCTFail("Expected privateKeyParameter exception")
        } catch HPKEException.privateKeyParameter {
        } catch {
            XCTFail("Expected privateKeyParameter exception")
        }
        let priv256 = try PrivateKey(kem: .P256, bytes: (CurveP256.order + 1).asMagnitudeBytes())
        XCTAssertEqual(priv256.s!, BInt.ONE)
        let priv384 = try PrivateKey(kem: .P384, bytes: (CurveP384.order + 1).asMagnitudeBytes())
        XCTAssertEqual(priv384.s!, BInt.ONE)
        let priv521 = try PrivateKey(kem: .P521, bytes: (CurveP521.order + 1).asMagnitudeBytes())
        XCTAssertEqual(priv521.s!, BInt.ONE)
    }

    func testPub() throws {

        // Curve point = Generator point
        do {
            let _ = try PublicKey(kem: .P256, bytes: CurveP256().encodePoint(Point(CurveP256.gx, CurveP256.gy), false))
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try PublicKey(kem: .P384, bytes: CurveP384().encodePoint(Point(CurveP384.gx, CurveP384.gy), false))
        } catch {
            XCTFail("Did not expect exception")
        }
        do {
            let _ = try PublicKey(kem: .P521, bytes: CurveP521().encodePoint(Point(CurveP521.gx, CurveP521.gy), false))
        } catch {
            XCTFail("Did not expect exception")
        }

        // Curve point = INFINITY
        do {
            let _ = try PublicKey(kem: .P256, bytes: CurveP256().encodePoint(Point.INFINITY, false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
        do {
            let _ = try PublicKey(kem: .P384, bytes: CurveP384().encodePoint(Point.INFINITY, false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
        do {
            let _ = try PublicKey(kem: .P521, bytes: CurveP521().encodePoint(Point.INFINITY, false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }

        // Curve point = (0, 0)
        do {
            let _ = try PublicKey(kem: .P256, bytes: CurveP256().encodePoint(Point(BInt.ZERO, BInt.ZERO), false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
        do {
            let _ = try PublicKey(kem: .P384, bytes: CurveP384().encodePoint(Point(BInt.ZERO, BInt.ZERO), false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
        do {
            let _ = try PublicKey(kem: .P521, bytes: CurveP521().encodePoint(Point(BInt.ZERO, BInt.ZERO), false))
            XCTFail("Expected publicKeyParameter exception")
        } catch HPKEException.publicKeyParameter {
        } catch {
            XCTFail("Expected publicKeyParameter exception")
        }
    }
}
