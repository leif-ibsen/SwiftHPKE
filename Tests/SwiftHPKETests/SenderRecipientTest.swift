//
//  BaseModeTest.swift
//  
//
//  Created by Leif Ibsen on 20/08/2023.
//

import XCTest
@testable import SwiftHPKE

final class SenderRecipientTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    var plainTexts: [Bytes] = [[], [], [], []]
    var theContext: Bytes = []
    var theInfo: Bytes = []
    var thePsk: Bytes = []
    var thePskId: Bytes = []
    var theAad: Bytes = []
    var length: Int = 0

    func doBaseMode(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, encap: sender.encapsulatedKey)
        var cipherTexts: [Bytes] = [Bytes](repeating: [], count: plainTexts.count)
        for i in 0 ..< plainTexts.count {
            cipherTexts[i] = try sender.seal(pt: plainTexts[i], aad: theAad)
        }
        for i in 0 ..< plainTexts.count {
            let pt = try recipient.open(ct: cipherTexts[i], aad: theAad)
            XCTAssertEqual(pt, plainTexts[i])
        }
    }

    func doBaseSecret(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, encap: sender.encapsulatedKey)
        let secret = try sender.sendExport(context: theContext, L: length)
        let secretx = try recipient.receiveExport(context: theContext, L: length)
        XCTAssertEqual(secret, secretx)
    }

    func doPskMode(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, psk: thePsk, pskId: thePskId)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)
        var cipherTexts: [Bytes] = [Bytes](repeating: [], count: plainTexts.count)
        for i in 0 ..< plainTexts.count {
            cipherTexts[i] = try sender.seal(pt: plainTexts[i], aad: theAad)
        }
        for i in 0 ..< plainTexts.count {
            let pt = try recipient.open(ct: cipherTexts[i], aad: theAad)
            XCTAssertEqual(pt, plainTexts[i])
        }
    }

    func doPskSecret(_ suite: CipherSuite, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, psk: thePsk, pskId: thePskId)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)
        let secret = try sender.sendExport(context: theContext, L: length)
        let secretx = try recipient.receiveExport(context: theContext, L: length)
        XCTAssertEqual(secret, secretx)
    }

    func doAuthMode(_ suite: CipherSuite, _ senderPub: PublicKey, _ senderPriv: PrivateKey, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, authentication: senderPriv)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, authentication: senderPub, encap: sender.encapsulatedKey)
        var cipherTexts: [Bytes] = [Bytes](repeating: [], count: plainTexts.count)
        for i in 0 ..< plainTexts.count {
            cipherTexts[i] = try sender.seal(pt: plainTexts[i], aad: theAad)
        }
        for i in 0 ..< plainTexts.count {
            let pt = try recipient.open(ct: cipherTexts[i], aad: theAad)
            XCTAssertEqual(pt, plainTexts[i])
        }
    }

    func doAuthSecret(_ suite: CipherSuite, _ senderPub: PublicKey, _ senderPriv: PrivateKey, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, authentication: senderPriv)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, authentication: senderPub, encap: sender.encapsulatedKey)
        let secret = try sender.sendExport(context: theContext, L: length)
        let secretx = try recipient.receiveExport(context: theContext, L: length)
        XCTAssertEqual(secret, secretx)
    }

    func doAuthPskMode(_ suite: CipherSuite, _ senderPub: PublicKey, _ senderPriv: PrivateKey, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, authentication: senderPriv, psk: thePsk, pskId: thePskId)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, authentication: senderPub, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)
        var cipherTexts: [Bytes] = [Bytes](repeating: [], count: plainTexts.count)
        for i in 0 ..< plainTexts.count {
            cipherTexts[i] = try sender.seal(pt: plainTexts[i], aad: theAad)
        }
        for i in 0 ..< plainTexts.count {
            let pt = try recipient.open(ct: cipherTexts[i], aad: theAad)
            XCTAssertEqual(pt, plainTexts[i])
        }
    }

    func doAuthPskSecret(_ suite: CipherSuite, _ senderPub: PublicKey, _ senderPriv: PrivateKey, _ recipientPub: PublicKey, _ recipientPriv: PrivateKey) throws {
        let sender = try Sender(suite: suite, publicKey: recipientPub, info: theInfo, authentication: senderPriv, psk: thePsk, pskId: thePskId)
        let recipient = try Recipient(suite: suite, privateKey: recipientPriv, info: theInfo, authentication: senderPub, psk: thePsk, pskId: thePskId, encap: sender.encapsulatedKey)
        let secret = try sender.sendExport(context: theContext, L: length)
        let secretx = try recipient.receiveExport(context: theContext, L: length)
        XCTAssertEqual(secret, secretx)
    }

    func doTest() throws {

        // Test all combinations of KEM, KDF and AEAD in all four modes

        for kem in KEM.allCases {
            for kdf in KDF.allCases {
                for aead in AEAD.allCases {
                    let suite = CipherSuite(kem: kem, kdf: kdf, aead: aead)
                    let (senderPub, senderPriv) = try suite.makeKeyPair()
                    let (recipientPub, recipientPriv) = try suite.makeKeyPair()
                    if aead != .EXPORTONLY {
                        try doBaseMode(suite, recipientPub, recipientPriv)
                        try doPskMode(suite, recipientPub, recipientPriv)
                        try doAuthMode(suite, senderPub, senderPriv, recipientPub, recipientPriv)
                        try doAuthPskMode(suite, senderPub, senderPriv, recipientPub, recipientPriv)
                    }
                    try doBaseSecret(suite, recipientPub, recipientPriv)
                    try doPskSecret(suite, recipientPub, recipientPriv)
                    try doAuthSecret(suite, senderPub, senderPriv, recipientPub, recipientPriv)
                    try doAuthPskSecret(suite, senderPub, senderPriv, recipientPub, recipientPriv)
                }
            }
        }
    }

    func testSenderRecipient1() throws {
        
        // Test with non-empty parameters

        plainTexts = [[], Bytes("This is plaintext 1".utf8), Bytes("This is plaintext 2".utf8), Bytes("This is plaintext 3".utf8)]
        theContext = [1, 2, 3]
        theInfo = [4, 5, 6]
        thePsk = [7, 8, 9]
        thePskId = [10, 11, 12]
        theAad = [13, 14, 15]
        length = 10

        try doTest()
    }

    func testSenderRecipient2() throws {

        // Test with empty parameters

        plainTexts = [[], [], [], []]
        theContext = []
        theInfo = []
        thePsk = []
        thePskId = []
        theAad = []
        length = 0

        try doTest()
    }

}
