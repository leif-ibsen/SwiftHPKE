//
//  PrivateKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import ASN1
import BigInt
import Digest

public struct PrivateKey: CustomStringConvertible, Equatable {
    
    let kem: KEM
    let s: BInt?

    // MARK: Initializers

    /// Creates a PrivateKey from its type and key bytes
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if `bytes` has wrong size for the key type
    public init(kem: KEM, bytes: Bytes) throws {
        self.kem = kem
        switch self.kem {
        case .P256:
            self.s = BInt(magnitude: bytes).mod(CurveP256.order)
            guard self.s! > BInt.ZERO else {
                throw HPKEException.privateKeyParameter
            }
            self.bytes = PrivateKey.int2bytes(self.s!, CurveP256.privateKeySize)
            self.publicKey = try PublicKey(kem: .P256, bytes: Curve.p256.encodePoint(Curve.p256.multiplyG(self.s!), false))
        case .P384:
            self.s = BInt(magnitude: bytes).mod(CurveP384.order)
            guard self.s! > BInt.ZERO else {
                throw HPKEException.privateKeyParameter
            }
            self.bytes = PrivateKey.int2bytes(self.s!, CurveP384.privateKeySize)
            self.publicKey = try PublicKey(kem: .P384, bytes: Curve.p384.encodePoint(Curve.p384.multiplyG(self.s!), false))
        case .P521:
            self.s = BInt(magnitude: bytes).mod(CurveP521.order)
            guard self.s! > BInt.ZERO else {
                throw HPKEException.privateKeyParameter
            }
            self.bytes = PrivateKey.int2bytes(self.s!, CurveP521.privateKeySize)
            self.publicKey = try PublicKey(kem: .P521, bytes: Curve.p521.encodePoint(Curve.p521.multiplyG(self.s!), false))
        case .X25519:
            guard bytes.count == Curve25519.keySize else {
                throw HPKEException.privateKeyParameter
            }
            var x = bytes
            x[0] &= 0xf8
            x[31] &= 0x7f
            x[31] |= 0x40
            self.bytes = x
            self.s = nil
            self.publicKey = try PublicKey(kem: .X25519, bytes: Curve25519.X25519(self.bytes, Curve25519._9))
        case .X448:
            guard bytes.count == Curve448.keySize else {
                throw HPKEException.privateKeyParameter
            }
            var x = bytes
            x[0] &= 0xfc
            x[55] |= 0x80
            self.bytes = x
            self.s = nil
            self.publicKey = try PublicKey(kem: .X448, bytes: Curve448.X448(self.bytes, Curve448._5))
        }
    }

    /// Creates a PrivateKey from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    /// - Throws: An exception if the DER encoding is wrong
    public init(der: Bytes) throws {
        guard let seq = try ASN1.build(der) as? ASN1Sequence else {
            throw HPKEException.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw HPKEException.asn1Structure
        }
        guard let seq0 = seq.get(0) as? ASN1Integer else {
            throw HPKEException.asn1Structure
        }
        if seq0 != ASN1.ZERO {
            throw HPKEException.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw HPKEException.asn1Structure
        }
        guard let seq2 = seq.get(2) as? ASN1OctetString else {
            throw HPKEException.asn1Structure
        }
        var OID: ASN1ObjectIdentifier
        if seq1.getValue().count == 1 {
            guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
                throw HPKEException.asn1Structure
            }
            OID = oid
        } else if seq1.getValue().count == 2 {
            guard let oid = seq1.get(1) as? ASN1ObjectIdentifier else {
                throw HPKEException.asn1Structure
            }
            OID = oid
        } else {
            throw HPKEException.asn1Structure
        }
        var kem: KEM
        if OID == CurveP256.oid {
            kem = .P256
        } else if OID == CurveP384.oid {
            kem = .P384
        } else if OID == CurveP521.oid {
            kem = .P521
        } else if OID == Curve25519.OID {
            kem = .X25519
        } else if OID == Curve448.OID {
            kem = .X448
        } else {
            throw HPKEException.asn1Structure
        }
        if kem == .P256 || kem == .P384 || kem == .P521 {
            guard let asn1 = try ASN1.build(seq2.value) as? ASN1Sequence else {
                throw HPKEException.asn1Structure
            }
            if asn1.getValue().count < 2 {
                throw HPKEException.asn1Structure
            }
            guard let os = asn1.get(1) as? ASN1OctetString else {
                throw HPKEException.asn1Structure
            }
            try self.init(kem: kem, bytes: os.value)
        } else {
            guard let seq3 = try ASN1.build(seq2.value) as? ASN1OctetString else {
                throw HPKEException.asn1Structure
            }
            try self.init(kem: kem, bytes: seq3.value)
        }
    }
    
    /// Creates a PrivateKey from its PEM encoding.
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PRIVATE KEY") else {
            throw HPKEException.pemStructure
        }
        try self.init(der: der)
    }


    // MARK: Stored Properties
    
    /// The serialized key bytes
    public let bytes: Bytes
    /// The corresponding public key
    public let publicKey: PublicKey
    
    
    // MARK: Computed Properties
    
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do {
        switch self.kem {
        case .P256:
            return ASN1Sequence()
                .add(ASN1.ZERO)
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP256.oid))
                .add(ASN1OctetString(
                    ASN1Sequence()
                        .add(ASN1.ONE)
                        .add(ASN1OctetString(Curve.p256.align(self.s!.asMagnitudeBytes())))
                        .add(ASN1Ctx(0, [CurveP256.oid]))
                        .add(ASN1Ctx(1, [bytes2bits(Curve.p256.encodePoint(Curve.p256.multiplyG(self.s!), false))]))
                        .encode()))
        case .P384:
            return ASN1Sequence()
                .add(ASN1.ZERO)
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP384.oid))
                .add(ASN1OctetString(
                    ASN1Sequence()
                        .add(ASN1.ONE)
                        .add(ASN1OctetString(Curve.p384.align(self.s!.asMagnitudeBytes())))
                        .add(ASN1Ctx(0, [CurveP384.oid]))
                        .add(ASN1Ctx(1, [bytes2bits(Curve.p384.encodePoint(Curve.p384.multiplyG(self.s!), false))]))
                        .encode()))
        case .P521:
            return ASN1Sequence()
                .add(ASN1.ZERO)
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP521.oid))
                .add(ASN1OctetString(
                    ASN1Sequence()
                        .add(ASN1.ONE)
                        .add(ASN1OctetString(Curve.p521.align(self.s!.asMagnitudeBytes())))
                        .add(ASN1Ctx(0, [CurveP521.oid]))
                        .add(ASN1Ctx(1, [bytes2bits(Curve.p521.encodePoint(Curve.p521.multiplyG(self.s!), false))]))
                        .encode()))
        case .X25519:
            return ASN1Sequence()
                .add(ASN1.ZERO)
                .add(ASN1Sequence().add(Curve25519.OID))
                .add(ASN1OctetString(ASN1OctetString(self.bytes).encode()))
        case .X448:
            return ASN1Sequence()
                .add(ASN1.ZERO)
                .add(ASN1Sequence().add(Curve448.OID))
                .add(ASN1OctetString(ASN1OctetString(self.bytes).encode()))
        }
    } } }
    /// The DER encoding of `self`
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM base 64 encoding of `self`
    public var pem: String { get { return Base64.pemEncode(self.der, "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }


    //  MARK: Instance Methods

    /// Equality of two private keys
    ///
    /// - Parameters:
    ///   - key1: a private key
    ///   - key2: a private key
    /// - Returns: `true` if key1 and key2 are equal, `false` otherwise
    public static func == (key1: PrivateKey, key2: PrivateKey) -> Bool {
        return key1.kem == key2.kem && key1.bytes == key2.bytes
    }


    static func int2bytes(_ x: BInt, _ n: Int) -> Bytes {
        var bytes = x.asMagnitudeBytes()
        while bytes.count < n {
            bytes.insert(0, at: 0)
        }
        return bytes
    }

    func bytes2bits(_ bytes: Bytes) -> ASN1BitString {
        do {
            return try ASN1BitString(bytes, 0)
        } catch {
            fatalError("ASN1BitString inconsistency")
        }
    }

}
