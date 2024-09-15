//
//  PublicKey.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 02/07/2023.
//

import ASN1
import BigInt
import Digest

public struct PublicKey: CustomStringConvertible, Equatable {
    
    let kem: KEM
    let w: Point?

    
    // MARK: Initializers
        
    /// Creates a PublicKey from its type and key bytes.
    ///
    /// For types P256, P384 and P521 the key bytes represents
    /// either a compressed curve point or an uncompressed curve point.
    ///
    /// - Parameters:
    ///   - kem: The key type
    ///   - bytes: The key bytes
    /// - Throws: An exception if `bytes` has wrong size for the key type
    public init(kem: KEM, bytes: Bytes) throws {
        self.kem = kem
        switch self.kem {
        case .P256:
            self.w = try Curve.p256.decodePoint(bytes)
            guard Curve.p256.contains(self.w!) && !self.w!.infinity else {
                throw HPKEException.publicKeyParameter
            }
            if bytes[0] == 4 {
                // uncompressed point
                self.bytes = bytes
            } else {
                // compressed point
                self.bytes = Curve.p256.encodePoint(self.w!, false)
            }
        case .P384:
            self.w = try Curve.p384.decodePoint(bytes)
            guard Curve.p384.contains(self.w!) && !self.w!.infinity else {
                throw HPKEException.publicKeyParameter
            }
            if bytes[0] == 4 {
                // uncompressed point
                self.bytes = bytes
            } else {
                // compressed point
                self.bytes = Curve.p384.encodePoint(self.w!, false)
            }
        case .P521:
            self.w = try Curve.p521.decodePoint(bytes)
            guard Curve.p521.contains(self.w!) && !self.w!.infinity else {
                throw HPKEException.publicKeyParameter
            }
            if bytes[0] == 4 {
                // uncompressed point
                self.bytes = bytes
            } else {
                // compressed point
                self.bytes = Curve.p521.encodePoint(self.w!, false)
            }
        case .X25519:
            guard bytes.count == Curve25519.keySize else {
                throw HPKEException.publicKeyParameter
            }
            self.bytes = bytes
            self.w = nil
            try checkZero()
        case .X448:
            guard bytes.count == Curve448.keySize else {
                throw HPKEException.publicKeyParameter
            }
            self.bytes = bytes
            self.w = nil
            try checkZero()
        }
    }

    /// Creates a PublicKey from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The DER encoding of the key
    /// - Throws: An exception if the DER encoding is wrong
    public init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw HPKEException.asn1Structure
        }
        guard seq.getValue().count == 2 else {
            throw HPKEException.asn1Structure
        }
        guard let seq1 = seq.get(0) as? ASN1Sequence else {
            throw HPKEException.asn1Structure
        }
        guard let bitString = seq.get(1) as? ASN1BitString else {
            throw HPKEException.asn1Structure
        }
        if seq1.getValue().count == 1 {
            // X25519 or X448
            guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
                throw HPKEException.asn1Structure
            }
            if oid == Curve25519.OID && bitString.bits.count == Curve25519.keySize {
                try self.init(kem: .X25519, bytes: bitString.bits)
            } else if oid == Curve448.OID && bitString.bits.count == Curve448.keySize {
                try self.init(kem: .X448, bytes: bitString.bits)
            } else {
                throw HPKEException.asn1Structure
            }
        } else if seq1.getValue().count == 2 {
            // P256 or P384 or P521
            guard let oid1 = seq1.get(0) as? ASN1ObjectIdentifier else {
                throw HPKEException.asn1Structure
            }
            if oid1 != Curve.OID_EC {
                throw HPKEException.asn1Structure
            }
            guard let oid2 = seq1.get(1) as? ASN1ObjectIdentifier else {
                throw HPKEException.asn1Structure
            }
            if oid2 == CurveP256.oid && bitString.bits.count == CurveP256.publicKeySize {
                try self.init(kem: .P256, bytes: bitString.bits)
            } else if oid2 == CurveP384.oid && bitString.bits.count == CurveP384.publicKeySize {
                try self.init(kem: .P384, bytes: bitString.bits)
            } else if oid2 == CurveP521.oid && bitString.bits.count == CurveP521.publicKeySize {
                try self.init(kem: .P521, bytes: bitString.bits)
            } else {
                throw HPKEException.asn1Structure
            }
        } else {
            throw HPKEException.asn1Structure
        }
    }

    /// Creates a PublicKey from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The PEM encoding of the key
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PUBLIC KEY") else {
            throw HPKEException.pemStructure
        }
        try self.init(der: der)
    }

    
    // MARK: Stored Properties
    
    /// The serialized key bytes
    public let bytes: Bytes
    
    
    // MARK: Computed Properties
    
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return self.getASN1() } } }
    /// The DER encoding of `self`
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM base 64 encoding of `self`
    public var pem: String { get { return Base64.pemEncode(self.der, "PUBLIC KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }

    
    //  MARK: Instance Methods

    /// Equality of two public keys
    ///
    /// - Parameters:
    ///   - key1: a public key
    ///   - key2: a public key
    /// - Returns: `true` if key1 and key2 are equal, `false` otherwise
    public static func == (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.kem == key2.kem && key1.bytes == key2.bytes
    }

    func getASN1() -> ASN1 {
        switch self.kem {
        case .P256:
            return ASN1Sequence()
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP256.oid))
                .add(bytes2bits(Curve.p256.encodePoint(self.w!, false)))
        case .P384:
            return ASN1Sequence()
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP384.oid))
                .add(bytes2bits(Curve.p384.encodePoint(self.w!, false)))
        case .P521:
            return ASN1Sequence()
                .add(ASN1Sequence().add(Curve.OID_EC).add(CurveP521.oid))
                .add(bytes2bits(Curve.p521.encodePoint(self.w!, false)))
        case .X25519:
            return ASN1Sequence()
                .add(ASN1Sequence().add(Curve25519.OID))
                .add(bytes2bits(self.bytes))
        case .X448:
            return ASN1Sequence()
                .add(ASN1Sequence().add(Curve448.OID))
                .add(bytes2bits(self.bytes))
        }
    }

    func checkZero() throws {
        var zz = Byte(0)
        for b in self.bytes {
            zz |= b
        }
        guard zz != 0 else {
            throw HPKEException.smallOrder
        }
    }

    func bytes2bits(_ bytes: Bytes) -> ASN1BitString {
        do {
            return try ASN1BitString(bytes, 0)
        } catch {
            fatalError("ASN1BitString inconsistency")
        }
    }

    static func bytes2hex(_ b: Bytes, _ n: Int) -> String {
        let x = BInt(magnitude: b)
        var s = x.asString(radix: 16)
        while s.count < n {
            s.insert("0", at: s.startIndex)
        }
        return s
    }
    
}
