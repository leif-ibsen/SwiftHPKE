//
//  Exception.swift
//  SwiftECC
//
//  Created by Leif Ibsen on 18/02/2020.
//

/// The HPKE exceptions
public enum HPKEException: Error, CustomStringConvertible {
    
    /// Textual description of `self`
    public var description: String {
        switch self {
        case .asn1Structure:
            return "ASN1 structure is wrong"
        case .pemStructure:
            return "PEM structure is wrong"
        case .decodePoint:
            return "Decode point error"
        case .smallOrder:
            return "X25519, X448 small order error"
        case .pskError:
            return "Inconsistent PSK parameters"
        case .privateKeyParameter:
            return "Invalid parameter to PrivateKey constructor"
        case .publicKeyParameter:
            return "Invalid parameter to PublicKey constructor"
        case .keyMismatch:
            return "CipherSuite key mismatch"
        case .derivedKeyError:
            return "Derived key error"
        case .exportOnlyError:
            return "Export only error"
        case .exportSize:
            return "Export size is negative or too large"
        }
    }
        
    /// ASN1 structure is wrong
    case asn1Structure

    /// PEM structure is wrong
    case pemStructure

    /// Decode point error
    case decodePoint
    
    /// Derived key error
    case derivedKeyError

    /// Export only error
    case exportOnlyError

    /// Export size is negative or too large
    case exportSize

    /// CipherSuite key mismatch
    case keyMismatch

    /// Invalid parameter to PrivateKey constructor
    case privateKeyParameter

    /// Inconsistent PSK parameters
    case pskError

    /// Invalid parameter to PublicKey constructor
    case publicKeyParameter

    /// X25519, X448 small order error
    case smallOrder

}
