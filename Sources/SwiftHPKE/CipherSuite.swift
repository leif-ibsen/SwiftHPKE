//
//  HPKE.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 19/06/2023.
//

typealias Limb = UInt64
typealias Limbs = [UInt64]

/// Unsigned 8 bit value
public typealias Byte = UInt8
/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

/// A CipherSuite instance combines a *Key Encapsulation Mechanism* (KEM), a *Key Derivation Function* (KDF)
/// and a *AEAD Encryption Algorithm* (AEAD).
/// It can encrypt or decrypt a single message in one of four modes:
///
/// * Base mode
/// * Preshared key mode
/// * Authenticated mode
/// * Authenticated, preshared key mode
///
public struct CipherSuite: CustomStringConvertible {

    let kemStructure: KEMStructure
    let kdfStructure: KDFStructure
    let aeadStructure: AEADStructure
    let suite_id: Bytes
    let Nk: Int
    let Nn: Int
    let Nh: Int


    // MARK: Initializers
    
    /// Creates a CipherSuite instance
    ///
    /// - Parameters:
    ///   - kem: The key encapsulation mechanism
    ///   - kdf: The key derivation function
    ///   - aead: The AEAD encryption algorithm
    public init(kem: KEM, kdf: KDF, aead: AEAD) {
        var id = Bytes("HPKE".utf8)
        self.kem = kem
        self.kdf = kdf
        self.aead = aead
        switch self.kem {
        case .P256:
            id += [0x00, 0x10]
        case .P384:
            id += [0x00, 0x11]
        case .P521:
            id += [0x00, 0x12]
        case .X25519:
            id += [0x00, 0x20]
        case .X448:
            id += [0x00, 0x21]
        }
        switch self.kdf {
        case .KDF256:
            id += [0x00, 0x01]
            self.Nh = 32
        case .KDF384:
            id += [0x00, 0x02]
            self.Nh = 48
        case .KDF512:
            id += [0x00, 0x03]
            self.Nh = 64
        }
        switch self.aead {
        case .AESGCM128:
            id += [0x00, 0x01]
            self.Nk = 16
        case .AESGCM256:
            id += [0x00, 0x02]
            self.Nk = 32
        case .CHACHAPOLY:
            id += [0x00, 0x03]
            self.Nk = 32
        case .EXPORTONLY:
            id += [0xff, 0xff]
            self.Nk = 0
        }
        self.Nn = 12
        self.suite_id = id
        self.kemStructure = KEMStructure(kem)
        self.kdfStructure = KDFStructure(kdf, self.suite_id)
        self.aeadStructure = AEADStructure(aead)
    }
    

    // MARK: Stored Properties
    
    /// The key encapsulation mechanism
    public let kem: KEM
    /// The key derivation function
    public let kdf: KDF
    /// The AEAD encryption algorithm
    public let aead: AEAD


    // MARK: Computed properties

    /// A textual representation of *self*
    public var description: String { get { return "(KEM:" + self.kem.description + " KDF:" + self.kdf.description + " AEAD:" + self.aead.description + ")"} }


    // MARK: Instance Methods
    
    /// Derives a public- and private HPKE key pair for *self* based on keying material
    ///
    /// - Parameters:
    ///   - ikm: The keying material
    /// - Returns: The public key and private key pair
    /// - Throws: A *derivedKeyError* exception in extremely rare cases
    public func deriveKeyPair(ikm: Bytes) throws -> (PublicKey, PrivateKey) {
        return try self.kemStructure.deriveKeyPair(ikm)
    }

    /// Generates a public- and private HPKE key pair for *self*
    ///
    /// - Returns: The public key and private key pair
    /// - Throws: A *derivedKeyError* exception in extremely rare cases
    public func makeKeyPair() throws -> (PublicKey, PrivateKey) {
        var ikm = Bytes(repeating: 0, count: self.kemStructure.Nsk)
        KEMStructure.randomBytes(&ikm)
        return try self.deriveKeyPair(ikm: ikm)
    }


    // MARK: Instance Methods - base mode

    /// Single-shot encryption in base mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulated key and cipher text
    /// - Throws: An exception if *publicKey* does not match *self* or the encryption fails or *self.aead* is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption in base mode
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or *self.aead* is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Generate an export secret in base mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if *publicKey* does not match *self* or L is negative or too large

    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = try self.kemStructure.encap(publicKey, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Retrieve an export secret in base mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try self.kemStructure.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - preshared key mode

    /// Single-shot encryption in preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if *publicKey* does not match *self* or the encryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, psk: Bytes, pskId: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, psk: psk, pskId: pskId)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption in preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey:The recipient private key
    ///   - info: The additional information
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, psk: Bytes, pskId: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, psk: psk, pskId: pskId, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Generate an export secret in preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if *publicKey* does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        let (sharedSecret, encap) = try self.kemStructure.encap(publicKey, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Retrieve an export secret in preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, psk: Bytes, pskId: Bytes, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        let sharedSecret = try self.kemStructure.decap(encap, privateKey)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - authenticated mode

    /// Single-shot encryption in authenticated mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if one of the keys does not match *self* or the encryption fails or *self.aead* is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, authentication: PrivateKey, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, authentication: authentication)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption in authenticated mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or *self.aead* is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, authentication: PublicKey, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, authentication: authentication, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Generate an export secret in authenticated mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender private key
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int, authentication: PrivateKey) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        try self.checkPrivKey(authentication)
        let (sharedSecret, encap) = try self.kemStructure.authEncap(publicKey, authentication, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Retrieve an export secret in authenticated mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, authentication: PublicKey, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        try self.checkPubKey(authentication)
        let sharedSecret = try self.kemStructure.authDecap(encap, privateKey, authentication)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, [], [])
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }


    // MARK: Instance Methods - authenticated, preshared key mode

    /// Single-shot encryption in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - authentication: The sender private key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - pt: The plain text to encrypt
    ///   - aad: The associated data
    /// - Returns: The encapsulted key and cipher text
    /// - Throws: An exception if one of the keys does not match *self* or the encryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func seal(publicKey: PublicKey, info: Bytes, authentication: PrivateKey, psk: Bytes, pskId: Bytes, pt: Bytes, aad: Bytes) throws -> (encap: Bytes, ct: Bytes) {
        let sender = try Sender(suite: self, publicKey: publicKey, info: info, authentication: authentication, psk: psk, pskId: pskId)
        return (sender.encapsulatedKey, try sender.seal(pt: pt, aad: aad))
    }

    /// Single-shot decryption in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - ct: The cipher text to decrypt
    ///   - aad: The associated data
    ///   - encap: The encapsulated key
    /// - Returns: The plain text
    /// - Throws: An exception if one of the keys does not match *self* or the decryption fails or the *psk* parameters are inconsistent or *self.aead* is EXPORTONLY
    public func open(privateKey: PrivateKey, info: Bytes, authentication: PublicKey, psk: Bytes, pskId: Bytes, ct: Bytes, aad: Bytes, encap: Bytes) throws -> Bytes {
        let recipient = try Recipient(suite: self, privateKey: privateKey, info: info, authentication: authentication, psk: psk, pskId: pskId, encap: encap)
        return try recipient.open(ct: ct, aad: aad)
    }

    /// Generate an export secret in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - publicKey: The recipient public key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender private key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    /// - Returns: The encapsulated key and export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func sendExport(publicKey: PublicKey, info: Bytes, context: Bytes, L: Int, authentication: PrivateKey, psk: Bytes, pskId: Bytes) throws -> (encapsulatedKey: Bytes, secret: Bytes) {
        try self.checkExportSize(L)
        try self.checkPubKey(publicKey)
        try self.checkPrivKey(authentication)
        let (sharedSecret, encap) = try self.kemStructure.authEncap(publicKey, authentication, [])
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return (encap, self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L))
    }

    /// Retrieve an export secret in authenticated, preshared key mode
    ///
    /// - Parameters:
    ///   - privateKey: The recipient private key
    ///   - info: The additional information
    ///   - context: The export context
    ///   - L: The length of the export secret
    ///   - authentication: The sender public key
    ///   - psk: The preshared key
    ///   - pskId: The preshared key id
    ///   - encap: The encapsulated key
    /// - Returns: The export secret
    /// - Throws: An exception if one of the keys does not match *self* or the *psk* parameters are inconsistent or L is negative or too large
    public func receiveExport(privateKey: PrivateKey, info: Bytes, context: Bytes, L: Int, authentication: PublicKey, psk: Bytes, pskId: Bytes, encap: Bytes) throws -> Bytes {
        try self.checkExportSize(L)
        try self.checkPrivKey(privateKey)
        try self.checkPubKey(authentication)
        let sharedSecret = try self.kemStructure.authDecap(encap, privateKey, authentication)
        let (_, _, exporter_secret) = self.keySchedule(HPKE.BASE, sharedSecret, info, psk, pskId)
        return self.kdfStructure.labeledExpand(exporter_secret, Bytes("sec".utf8), context, L)
    }

    func keySchedule(_ mode: Byte, _ sharedSecret: Bytes, _ info: Bytes, _ psk: Bytes, _ pskId: Bytes) -> (key: Bytes, base_nonce: Bytes, exporter_secret: Bytes) {
        let psk_id_hash = self.kdfStructure.labeledExtract([], Bytes("psk_id_hash".utf8), pskId)
        let info_hash = self.kdfStructure.labeledExtract([], Bytes("info_hash".utf8), info)
        let key_schedule_context = [mode] + psk_id_hash + info_hash
        let secret = self.kdfStructure.labeledExtract(sharedSecret, Bytes("secret".utf8), psk)
        let key = self.aead == .EXPORTONLY ? [] : self.kdfStructure.labeledExpand(secret, Bytes("key".utf8), key_schedule_context, self.Nk)
        let base_nonce = self.aead == .EXPORTONLY ? [] : self.kdfStructure.labeledExpand(secret, Bytes("base_nonce".utf8), key_schedule_context, self.Nn)
        let exporter_secret = self.kdfStructure.labeledExpand(secret, Bytes("exp".utf8), key_schedule_context, self.Nh)
        return (key, base_nonce, exporter_secret)
    }
    
    func checkExportSize(_ L: Int) throws {
        if L < 0 || L > 255 * self.Nh {
            throw HPKEException.exportSize
        }
    }

    func checkPubKey(_ key: PublicKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }

    func checkPrivKey(_ key: PrivateKey) throws {
        if self.kem != key.kem {
            throw HPKEException.keyMismatch
        }
    }

    static func checkPsk(_ psk: Bytes, _ pskId: Bytes) -> Bool {
        return (psk.count == 0 && pskId.count == 0) || (psk.count > 0 && pskId.count > 0)
    }

}

struct HPKE {
    static let BASE = Byte(0x00)
    static let PSK = Byte(0x01)
    static let AUTH = Byte(0x02)
    static let AUTH_PSK = Byte(0x03)
}
