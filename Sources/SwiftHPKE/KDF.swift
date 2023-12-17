//
//  KDF.swift
//  SwiftHPKETest
//
//  Created by Leif Ibsen on 20/06/2023.
//

import Digest

///
/// Key Derivation Functions
///
public enum KDF: CustomStringConvertible, CaseIterable {
    
    /// Textual description of *self*
    public var description: String {
        switch self {
        case .KDF256:
            return "HKDF-SHA256"
        case .KDF384:
            return "HKDF-SHA384"
        case .KDF512:
            return "HKDF-SHA512"
        }
    }

    /// HKDF-SHA256
    case KDF256
    /// HKDF-SHA384
    case KDF384
    /// HKDF-SHA512
    case KDF512
}

struct KDFStructure {

    let kind: MessageDigest.Kind
    let dl: Int
    let suite_id: Bytes
    
    init(_ kdf: KDF, _ suite_id: Bytes) {
        switch kdf {
        case .KDF256:
            self.kind = .SHA2_256
        case .KDF384:
            self.kind = .SHA2_384
        case .KDF512:
            self.kind = .SHA2_512
        }
        self.dl = MessageDigest(self.kind).digestLength
        self.suite_id = suite_id
    }

    func extract(_ salt: Bytes, _ ikm: Bytes) -> Bytes {
        return HMAC(self.kind, salt.count > 0 ? salt : Bytes(repeating: 0, count: self.dl)).compute(ikm)
    }
    
    func expand(_ prk: Bytes, _ info: Bytes, _ L: Int) -> Bytes {
        assert(0 <= L && L <= self.dl * 255)
        let hMac = HMAC(self.kind, prk)
        let (q, r) = L.quotientAndRemainder(dividingBy: self.dl)
        let n = r == 0 ? q : q + 1
        var t: Bytes = []
        var T: Bytes = []
        var x = Byte(0)
        for _ in 0 ..< n {
            x += 1
            t = hMac.compute(t + info + [x])
            hMac.reset()
            T += t
        }
        return Bytes(T[0 ..< L])
    }
    
    func labeledExtract(_ salt: Bytes, _ label: Bytes, _ ikm: Bytes) -> Bytes {
        let labeled_ikm: Bytes = "HPKE-v1".utf8 + self.suite_id + label + ikm
        return extract(salt, labeled_ikm)
    }

    func labeledExpand(_ prk: Bytes, _ label: Bytes, _ info: Bytes, _ L: Int) -> Bytes {
        let labeled_info: Bytes = [Byte((L >> 8) & 0xff), Byte(L & 0xff)] + "HPKE-v1".utf8 + self.suite_id + label + info
        return expand(prk, labeled_info, L)
    }

 }
