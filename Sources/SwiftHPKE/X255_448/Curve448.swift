//
//  Curve448.swift
//  SwiftX25519Test
//
//  Created by Leif Ibsen on 08/01/2023.
//

import ASN1

struct Curve448 {
    
    static let keySize = 56
    
    static let OID = ASN1ObjectIdentifier("1.3.101.111")!

    static let _5: Bytes = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    // RFC 7748 page 9
    static func X448(_ k: Bytes, _ u: Bytes) throws -> Bytes {
        assert(k.count == keySize && u.count == keySize)
        var k1 = k
        k1[0] &= 0xfc
        k1[55] |= 0x80
        let x1 = Field448(u)
        var x2 = Field448.fe1
        var x3 = x1
        var z2 = Field448.fe0
        var z3 = Field448.fe1
        var swap = false
        for t in (0 ..< 448).reversed() {
            let k_t = ((k1[t >> 3] >> (t & 0x7)) & 1) == 1
            swap = swap != k_t
            cswap(swap, &x2, &x3)
            cswap(swap, &z2, &z3)
            swap = k_t
            let A = x2.add(z2)
            let AA = A.square()
            let B = x2.sub(z2)
            let BB = B.square()
            let E = AA.sub(BB)
            let C = x3.add(z3)
            let D = x3.sub(z3)
            let DA = D.mul(A)
            let CB = C.mul(B)
            x3 = (DA.add(CB)).square()
            z3 = x1.mul((DA.sub(CB)).square())
            x2 = AA.mul(BB)
            z2 = E.mul(AA.add(E.mul(39081)))
        }
        cswap(swap, &x2, &x3)
        cswap(swap, &z2, &z3)
        z2 = z2.invert()
        x2 = x2.mul(z2)
        let x2bytes = x2.bytes
        var zz = Byte(0)
        for i in 0 ..< x2bytes.count {
            zz |= x2bytes[i]
        }
        guard zz != 0 else {
            throw HPKEException.smallOrder
        }
        return x2bytes
    }

    static func cswap(_ swap: Bool, _ x: inout Field448, _ y: inout Field448) {
        let X = swap ? y : x
        let Y = swap ? x : y
        x = X
        y = Y
    }

}
