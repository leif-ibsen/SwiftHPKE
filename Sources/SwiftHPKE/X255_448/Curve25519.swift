//
//  Curve25519.swift
//  SwiftX25519Test
//
//  Created by Leif Ibsen on 25/12/2022.
//

import ASN1

class Curve25519 {
    
    static let OID = ASN1ObjectIdentifier("1.3.101.110")!

    static let _9: Bytes = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    // RFC 7748 page 9
    func X25519(_ k: Bytes, _ u: Bytes) throws -> Bytes {
        assert(k.count == 32 && u.count == 32)
        let a24 = Field25519(121665, 0, 0, 0, 0)
        var k1 = k
        k1[0] &= 0xf8
        k1[31] &= 0x7f
        k1[31] |= 0x40
        var u1 = u
        u1[31] &= 0x7f
        let x1 = Field25519(u1)
        var x2 = Field25519.fe1
        var x3 = x1
        var z2 = Field25519.fe0
        var z3 = Field25519.fe1
        var swap = false
        for t in (0 ..< 255).reversed() {
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
            z2 = E.mul(AA.add(a24.mul(E)))
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

    func cswap(_ swap: Bool, _ x: inout Field25519, _ y: inout Field25519) {
        let X = x
        let Y = y
        if swap {
            x = Y
            y = X
        } else {
            x = X
            y = Y
        }
    }

}
