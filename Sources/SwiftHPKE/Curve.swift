//
//  DomainP.swift
//  AEC
//
//  Created by Leif Ibsen on 01/10/2019.
//

import ASN1
import BigInt

class CurveP256: Curve {
    
    static let name = "secp256r1"
    static let p = BInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", radix: 16)!
    static let a = BInt("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", radix: 16)!
    static let b = BInt("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", radix: 16)!
    static let gx = BInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", radix: 16)!
    static let gy = BInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", radix: 16)!
    static let order = BInt("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", radix: 16)!
    static let cofactor = 1
    static let oid = ASN1ObjectIdentifier("1.2.840.10045.3.1.7")!

    init() {
        super.init(CurveP256.name, CurveP256.p, CurveP256.a, CurveP256.b, CurveP256.gx, CurveP256.gy, CurveP256.order, CurveP256.cofactor, CurveP256.oid)
    }
}

class CurveP384: Curve {
    
    static let name = "secp384r1"
    static let p = BInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", radix: 16)!
    static let a = BInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", radix: 16)!
    static let b = BInt("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", radix: 16)!
    static let gx = BInt("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", radix: 16)!
    static let gy = BInt("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", radix: 16)!
    static let order = BInt("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", radix: 16)!
    static let cofactor = 1
    static let oid = ASN1ObjectIdentifier("1.3.132.0.34")!

    init() {
        super.init(CurveP384.name, CurveP384.p, CurveP384.a, CurveP384.b, CurveP384.gx, CurveP384.gy, CurveP384.order, CurveP384.cofactor, CurveP384.oid)
    }
}

class CurveP521: Curve {
    
    static let name = "secp521r1"
    static let p = BInt("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", radix: 16)!
    static let a = BInt("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", radix: 16)!
    static let b = BInt("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", radix: 16)!
    static let gx = BInt("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", radix: 16)!
    static let gy = BInt("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", radix: 16)!
    static let order = BInt("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", radix: 16)!
    static let cofactor = 1
    static let oid = ASN1ObjectIdentifier("1.3.132.0.35")!

    init() {
        super.init(CurveP521.name, CurveP521.p, CurveP521.a, CurveP521.b, CurveP521.gx, CurveP521.gy, CurveP521.order, CurveP521.cofactor, CurveP521.oid)
    }
}

class Curve {

    static let p256 = CurveP256()
    static let p384 = CurveP384()
    static let p521 = CurveP521()

    static let OID_P = ASN1ObjectIdentifier("1.2.840.10045.1.1")!
    static let OID_EC = ASN1ObjectIdentifier("1.2.840.10045.2.1")!

    // Generator point multiplication window width
    static let WW = 4
    static let WWMASK = Limb(0xf)
    static let WWEXP = 16 // 2 ** WW

    let name: String
    let oid: ASN1ObjectIdentifier?
    let p: BInt
    let a: BInt
    let b: BInt
    let g: Point
    let order: BInt
    let cofactor: Int

    // Stuff related to Barrett reduction modulo p

    let u: BInt
    let shifts: Int

    // Stuff related to Montgomery inversion
    
    let Rsize: Int
    let Rsize64: Int
    var modulus: Vector
    var mprime = Vector.ZERO
    
    // Precomputed multiples of the generator point

    var gpts: [Point] = []

    init(_ name: String, _ p: BInt, _ a: BInt, _ b: BInt, _ gx: BInt, _ gy: BInt, _ order: BInt, _ cofactor: Int, _ oid: ASN1ObjectIdentifier? = nil) {
        self.name = name
        self.oid = oid
        self.p = p
        self.a = a
        self.b = b
        self.g = Point(gx, gy)
        self.order = order
        self.cofactor = cofactor
        self.shifts = self.p.magnitude.count * 128
        self.u = (BInt.ONE << self.shifts) / self.p
        self.modulus = Vector(self.p)
        self.Rsize = self.modulus.count
        self.Rsize64 = self.Rsize * 64

        // R = 1 << Rsize64
        // [WARREN] - Compute Rinv and mprime such that R * Rinv - modulus * mprime = 1

        var Bmprime = BInt.ZERO
        var BRinv = BInt.ONE
        for _ in 0 ..< Rsize64 {
            if BRinv.isEven {
                BRinv >>= 1
                Bmprime >>= 1
            } else {
                BRinv += self.p
                BRinv >>= 1
                Bmprime >>= 1
                Bmprime.setBit(Rsize64 - 1)
            }
        }
        self.mprime = Vector(Bmprime)

        // Precompute multiples of the generator point to speed-up generator point multiplication

        self.gpts = computeGWpts(self.g)
    }

    func computeGWpts(_ w: Point) -> [Point] {
        let d = (self.order.bitWidth + Curve.WW - 1) / Curve.WW
        var wpts = [Point](repeating: Point.INFINITY, count: d)
        wpts[0] = w
        for i in 1 ..< d {
            wpts[i] = wpts[i - 1]
            for _ in 0 ..< Curve.WW {
                wpts[i] = double(wpts[i])
            }
        }
        return wpts
    }

    // [CRANDALL] - algorithm 7.2.2
    func double(_ pt: Point) -> Point {
        if pt.infinity || pt.y.isZero {
            return Point.INFINITY
        }
        let m = mulModP(addModP(mul3ModP(squareModP(pt.x)), self.a), inverse(mul2ModP(pt.y)))
        let x3 = subModP(squareModP(m), mul2ModP(pt.x))
        return Point(x3, subModP(mulModP(m, subModP(pt.x, x3)), pt.y))
    }

    func add(_ pt1: Point, _ pt2: Point) -> Point {
        if pt1.infinity {
            return pt2
        }
        if pt2.infinity {
            return pt1
        }
        var m: BInt
        if pt1.x == pt2.x {
            if addModP(pt1.y, pt2.y).isZero {
                return Point.INFINITY
            }
            m = mulModP(addModP(mul3ModP(squareModP(pt1.x)), self.a), inverse(mul2ModP(pt1.y)))
        } else {
            m = mulModP(subModP(pt2.y, pt1.y), inverse(subModP(pt2.x, pt1.x)))
        }
        let x3 = subModP(squareModP(m), addModP(pt1.x, pt2.x))
        return Point(x3, subModP(mulModP(m, subModP(pt1.x, x3)), pt1.y))
    }
    
    func subtract(_ pt1: Point, _ pt2: Point) -> Point {
        return add(pt1, negate(pt2))
    }

    func negate(_ pt: Point) -> Point {
        return pt.infinity ? Point.INFINITY : Point(pt.x, self.p - pt.y)
    }

    // [CRANDALL] - algorithm 7.2.4
    func multiply(_ pt: Point, _ n: BInt) -> Point {
        assert(0 <= n && n < self.order)
        if n.isZero {
            return Point.INFINITY
        }
        if n.isOne {
            return pt
        }
        var q = pt
        let npt = negate(pt)
        let m = n * 3
        for i in (1 ... m.bitWidth - 2).reversed() {
            q = double(q)
            let mi = m.testBit(i)
            let ni = n.testBit(i)
            if mi && !ni {
                q = add(q, pt)
            } else if !mi && ni {
                q = add(q, npt)
            }
        }
        return q
    }

/*
    // Montgomery ladder algorithm, about 40% slower than the above algorithm but runs in constant time
    func multiply(_ pt: Point, _ n: BInt) -> Point {
        assert(0 <= n && n < self.order)
        var p0 = Point.INFINITY
        var p1 = pt
        for i in (0 ..< n.bitWidth).reversed() {
            if n.testBit(i) {
                p0 = add(p0, p1)
                p1 = double(p1)
            } else {
                p1 = add(p0, p1)
                p0 = double(p0)
            }
        }
        return p0
    }
*/
    // Multiply the generator point by n
    func multiplyG(_ n: BInt) -> Point {
        return multiplyGW(n, &self.gpts)
    }

    // Multiply a public key w by n
    func multiplyW(_ n: BInt, _ wpts: inout [Point]) -> Point {
        return multiplyGW(n, &wpts)
    }
    
    // [GUIDE] - algorithm 3.41
    func multiplyGW(_ n: BInt, _ gwpts: inout [Point]) -> Point {
        var a = Point.INFINITY
        var b = Point.INFINITY
        for j in (1 ..< Curve.WWEXP).reversed() {
            var mx = 0
            var mi = 0
            for i in 0 ..< gwpts.count {
                if (n.magnitude[mx] >> mi) & Curve.WWMASK == j {
                    b = add(b, gwpts[i])
                }
                mi += Curve.WW
                if mi == 64 {
                    mi = 0
                    mx += 1
                    if mx == n.magnitude.count {
                        break
                    }
                }
            }
            a = add(a, b)
        }
        return a
    }

    // y^2 = x^3 + ax + b
    func contains(_ pt: Point) -> Bool {
        if pt.infinity {
            return true
        }
        let x3 = addModP(mulModP(squareModP(pt.x), pt.x), addModP(mulModP(pt.x, self.a), self.b))
        let y2 = squareModP(pt.y)
        return x3 == y2
    }
    
    func asn1(_ explicit: Bool) -> ASN1 {
        if explicit || self.oid == nil {
            return ASN1Sequence()
                .add(ASN1Integer(BInt.ONE))
            .   add(ASN1Sequence()
                    .add(Curve.OID_P)
                    .add(ASN1Integer(self.p)))
                .add(ASN1Sequence()
                    .add(ASN1OctetString(self.a.asMagnitudeBytes()))
                    .add(ASN1OctetString(self.b.asMagnitudeBytes())))
                .add(ASN1OctetString(encodePoint(self.g, false)))
                .add(ASN1Integer(self.order))
                .add(ASN1Integer(BInt(self.cofactor)))
        }
        return self.oid!
    }
    
    // Barrett reduction algorithm from Project Nayuki - https://www.nayuki.io/page/barrett-reduction-algorithm
    // Requires 0 <= x and x < self.p ** 2, which is the case for all invocations
    func reduceModP(_ x: BInt) -> BInt {
        assert(0 <= x && x < self.p ** 2)
        // precondition(0 <= x && x < self.p ** 2)
        let t = x - ((x * self.u) >> self.shifts) * self.p
        return t < self.p ? t : t - self.p
    }

    func addModP(_ x: BInt, _ y: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        assert(0 <= y && y < self.p)
        // precondition(0 <= x && x < self.p)
        // precondition(0 <= y && y < self.p)
        let t = x + y
        return t < self.p ? t : t - self.p
    }
    
    func subModP(_ x: BInt, _ y: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        assert(0 <= y && y < self.p)
        // precondition(0 <= x && x < self.p)
        // precondition(0 <= y && y < self.p)
        let t = x - y
        return t.isNegative ? t + self.p : t
    }
    
    func mulModP(_ x: BInt, _ y: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        assert(0 <= y && y < self.p)
        // precondition(0 <= x && x < self.p)
        // precondition(0 <= y && y < self.p)
        return self.reduceModP(x * y)
    }

    func mul2ModP(_ x: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        // precondition(0 <= x && x < self.p)
        let t = x << 1
        return t < self.p ? t : t - self.p
    }
    
    func mul3ModP(_ x: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        // precondition(0 <= x && x < self.p)
        return self.reduceModP(x << 1 + x)
    }

    func squareModP(_ x: BInt) -> BInt {
        assert(0 <= x && x < self.p)
        // precondition(0 <= x && x < self.p)
        return self.reduceModP(x * x)
    }

    // [SEC 1] section 2.3.3
    func encodePoint(_ pt: Point, _ compress: Bool) -> Bytes {
        var b: Bytes
        if pt.infinity {
            b = [0]
        } else {
            let l = (self.p.bitWidth + 7) / 8
            let bx = pt.x.asMagnitudeBytes()
            if compress {
                b = Bytes(repeating: 0, count: l + 1)
                b[0] = pt.y.isEven ? 2 : 3
                var x = 1 + l - bx.count
                for i in 0 ..< bx.count {
                    b[x] = bx[i]
                    x += 1
                }
            } else {
                let by = pt.y.asMagnitudeBytes()
                b = Bytes(repeating: 0, count: 2 * l + 1)
                b[0] = 4
                var x = 1 + l - bx.count
                for i in 0 ..< bx.count {
                    b[x] = bx[i]
                    x += 1
                }
                x += l - by.count
                for i in 0 ..< by.count {
                    b[x] = by[i]
                    x += 1
                }
            }
        }
        return b
    }

    // [SEC 1] section 2.3.4
    func decodePoint(_ bytes: Bytes) throws -> Point {
        var pt: Point
        let l = bytes.count
        let bw = (self.p.bitWidth + 7) / 8
        if l == 1 {
            if bytes[0] == 0 {
                pt = Point.INFINITY
            } else {
                throw HPKEException.decodePoint
            }
        } else if l == bw + 1 {

            // Compressed format
            
            let x = BInt(magnitude: Bytes(bytes[1 ..< l]))
            let x3 = addModP(mulModP(squareModP(x), x), addModP(mulModP(x, self.a), self.b))
            if let y = x3.sqrtMod(self.p) {
                if bytes[0] == 2 {
                    pt = Point(x, y.isEven ? y : self.p - y)
                } else if bytes[0] == 3 {
                    pt = Point(x, y.isOdd ? y : self.p - y)
                } else {
                    throw HPKEException.decodePoint
                }
            } else {
                throw HPKEException.decodePoint
            }
        } else if l == 2 * bw + 1 {
            
            // Uncompressed format
            
            if bytes[0] != 4 {
                throw HPKEException.decodePoint
            }
            let x = BInt(magnitude: Bytes(bytes[1 ... l / 2]))
            let y = BInt(magnitude: Bytes(bytes[l / 2 + 1 ..< l]))
            pt = Point(x, y)
        } else {
            throw HPKEException.decodePoint
        }
        return pt
    }
    
    // [GUIDE] - algorithm 2.23
    func inverse(_ x: BInt) -> BInt {
        var vp = Vector(self.p)
        var u = Vector(x)
        var v = vp
        var x1 = Vector.ONE
        var x2 = Vector.ZERO
        var k = 0
        while v.isPositive {
            if v.isEven {
                v.shift1Right()
                x1.shift1Left()
            } else if u.isEven {
                u.shift1Right()
                x2.shift1Left()
            } else if v.compare(&u) >= 0 {
                v.subtract(&u)
                v.shift1Right()
                x2.add(&x1)
                x1.shift1Left()
            } else {
                u.subtract(&v)
                u.shift1Right()
                x1.add(&x2)
                x2.shift1Left()
            }
            k += 1
        }
        precondition(u.isOne, "'inverse' inconsistency")
        if x1.compare(&vp) > 0 {
            x1.subtract(&vp)
        }

        // [Savacs] - at this point x1 = the almost Montgomery inverse

        if k > self.Rsize64 {
            reduce(&x1)
            k -= self.Rsize64
        }
        x1.shiftLeft(self.Rsize64 - k)
        reduce(&x1)
        return BInt(x1.v)
    }
    
    // [WARREN]
    func reduce(_ t: inout Vector) {
        var u = t

        // u = u mod R
        while u.count > self.Rsize {
            u.v.removeLast()
        }

        u.multiply(&self.mprime)

        // u = u mod R
        while u.count > self.Rsize {
            u.v.removeLast()
        }

        u.multiply(&self.modulus)
        u.add(&t)
        
        // u = u / R
        if u.count > self.Rsize {
            for _ in 0 ..< self.Rsize {
                u.v.removeFirst()
            }
        } else {
            u = Vector.ZERO
        }

        if u.compare(&self.modulus) >= 0 {
            u.subtract(&self.modulus)
        }
        t = u
    }
    
    func align(_ b: Bytes) -> Bytes {
        var bb = b
        while bb.count < (self.p.bitWidth + 7) / 8 {
            bb.insert(0, at: 0)
        }
        return bb
    }

}

// Helper structure to speed up the 'inverse' function

struct Vector {
    
    static let ZERO = Vector(BInt.ZERO)
    static let ONE = Vector(BInt.ONE)

    var v: Limbs
    var count: Int {return self.v.count}
    
    var isEven: Bool {
        return self.v[0] & 1 == 0
    }

    var isPositive: Bool {
        return self.count > 1 || self.v[0] > 0
    }

    var isOne: Bool {
        return self.count == 1 && self.v[0] == 1
    }

    init(_ x: BInt) {
        self.v = x.magnitude
    }
    
    mutating func normalize() {
        let sc = self.count
        if sc == 0 {
            self.v.append(0)
        } else if sc > 1 {
            var i = sc - 1
            while self.v[i] == 0 && i > 0 {
                i -= 1
            }
            self.v.removeSubrange(i + 1 ..< sc)
        }
    }

    mutating func ensureSize(_ size: Int) {
        self.v.reserveCapacity(size)
        while self.count < size {
            self.v.append(0)
        }
    }

    mutating func add(_ x: inout Vector) {
        self.ensureSize(x.count)
        var carry = false
        for i in 0 ..< x.count {
            if carry {
                self.v[i] = self.v[i] &+ 1
                if self.v[i] == 0 {
                    self.v[i] = x.v[i]
                    // carry still lives
                } else {
                    (self.v[i], carry) = self.v[i].addingReportingOverflow(x.v[i])
                }
            } else {
                (self.v[i], carry) = self.v[i].addingReportingOverflow(x.v[i])
            }
        }
        var i = x.count
        while carry && i < self.count {
            self.v[i] = self.v[i] &+ 1
            carry = self.v[i] == 0
            i += 1
        }
        if carry {
            self.v.append(1)
        }
    }

    mutating func subtract(_ x: inout Vector) {
        var borrow = false
        for i in 0 ..< x.count {
            if borrow {
                if self.v[i] == 0 {
                    self.v[i] = 0xffffffffffffffff - x.v[i]
                    // borrow still lives
                } else {
                    self.v[i] -= 1
                    (self.v[i], borrow) = self.v[i].subtractingReportingOverflow(x.v[i])
                }
            } else {
                (self.v[i], borrow) = self.v[i].subtractingReportingOverflow(x.v[i])
            }
        }
        var i = x.count
        while borrow && i < self.count {
            self.v[i] = self.v[i] &- 1
            borrow = self.v[i] == 0xffffffffffffffff
            i += 1
        }
        self.normalize()
    }
    
    mutating func multiply(_ x: inout Vector) {
        let m = self.count
        let n = x.count
        var w = Limbs(repeating: 0, count: m + n)
        var carry: Limb
        var ovfl1, ovfl2: Bool
        for i in 0 ..< m {
            carry = 0
            for j in 0 ..< n {
                let ij = i + j
                let (hi, lo) = self.v[i].multipliedFullWidth(by: x.v[j])
                (w[ij], ovfl1) = w[ij].addingReportingOverflow(lo)
                (w[ij], ovfl2) = w[ij].addingReportingOverflow(carry)
                carry = hi &+ ((ovfl1 ? 1 : 0) + (ovfl2 ? 1 : 0))
            }
            w[i + n] = carry
        }
        self.v = w
        self.normalize()
    }

    mutating func shiftLeft(_ shifts: Int) {
        let limbShifts = shifts >> 6
        let bitShifts = shifts & 0x3f
        var b = self.v[0] >> (64 - bitShifts)
        if bitShifts > 0 {
            self.v[0] <<= bitShifts
            for i in 1 ..< self.count {
                let b1 = self.v[i] >> (64 - bitShifts)
                self.v[i] <<= bitShifts
                self.v[i] |= b
                b = b1
            }
        }
        if b != 0 {
            self.v.append(b)
        }
        for _ in 0 ..< limbShifts {
            self.v.insert(0, at: 0)
        }
    }

    mutating func shift1Left() {
        var b = self.v[0] & 0x8000000000000000 != 0
        self.v[0] <<= 1
        for i in 1 ..< self.count {
            let b1 = self.v[i] & 0x8000000000000000 != 0
            self.v[i] <<= 1
            if b {
                self.v[i] |= 1
            }
            b = b1
        }
        if b {
            self.v.append(1)
        }
    }

    mutating func shift1Right() {
        for i in 0 ..< self.count {
            if i > 0 && self.v[i] & 1 == 1 {
                self.v[i - 1] |= 0x8000000000000000
            }
            self.v[i] >>= 1
        }
        self.normalize()
    }
    
    func compare(_ x: inout Vector) -> Int {
        let scount = self.count
        let xcount = x.count
        if scount < xcount {
            return -1
        } else if scount > xcount {
            return 1
        }
        var i = xcount - 1
        while i >= 0 {
            if self.v[i] < x.v[i] {
                return -1
            } else if self.v[i] > x.v[i] {
                return 1
            }
            i -= 1
        }
        return 0
    }

}
