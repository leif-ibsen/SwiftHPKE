//
//  Point.swift
//  AEC
//
//  Created by Leif Ibsen on 23/10/2019.
//

import BigInt

struct Point: CustomStringConvertible, Equatable {
    
    static let INFINITY = Point()
    
    private init() {
        self.x = BInt.ZERO
        self.y = BInt.ZERO
        self.infinity = true
    }
    
    init(_ x: BInt, _ y: BInt) {
        self.x = x
        self.y = y
        self.infinity = false
    }

    let x: BInt
    let y: BInt
    let infinity: Bool
    
    var description: String {
        return self.infinity ? "Point(infinity)" : "Point(\(self.x), \(self.y))"
    }
    
    static func == (p1: Point, p2: Point) -> Bool {
        return p1.x == p2.x && p1.y == p2.y && p1.infinity == p2.infinity
    }
    
}
