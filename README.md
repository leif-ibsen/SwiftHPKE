<h2><b>SwiftHPKE</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#basic">Basics</a></li>
<li><a href="#basic1">Creating Public and Private Keys</a></li>
<li><a href="#basic2">Loading Existing Keys</a></li>
<li><a href="#basic6">Encryption and Decryption</a></li>
<li><a href="#basic7">Secret Export</a></li>
<li><a href="#basic8">CryptoKit Compatibility</a></li>
<li><a href="#basic9">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
</ul>
SwiftHPKE implements the Hybrid Public Key Encryption standard as defined in RFC 9180.
<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftHPKE", from: "1.6.0"),
	  ]
SwiftHPKE requires Swift 5.0. It also requires that the Int and UInt types be 64 bit types.
SwiftHPKE uses Apple's CryptoKit framework. Therefore, for macOS the version must be at least 10.15,
for iOS the version must be at least 13, and for watchOS the version must be at least 8.

<h2 id="basic"><b>Basics</b></h2>
The basic concepts in SwiftHPKE are CipherSuite, Sender and Recipient, represented by the
*CipherSuite* structure and the *Sender* and *Recipient* classes.

A CipherSuite combines a *Key Encapsulation Mechanism* (KEM), a *Key Derivation Function* (KDF)
and a *Authenticated Encryption with Associated Data* (AEAD) algorithm.

There are 5 different KEM's, 3 different KDF's and 4 different AEAD's giving 60 CipherSuite combinations.

A *Sender* is based on a specific *CipherSuite* and a *Sender* instance can encrypt (seal) a sequence of plaintexts
in one of four different modes:
<ul>
<li>Base mode</li>
<li>Preshared key mode</li>
<li>Authenticated mode</li>
<li>Authenticated, preshared key mode</li>
</ul>
A *Recipient* is also based on a specific *CipherSuite* and a *Recipient* instance can decrypt (open)
a sequence of ciphertexts in the four modes shown above.

A *CipherSuite* instance can encrypt (seal) a single plaintext message and decrypt (open) a single
ciphertext message without the need for a *Sender* instance and a *Recipient* instance.
<h2 id="basic1"><b>Creating Public and Private Keys</b></h2>
Given a *CipherSuite* instance it is possible to generate new public- and private keys.
<h3><b>Example</b></h3>

    import SwiftHPKE

    let suite = CipherSuite(kem: .X25519, kdf: .KDF256, aead: .CHACHAPOLY)
    let (pubKey, privKey) = try suite.makeKeyPair()

    // See the key ASN1 structures

    print(pubKey)
    print(privKey)

giving (for example):

    Sequence (2):
      Sequence (1):
        Object Identifier: 1.3.101.110
      Bit String (256): 11100111 11100111 00010111 11110101 10101000 10010101 01001010 00100010 00011010 10001001 11001011 11010001 11101101 10000101 01110101 11011111 11010110 00001101 01001110 10100100 00111011 00110100 01110000 01011000 00111111 01011011 10001010 11111010 01101000 10010011 10100001 00001101

    Sequence (3):
      Integer: 0
      Sequence (1):
        Object Identifier: 1.3.101.110
      Octet String (34): 04 20 b0 e5 94 7d f8 72 04 8f 90 79 5f d5 b7 e4 6e ca 56 18 58 30 2e 4e 79 83 d6 46 bb 42 70 2a 34 68

<h2 id="basic2"><b>Loading Existing Keys</b></h2>
It is possible to load existing keys from their PEM encodings or DER encodings.
<h3><b>Example</b></h3>

    import SwiftHPKE

    // Public key encoding - curve P384
    let pubKeyPem =
    """
    -----BEGIN PUBLIC KEY-----
    MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQW/MahMwMTFjwY95uOEdfBVC7HrQhTGG
    TwxiPlgDiARqC6y6EQ1Ajkuhe4A02WOltRYQRXKytzspOR25UfgtagURAwxVFYzR
    9cmi6FRmvvq/Tsigd/dAi4FNjniR7/Pg
    -----END PUBLIC KEY-----
    """
    let pubKey = try PublicKey(pem: pubKeyPem)
    
    // Private key encoding - curve P384
    let privKeyPem =
    """
    -----BEGIN PRIVATE KEY-----
    MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDBmpNziSYmGoWwl7apJ
    M9ZdDBxkJqmxMScHGXG45ZQXSv7fIuJlsSwxK76nUiiO7gigBwYFK4EEACKhZANi
    AARBb8xqEzAxMWPBj3m44R18FULsetCFMYZPDGI+WAOIBGoLrLoRDUCOS6F7gDTZ
    Y6W1FhBFcrK3Oyk5HblR+C1qBREDDFUVjNH1yaLoVGa++r9OyKB390CLgU2OeJHv
    8+A=
    -----END PRIVATE KEY-----
    """
    let privKey = try PrivateKey(pem: privKeyPem)
    
    // See the key ASN1 structures
    
    print(pubKey)
    print(privKey)

giving:

    Sequence (2):
      Sequence (2):
        Object Identifier: 1.2.840.10045.2.1
        Object Identifier: 1.3.132.0.34
      Bit String (776): 00000100 01000001 01101111 11001100 01101010 00010011 00110000 00110001 00110001 01100011 11000001 10001111 01111001 10111000 11100001 00011101 01111100 00010101 01000010 11101100 01111010 11010000 10000101 00110001 10000110 01001111 00001100 01100010 00111110 01011000 00000011 10001000 00000100 01101010 00001011 10101100 10111010 00010001 00001101 01000000 10001110 01001011 10100001 01111011 10000000 00110100 11011001 01100011 10100101 10110101 00010110 00010000 01000101 01110010 10110010 10110111 00111011 00101001 00111001 00011101 10111001 01010001 11111000 00101101 01101010 00000101 00010001 00000011 00001100 01010101 00010101 10001100 11010001 11110101 11001001 10100010 11101000 01010100 01100110 10111110 11111010 10111111 01001110 11001000 10100000 01110111 11110111 01000000 10001011 10000001 01001101 10001110 01111000 10010001 11101111 11110011 11100000

    Sequence (3):
      Integer: 0
      Sequence (2):
        Object Identifier: 1.2.840.10045.2.1
        Object Identifier: 1.3.132.0.34
      Octet String (167): 30 81 a4 02 01 01 04 30 66 a4 dc e2 49 89 86 a1 6c 25 ed aa 49 33 d6 5d 0c 1c 64 26 a9 b1 31 27 07 19 71 b8 e5 94 17 4a fe df 22 e2 65 b1 2c 31 2b be a7 52 28 8e ee 08 a0 07 06 05 2b 81 04 00 22 a1 64 03 62 00 04 41 6f cc 6a 13 30 31 31 63 c1 8f 79 b8 e1 1d 7c 15 42 ec 7a d0 85 31 86 4f 0c 62 3e 58 03 88 04 6a 0b ac ba 11 0d 40 8e 4b a1 7b 80 34 d9 63 a5 b5 16 10 45 72 b2 b7 3b 29 39 1d b9 51 f8 2d 6a 05 11 03 0c 55 15 8c d1 f5 c9 a2 e8 54 66 be fa bf 4e c8 a0 77 f7 40 8b 81 4d 8e 78 91 ef f3 e0

<h2 id="basic6"><b>Encryption and Decryption</b></h2>
A *CipherSuite* instance can encrypt (seal) a single plaintext message and decrypt (open) a single ciphertext message.

<h3><b>Example</b></h3>

    // Encryption and decryption of a single message in base mode
    
    import SwiftHPKE

    // The CipherSuite to use
    let theSuite = CipherSuite(kem: .X448, kdf: .KDF512, aead: .AESGCM256)

    // The recipient keys
    let (recipientPub, recipientPriv) = try theSuite.makeKeyPair()

    let plainText = Bytes("Hi, there".utf8)
    let (encapsulatedKey, cipherText) = try theSuite.seal(publicKey: recipientPub, info: [1, 2, 3], pt: plainText, aad: [4, 5, 6])
    let decrypted = try theSuite.open(privateKey: recipientPriv, info: [1, 2, 3], ct: cipherText, aad: [4, 5, 6], encap: encapsulatedKey)
    print(String(bytes: decrypted, encoding: .utf8)!)

giving:

    Hi, there

Using a *Sender* instance and a *Recipient* instance it is possible to encrypt a sequence of plaintext messages
and decrypt a sequence of ciphertext messages.
<h3><b>Example</b></h3>

    // Encryption and decryption of several messages in authenticated mode
    
    import SwiftHPKE
    
    // The CipherSuite to use
    let theSuite = CipherSuite(kem: .P384, kdf: .KDF384, aead: .CHACHAPOLY)

    let plainText1 = Bytes("Hi, there 1".utf8)
    let plainText2 = Bytes("Hi, there 2".utf8)
    let plainText3 = Bytes("Hi, there 3".utf8)
    
    // The Sender and Recipient keys
    let (senderPub, senderPriv) = try theSuite.makeKeyPair()
    let (recipientPub, recipientPriv) = try theSuite.makeKeyPair()
    
    // Create the Sender instance
    let sender = try Sender(suite: theSuite, publicKey: recipientPub, info: [1, 2, 3], authentication: senderPriv)
    
    let cipherText1 = try sender.seal(pt: plainText1, aad: [4, 5])
    let cipherText2 = try sender.seal(pt: plainText2, aad: [6, 7])
    let cipherText3 = try sender.seal(pt: plainText3, aad: [8, 9])

    // Create the Recipient instance
    let recipient = try Recipient(suite: theSuite, privateKey: recipientPriv, info: [1, 2, 3], authentication: senderPub, encap: sender.encapsulatedKey)
    
    let decrypted1 = try recipient.open(ct: cipherText1, aad: [4, 5])
    let decrypted2 = try recipient.open(ct: cipherText2, aad: [6, 7])
    let decrypted3 = try recipient.open(ct: cipherText3, aad: [8, 9])
    
    print(String(bytes: decrypted1, encoding: .utf8)!)
    print(String(bytes: decrypted2, encoding: .utf8)!)
    print(String(bytes: decrypted3, encoding: .utf8)!)

giving:

    Hi, there 1
    Hi, there 2
    Hi, there 3

<h2 id="basic7"><b>Secret Export</b></h2>
Given the recipients public key, a sender can generate a secret that only the recipient can know.
<h3><b>Example 1</b></h3>

    import SwiftHPKE

    // The aead need not be .EXPORTONLY, any aead will work

    let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .EXPORTONLY)
    let (recipientPubKey, recipientPrivKey) = try theSuite.makeKeyPair()

    // Generate the secret

    let (encapsulated, secret) = try theSuite.sendExport(publicKey: recipientPubKey, info: [], context: [1, 2, 3], L: 10)
    print("Generated secret:", secret)

    // The recipient retrieves the secret by means of the encapsulated key

    let retrievedSecret = try theSuite.receiveExport(privateKey: recipientPrivKey, info: [], context: [1, 2, 3], L: 10, encap: encapsulated)
    print("Retrieved secret:", retrievedSecret)

giving (for example):

    Generated secret: [172, 169, 119, 121, 167, 53, 213, 12, 0, 29]
    Retrieved secret: [172, 169, 119, 121, 167, 53, 213, 12, 0, 29]

<h3><b>Example 2</b></h3>

    import SwiftHPKE

    // The aead need not be .EXPORTONLY, any aead will work

    let theSuite = CipherSuite(kem: .P256, kdf: .KDF256, aead: .EXPORTONLY)
    let (recipientPubKey, recipientPrivKey) = try theSuite.makeKeyPair()
    let sender = try Sender(suite: theSuite, publicKey: recipientPubKey, info: [])

    // Generate the secret

    let secret = try sender.sendExport(context: [1, 2, 3], L: 10)
    print("Generated secret:", secret)

    // The recipient retrieves the secret by means of the encapsulated key

    let receiver = try Recipient(suite: theSuite, privateKey: recipientPrivKey, info: [], encap: sender.encapsulatedKey)
    let retrievedSecret = try receiver.receiveExport(context: [1, 2, 3], L: 10)
    print("Retrieved secret:", retrievedSecret)

giving (for example):

    Generated secret: [3, 230, 139, 128, 86, 4, 81, 78, 110, 135]
    Retrieved secret: [3, 230, 139, 128, 86, 4, 81, 78, 110, 135]

The above examples use Base mode. Preshared key mode, Authenticated mode and Authenticated, preshared key mode
is also possible.
<h2 id="basic8"><b>Compatibility with Apple's CryptoKit Framework</b></h2>
The SwiftHPKE keys of type .P256, .P384, .P521 and .X25519 are equivalent to
CryptoKit keys of type P256, P384, P521 and Curve25519. Keys of type .X448 is not supported in CryptoKit.

To convert CryptoKit P256 keys (similarly for P384 and P521) - say *ckPriv* and *ckPub* to SwiftHPKE keys:

    let hpkePriv = try PrivateKey(der: Bytes(ckPriv.derRepresentation))
    let hpkePub = try PublicKey(der: Bytes(ckPub.derRepresentation))

To convert CryptoKit Curve25519 keys - say *ckPriv* and *ckPub* to SwiftHPKE keys:

    let hpkePriv = try PrivateKey(kem: .X25519, bytes: Bytes(ckPriv.rawRepresentation))
    let hpkePub = try PublicKey(kem: .X25519, bytes: Bytes(ckPub.rawRepresentation))

To convert SwiftHPKE .P256 keys (similarly for .P384 and .P521) - say *hpkePriv* and *hpkePub* to CryptoKit keys:

    let ckPriv = try CryptoKit.P256.KeyAgreement.PrivateKey(derRepresentation: hpkePriv.der)
    let ckPub = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: hpkePub.der)

To convert SwiftHPKE .X25519 keys - say *hpkePriv* and *hpkePub* to CryptoKit keys:

    let ckPriv = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hpkePriv.bytes)
    let ckPub = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: hpkePub.bytes)

<h2 id="basic9"><b>Performance</b></h2>
SwiftHPKE's encryption and decryption performance was measured on an iMac 2021, Apple M1 chip.
The time to create a *Sender* and *Recipient* instance in base mode is shown in the table below, depending on the KEM type - units are milliseconds.
<table width="90%">
<tr><th align="left" width="16%">KEM</th><th align="right" width="28%">Sender</th><th align="right" width="28%">Recipient</th></tr>
<tr><td>P256</td><td align="right">7 mSec</td><td align="right">6 mSec</td></tr>
<tr><td>P384</td><td align="right">20 mSec</td><td align="right">17 mSec</td></tr>
<tr><td>P521</td><td align="right">46 mSec</td><td align="right">39 mSec</td></tr>
<tr><td>X25519</td><td align="right">0.14 mSec</td><td align="right">0.09 mSec</td></tr>
<tr><td>X448</td><td align="right">1.1 mSec</td><td align="right">0.5 mSec</td></tr>
</table>
The encryption and decryption speed in base mode, once the *Sender* or *Recipient* instance is created, is shown in the table below, depending on the AEAD type - units are MBytes / Sec.
<table width="90%">
<tr><th align="left" width="16%">AEAD</th><th align="right" width="28%">Encryption speed</th><th align="right" width="28%">Decryption speed</th></tr>
<tr><td>AESGCM128</td><td align="right">3500 MB/Sec (0.91 cycles / byte)</td><td align="right">3340 MB/Sec (0.96 cycles / byte)</td></tr>
<tr><td>AESGCM256</td><td align="right">3640 MB/Sec (0.88 cycles / byte)</td><td align="right">3630 MB/Sec (0.88 cycles / byte)</td></tr>
<tr><td>CHACHAPOLY</td><td align="right">555 MB/Sec (5.8 cycles / byte)</td><td align="right">557 MB/Sec (5.7 cycles / byte)</td></tr>
</table>

<h2 id="dep"><b>Dependencies</b></h2>
The SwiftHPKE package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.2.0"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.14.0"),
    ],

<h2 id="ref"><b>References</b></h2>

Algorithms from the following books and papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[FIPS 180-4] - FIPS PUB 180-4 - Secure Hash Standard (SHS), August 2015</li>
<li>[GUIDE] - Hankerson, Menezes, Vanstone: Guide to Elliptic Curve Cryptography. Springer 2004</li>
<li>[RFC-9180] - Hybrid Public Key Encryption, February 2022</li>
<li>[SEC 1] - Standards for Efficient Cryptography 1 (SEC 1), Certicom Corp. 2009</li>
<li>[SEC 2] - Standards for Efficient Cryptography 2 (SEC 2), Certicom Corp. 2010</li>
<li>[WARREN] - Henry S. Warren, Jr.: Montgomery Multiplication, July 2012</li>
</ul>
