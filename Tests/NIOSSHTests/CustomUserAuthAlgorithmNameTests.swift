//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import NIOCore
import NIOFoundationCompat
@testable import NIOSSH
import XCTest

// MARK: - Fixtures

private enum CustomUserAuthTestError: Error {
    case malformedBlob
}

private let userAuthTestKeyMaterial = Data("a-user-key-that-is-not-a-key".utf8)

/// A stand-in for a real signature: XOR the payload with a fixed pad. Reversible, so the public key
/// can check it without any cryptography being involved, and deterministic, so the bytes a request
/// serialises to are a fixture.
private func xorWithUserAuthTestKey(_ data: Data) -> Data {
    var data = data
    let padSize = userAuthTestKeyMaterial.count
    for index in 0 ..< data.count {
        data[index] ^= userAuthTestKeyMaterial[index % padSize]
    }
    return data
}

/// A user key type whose user auth algorithm name differs from its key blob type, the way RFC 8332
/// separates `rsa-sha2-512` from `ssh-rsa`.
///
/// It deliberately does NOT declare `hostKeyAlgorithmNames`: the user auth split has to work on its
/// own, without a type also claiming a separate key exchange name.
struct RenamedUserAuthPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "blob-x"
    static let userAuthAlgorithmName = "alg-x"

    var rawRepresentation: Data {
        userAuthTestKeyMaterial
    }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        signature.rawRepresentation == xorWithUserAuthTestKey(Data(data))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RenamedUserAuthPublicKey {
        guard var body = buffer.readSSHString(), body.readData(length: body.readableBytes) != nil else {
            throw CustomUserAuthTestError.malformedBlob
        }
        return RenamedUserAuthPublicKey()
    }
}

struct RenamedUserAuthSignature: NIOSSHSignatureProtocol {
    // RFC 8332 types the signature blob with the algorithm name, not with the key blob type.
    static let signaturePrefix = "alg-x"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RenamedUserAuthSignature {
        guard var body = buffer.readSSHString(), let data = body.readData(length: body.readableBytes) else {
            throw CustomUserAuthTestError.malformedBlob
        }
        return RenamedUserAuthSignature(rawRepresentation: data)
    }
}

/// A user key type that does not declare a separate user auth algorithm name, i.e. every custom type
/// written against NIOSSH before this member existed.
struct PlainUserAuthPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "plain-user-prefix"

    var rawRepresentation: Data {
        userAuthTestKeyMaterial
    }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        signature.rawRepresentation == xorWithUserAuthTestKey(Data(data))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> PlainUserAuthPublicKey {
        guard var body = buffer.readSSHString(), body.readData(length: body.readableBytes) != nil else {
            throw CustomUserAuthTestError.malformedBlob
        }
        return PlainUserAuthPublicKey()
    }
}

struct PlainUserAuthSignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "plain-user-prefix"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> PlainUserAuthSignature {
        guard var body = buffer.readSSHString(), let data = body.readData(length: body.readableBytes) else {
            throw CustomUserAuthTestError.malformedBlob
        }
        return PlainUserAuthSignature(rawRepresentation: data)
    }
}

// MARK: - Deterministic keys

/// Fixed key material, so that every byte a request serialises to is reproducible across runs and can
/// be compared against a recorded fixture.
private enum DeterministicKeys {
    static var ed25519: NIOSSHPublicKey {
        let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x07, count: 32))
        return NIOSSHPrivateKey(ed25519Key: key).publicKey
    }

    static var p256: NIOSSHPublicKey {
        let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x07, count: 32))
        return NIOSSHPrivateKey(p256Key: key).publicKey
    }

    static var p384: NIOSSHPublicKey {
        let key = try! P384.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x07, count: 48))
        return NIOSSHPrivateKey(p384Key: key).publicKey
    }

    static var p521: NIOSSHPublicKey {
        // A leading zero byte keeps the scalar below the P521 group order.
        let key = try! P521.Signing.PrivateKey(rawRepresentation: Data([0x00]) + Data(repeating: 0x07, count: 65))
        return NIOSSHPrivateKey(p521Key: key).publicKey
    }

    /// A certified ed25519 user key, loaded from a fixed OpenSSH certificate.
    static let certifiedEd25519OpenSSH = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDxk/nOhhVDtrweRRR1trNm3T3RdPinf7bYLTPnfWAPuAAAAIJfkNV4OS33ImTXvorZr72q4v5XhVEQKfvqsxOEJ/XaRAAAAAAAAAAAAAAABAAAAEFVzZXIgZWQyNTUxOSBrZXkAAAAAAAAAAF7X1scAAAAAvJH7AwAAACEAAAANZm9yY2UtY29tbWFuZAAAAAwAAAAIdW5hbWUgLWEAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAACIAAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHYlMSXacXt13oBLpMXEP0OSMw5okd5c7G3hoim1MR/THUOyOS2AVQKEqLZs+td3Y6yYCrq5TGWDNGY2dfKFX99nLqJCq2kxR//CP3UherkZnn6u4eW4biLL7xODqNOzkQAAAIMAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAGgAAAAwBWeqRhZqFoGRXg7WtKSbQ9rOn2WNUiaDV1XjX2aCyi/W7431Hxpxg5iGLzP5B7ZuAAAAMByxIrsZhBM9RDxS2qGV9QByw5ebAaRFLtmvJSyxgn1nwWtkPnKetYTsP1Olh4+3tQ== lukasa@MacBook-Pro.local"
}

// MARK: - Recorded fixtures

/// Bytes recorded from the fork at tag 0.3.9 (`d756a67`), BEFORE the user auth algorithm name was
/// split from the key blob prefix. Every serialisation these pin must be byte-identical afterwards:
/// the split may only change what a type that opts in writes.
private enum RecordedAt039 {
    static let ed25519Request = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579000000000b7373682d65643235353139000000330000000b7373682d6564323535313900000020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    static let p256Request = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579000000001365636473612d736861322d6e69737470323536000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"
    static let p384Request = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579000000001365636473612d736861322d6e69737470333834000000880000001365636473612d736861322d6e69737470333834000000086e697374703338340000006104b01bfc4a2d7fe2095e6627cc5caf9abd153d5b551fe7f6da615da9d1bfd101e8d191e85902c0a34eaa3a16e666880b73059f658c4d6a6e57c0959de80109b0fa6b56bd63d1d5701a93d15322f2267a15526641c60cd07c912a6df58aa993d89b"
    static let p521Request = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579000000001365636473612d736861322d6e69737470353231000000ac0000001365636473612d736861322d6e69737470353231000000086e69737470353231000000850400e885ae400c9674eeca8cf31f686419a33138db4aae8a20067d62c94d600bb2a48d989aa95f9615d4e5bacdc044e179803072f8f133e115d25e96c556e469bd8ad3000e07af1f79c99b5ac75a49f120cd7e8cc995d00929df0d37d943d81b55a306d6c8c0eedf8732041f03d073625aef81f59ec165a6a8f6a86db7d2aa72536d3c9bb7"
    static let plainCustomRequest = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b65790000000011706c61696e2d757365722d7072656669780000003500000011706c61696e2d757365722d7072656669780000001c612d757365722d6b65792d746861742d69732d6e6f742d612d6b6579"
    static let certifiedEd25519Request = "0000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b657900000000207373682d656432353531392d636572742d763031406f70656e7373682e636f6d00000262000000207373682d656432353531392d636572742d763031406f70656e7373682e636f6d000000203c64fe73a18550edaf0791451d6dacd9b74f745d3e29dfedb60b4cf9df5803ee0000002097e4355e0e4b7dc89935efa2b66bef6ab8bf95e154440a7efaacc4e109fd769100000000000000000000000100000010557365722065643235353139206b657900000000000000005ed7d6c700000000bc91fb03000000210000000d666f7263652d636f6d6d616e640000000c00000008756e616d65202d6100000082000000157065726d69742d5831312d666f7277617264696e6700000000000000177065726d69742d6167656e742d666f7277617264696e6700000000000000167065726d69742d706f72742d666f7277617264696e67000000000000000a7065726d69742d707479000000000000000e7065726d69742d757365722d72630000000000000000000000880000001365636473612d736861322d6e69737470333834000000086e69737470333834000000610476253125da717b75de804ba4c5c43f4392330e6891de5cec6de1a229b5311fd31d43b2392d80550284a8b66cfad77763ac980abab94c658334663675f2855fdf672ea242ab693147ffc23f75217ab9199e7eaee1e5b86e22cbef1383a8d3b391000000830000001365636473612d736861322d6e6973747033383400000068000000300567aa46166a1681915e0ed6b4a49b43dace9f658d5226835755e35f6682ca2fd6ef8df51f1a718398862f33f907b66e000000301cb122bb1984133d443c52daa195f50072c3979b01a4452ed9af252cb1827d67c16b643e729eb584ec3f53a5878fb7b5"

    static let ed25519SignablePayload = "000000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a320000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b6579010000000b7373682d65643235353139000000330000000b7373682d6564323535313900000020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    static let plainCustomSignablePayload = "000000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a320000000b66697874757265557365720000000e7373682d636f6e6e656374696f6e000000097075626c69636b65790100000011706c61696e2d757365722d7072656669780000003500000011706c61696e2d757365722d7072656669780000001c612d757365722d6b65792d746861742d69732d6e6f742d612d6b6579"
}

private let fixtureUserName = "fixtureUser"
private let fixtureServiceName = "ssh-connection"
private let fixtureSessionIdentifierBytes = Data(repeating: 0x5A, count: 32)

private extension ByteBuffer {
    var hexEncoded: String {
        self.readableBytesView.map { String(format: "%02x", $0) }.joined()
    }
}

private func serialisedUserAuthRequest(key: NIOSSHPublicKey, signature: NIOSSHSignature? = nil) -> ByteBuffer {
    let message = SSHMessage.UserAuthRequestMessage(
        username: fixtureUserName,
        service: fixtureServiceName,
        method: .publicKey(.known(key: key, signature: signature))
    )
    var buffer = ByteBufferAllocator().buffer(capacity: 1024)
    _ = buffer.writeUserAuthRequestMessage(message)
    return buffer
}

private func signablePayload(for key: NIOSSHPublicKey) -> ByteBuffer {
    var sessionIdentifier = ByteBufferAllocator().buffer(capacity: 32)
    sessionIdentifier.writeBytes(fixtureSessionIdentifierBytes)
    return UserAuthSignablePayload(
        sessionIdentifier: sessionIdentifier,
        userName: fixtureUserName,
        serviceName: fixtureServiceName,
        publicKey: key
    ).bytes
}

/// The three identifiers RFC 8332 §3 keeps apart, read back out of a serialised user auth request.
private struct RequestIdentifiers: Equatable, CustomStringConvertible {
    var pkalg: String
    var blobType: String
    var signatureType: String?

    var description: String {
        "pkalg: \(self.pkalg), blob: \(self.blobType), signature: \(self.signatureType ?? "<none>")"
    }
}

private func readIdentifiers(from buffer: ByteBuffer) throws -> RequestIdentifiers {
    var buffer = buffer
    guard buffer.readSSHString() != nil, // username
          buffer.readSSHString() != nil, // service
          let method = buffer.readSSHStringAsString(),
          method == "publickey",
          let hasSignature = buffer.readSSHBoolean(),
          let pkalg = buffer.readSSHStringAsString(),
          var blob = buffer.readSSHString(),
          let blobType = blob.readSSHStringAsString()
    else {
        throw CustomUserAuthTestError.malformedBlob
    }

    var signatureType: String?
    if hasSignature {
        guard var signature = buffer.readSSHString(), let type = signature.readSSHStringAsString() else {
            throw CustomUserAuthTestError.malformedBlob
        }
        signatureType = type
    }

    return RequestIdentifiers(pkalg: pkalg, blobType: blobType, signatureType: signatureType)
}

/// The public key algorithm name a signable payload carries, i.e. the seventh field of the signed
/// data as listed in RFC 4252 §7.
private func readAlgorithmName(fromSignablePayload buffer: ByteBuffer) throws -> String {
    var buffer = buffer
    guard buffer.readSSHString() != nil, // session identifier
          buffer.readInteger(as: UInt8.self) != nil, // SSH_MSG_USERAUTH_REQUEST
          buffer.readSSHString() != nil, // user name
          buffer.readSSHString() != nil, // service name
          buffer.readSSHString() != nil, // "publickey"
          buffer.readSSHBoolean() != nil,
          let algorithmName = buffer.readSSHStringAsString()
    else {
        throw CustomUserAuthTestError.malformedBlob
    }
    return algorithmName
}

// MARK: - Tests

final class CustomUserAuthAlgorithmNameTests: XCTestCase {
    override func setUp() {
        NIOSSHAlgorithms.unregisterAlgorithms()
    }

    override func tearDown() {
        NIOSSHAlgorithms.unregisterAlgorithms()
    }

    private var renamedKey: NIOSSHPublicKey {
        NIOSSHPublicKey(backingKey: .custom(RenamedUserAuthPublicKey()))
    }

    private var plainKey: NIOSSHPublicKey {
        NIOSSHPublicKey(backingKey: .custom(PlainUserAuthPublicKey()))
    }

    private var renamedSignature: NIOSSHSignature {
        NIOSSHSignature(backingSignature: .custom(RenamedUserAuthSignature(rawRepresentation: Data(repeating: 0x11, count: 16))))
    }

    // MARK: The three identifiers on the wire

    func testARequestWritesTheAlgorithmNameAsPkalgAndTheBlobPrefixInTheBlob() throws {
        let buffer = serialisedUserAuthRequest(key: self.renamedKey, signature: self.renamedSignature)

        XCTAssertEqual(try readIdentifiers(from: buffer),
                       RequestIdentifiers(pkalg: RenamedUserAuthPublicKey.userAuthAlgorithmName,
                                          blobType: RenamedUserAuthPublicKey.publicKeyPrefix,
                                          signatureType: RenamedUserAuthSignature.signaturePrefix))
    }

    func testTheSignablePayloadCarriesTheAlgorithmNameNotTheBlobPrefix() throws {
        let payload = signablePayload(for: self.renamedKey)

        XCTAssertEqual(try readAlgorithmName(fromSignablePayload: payload),
                       RenamedUserAuthPublicKey.userAuthAlgorithmName)
    }

    func testAPKOKEchoWritesTheAlgorithmName() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        _ = buffer.writeUserAuthPKOKMessage(SSHMessage.UserAuthPKOKMessage(key: self.renamedKey))

        guard let echoedName = buffer.readSSHStringAsString(),
              var blob = buffer.readSSHString(),
              let blobType = blob.readSSHStringAsString()
        else {
            XCTFail("Malformed PK_OK")
            return
        }

        XCTAssertEqual(echoedName, RenamedUserAuthPublicKey.userAuthAlgorithmName)
        XCTAssertEqual(blobType, RenamedUserAuthPublicKey.publicKeyPrefix)
    }

    // MARK: The parse side, i.e. the server role

    func testAServerAcceptsARequestWhosePkalgIsTheAlgorithmName() throws {
        NIOSSHAlgorithms.register(publicKey: RenamedUserAuthPublicKey.self, signature: RenamedUserAuthSignature.self)

        // Hand-rolled rather than round-tripped through the writer: a round trip agrees with itself
        // whatever the writer puts in the pkalg field, so it cannot see this at all.
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        _ = buffer.writeSSHString(fixtureUserName.utf8)
        _ = buffer.writeSSHString(fixtureServiceName.utf8)
        _ = buffer.writeSSHString("publickey".utf8)
        _ = buffer.writeSSHBoolean(false)
        _ = buffer.writeSSHString(RenamedUserAuthPublicKey.userAuthAlgorithmName.utf8)
        _ = buffer.writeCompositeSSHString { inner in
            inner.writeSSHHostKey(self.renamedKey)
        }

        guard let parsed = try buffer.readUserAuthRequestMessage() else {
            XCTFail("Did not parse a user auth request")
            return
        }

        guard case .publicKey(.known(key: let key, signature: let signature)) = parsed.method else {
            XCTFail("Expected a known public key, got \(parsed.method)")
            return
        }

        XCTAssertEqual(key, self.renamedKey)
        XCTAssertNil(signature)
    }

    func testAServerRejectsARequestWhosePkalgIsNeitherName() throws {
        NIOSSHAlgorithms.register(publicKey: RenamedUserAuthPublicKey.self, signature: RenamedUserAuthSignature.self)

        // Hand-roll a request whose pkalg is `plain-user-prefix` -- a name that is known, because the
        // plain type is registered too -- around a `blob-x` blob.
        NIOSSHAlgorithms.register(publicKey: PlainUserAuthPublicKey.self, signature: PlainUserAuthSignature.self)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        _ = buffer.writeSSHString(fixtureUserName.utf8)
        _ = buffer.writeSSHString(fixtureServiceName.utf8)
        _ = buffer.writeSSHString("publickey".utf8)
        _ = buffer.writeSSHBoolean(false)
        _ = buffer.writeSSHString(PlainUserAuthPublicKey.publicKeyPrefix.utf8)
        _ = buffer.writeCompositeSSHString { inner in
            inner.writeSSHHostKey(self.renamedKey)
        }

        XCTAssertThrowsError(try buffer.readUserAuthRequestMessage()) { error in
            guard let error = error as? NIOSSHError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(error.type, .invalidSSHMessage, "Unexpected error: \(error)")
        }
    }

    func testAServerAcceptsAPKOKWhoseNameIsTheAlgorithmName() throws {
        NIOSSHAlgorithms.register(publicKey: RenamedUserAuthPublicKey.self, signature: RenamedUserAuthSignature.self)

        // Hand-rolled for the same reason as the request above.
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        _ = buffer.writeSSHString(RenamedUserAuthPublicKey.userAuthAlgorithmName.utf8)
        _ = buffer.writeCompositeSSHString { inner in
            inner.writeSSHHostKey(self.renamedKey)
        }

        let parsed = try buffer.readUserAuthPKOKMessage()
        XCTAssertEqual(parsed?.key, self.renamedKey)
    }

    // MARK: The member itself

    func testTheDefaultUserAuthAlgorithmNameIsTheBlobPrefix() {
        XCTAssertEqual(PlainUserAuthPublicKey.userAuthAlgorithmName, PlainUserAuthPublicKey.publicKeyPrefix)
        XCTAssertEqual(String(decoding: self.plainKey.userAuthAlgorithmName, as: UTF8.self),
                       PlainUserAuthPublicKey.publicKeyPrefix)
    }

    func testTheUserAuthNameIsIndependentOfTheHostKeyNames() {
        // The renamed type declares only the user auth split, so its host key names still default to
        // the blob prefix. The two members do not stand in for one another.
        XCTAssertEqual(RenamedUserAuthPublicKey.hostKeyAlgorithmNames, [RenamedUserAuthPublicKey.publicKeyPrefix])
        XCTAssertEqual(RenamedUserAuthPublicKey.userAuthAlgorithmName, "alg-x")
    }

    func testABundledKeysUserAuthAlgorithmNameIsItsBlobPrefix() {
        let key = DeterministicKeys.ed25519
        XCTAssertEqual(String(decoding: key.userAuthAlgorithmName, as: UTF8.self),
                       String(decoding: key.keyPrefix, as: UTF8.self))
    }

    func testACertifiedKeysUserAuthAlgorithmNameIsItsCertificateName() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: DeterministicKeys.certifiedEd25519OpenSSH)
        XCTAssertEqual(String(decoding: key.userAuthAlgorithmName, as: UTF8.self),
                       String(decoding: key.keyPrefix, as: UTF8.self))
        XCTAssertEqual(String(decoding: key.userAuthAlgorithmName, as: UTF8.self),
                       "ssh-ed25519-cert-v01@openssh.com")
    }

    func testKnownAlgorithmsCarriesTheUserAuthNameAndTheBlobPrefixExactlyOnceEach() {
        NIOSSHAlgorithms.register(publicKey: RenamedUserAuthPublicKey.self, signature: RenamedUserAuthSignature.self)

        let known = NIOSSHPublicKey.knownAlgorithms.map { String(decoding: $0, as: UTF8.self) }

        XCTAssertEqual(known.filter { $0 == RenamedUserAuthPublicKey.userAuthAlgorithmName }.count, 1, "\(known)")
        XCTAssertEqual(known.filter { $0 == RenamedUserAuthPublicKey.publicKeyPrefix }.count, 1, "\(known)")
    }

    func testKnownAlgorithmsDoesNotDuplicateAPrefixThatIsAlsoTheUserAuthName() {
        // Measured against this run's own baseline rather than a written-down number, so that adding
        // a bundled type cannot make this assertion quietly wrong.
        let bundledCount = NIOSSHPublicKey.knownAlgorithms.count

        NIOSSHAlgorithms.register(publicKey: PlainUserAuthPublicKey.self, signature: PlainUserAuthSignature.self)

        let known = NIOSSHPublicKey.knownAlgorithms.map { String(decoding: $0, as: UTF8.self) }

        XCTAssertEqual(known.filter { $0 == PlainUserAuthPublicKey.publicKeyPrefix }.count, 1, "\(known)")
        XCTAssertEqual(known.count, bundledCount + 1,
                       "a type without either override must contribute exactly one name, got \(known)")
    }

    // MARK: A type without the override, and the bundled types, are untouched

    func testATypeWithoutTheOverrideWritesItsBlobPrefixAsPkalg() throws {
        let signature = NIOSSHSignature(backingSignature: .custom(PlainUserAuthSignature(rawRepresentation: Data(repeating: 0x22, count: 16))))
        let buffer = serialisedUserAuthRequest(key: self.plainKey, signature: signature)

        XCTAssertEqual(try readIdentifiers(from: buffer),
                       RequestIdentifiers(pkalg: PlainUserAuthPublicKey.publicKeyPrefix,
                                          blobType: PlainUserAuthPublicKey.publicKeyPrefix,
                                          signatureType: PlainUserAuthSignature.signaturePrefix))
    }

    func testATypeWithoutTheOverrideSerialisesExactlyAsItDidAt039() {
        XCTAssertEqual(serialisedUserAuthRequest(key: self.plainKey).hexEncoded, RecordedAt039.plainCustomRequest)
    }

    func testEd25519SerialisesExactlyAsItDidAt039() {
        XCTAssertEqual(serialisedUserAuthRequest(key: DeterministicKeys.ed25519).hexEncoded, RecordedAt039.ed25519Request)
    }

    func testP256SerialisesExactlyAsItDidAt039() {
        XCTAssertEqual(serialisedUserAuthRequest(key: DeterministicKeys.p256).hexEncoded, RecordedAt039.p256Request)
    }

    func testP384SerialisesExactlyAsItDidAt039() {
        XCTAssertEqual(serialisedUserAuthRequest(key: DeterministicKeys.p384).hexEncoded, RecordedAt039.p384Request)
    }

    func testP521SerialisesExactlyAsItDidAt039() {
        XCTAssertEqual(serialisedUserAuthRequest(key: DeterministicKeys.p521).hexEncoded, RecordedAt039.p521Request)
    }

    func testACertifiedKeySerialisesExactlyAsItDidAt039() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: DeterministicKeys.certifiedEd25519OpenSSH)
        XCTAssertEqual(serialisedUserAuthRequest(key: key).hexEncoded, RecordedAt039.certifiedEd25519Request)
    }

    func testACertifiedKeyWritesItsCertificateAlgorithmNameAsPkalg() throws {
        let key = try NIOSSHPublicKey(openSSHPublicKey: DeterministicKeys.certifiedEd25519OpenSSH)
        let identifiers = try readIdentifiers(from: serialisedUserAuthRequest(key: key))

        XCTAssertEqual(identifiers.pkalg, "ssh-ed25519-cert-v01@openssh.com")
        XCTAssertEqual(identifiers.blobType, "ssh-ed25519-cert-v01@openssh.com")
    }

    func testTheSignablePayloadForEd25519IsExactlyAsItWasAt039() {
        XCTAssertEqual(signablePayload(for: DeterministicKeys.ed25519).hexEncoded, RecordedAt039.ed25519SignablePayload)
    }

    func testTheSignablePayloadForATypeWithoutTheOverrideIsExactlyAsItWasAt039() {
        XCTAssertEqual(signablePayload(for: self.plainKey).hexEncoded, RecordedAt039.plainCustomSignablePayload)
    }
}
