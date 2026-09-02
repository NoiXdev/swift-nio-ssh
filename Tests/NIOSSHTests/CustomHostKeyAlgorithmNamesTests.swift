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
import NIOEmbedded
import NIOFoundationCompat
@testable import NIOSSH
import XCTest

// MARK: - Fixtures

private enum CustomHostKeyTestError: Error {
    case malformedBlob
}

private let renamedAlgorithmTestKey = Data("a-key-that-is-not-a-key".utf8)

/// A stand-in for a real signature: XOR the payload with a fixed pad. Reversible, so the public key
/// can check it without any cryptography being involved.
private func xorWithTestKey(_ data: Data) -> Data {
    var data = data
    let padSize = renamedAlgorithmTestKey.count
    for index in 0 ..< data.count {
        data[index] ^= renamedAlgorithmTestKey[index % padSize]
    }
    return data
}

/// A host key type whose key exchange algorithm name differs from its key blob type, the way
/// RFC 8332 separates `rsa-sha2-512` from `ssh-rsa`.
struct RenamedAlgorithmPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "blob-x"
    static let hostKeyAlgorithmNames = ["alg-x"]

    var rawRepresentation: Data {
        renamedAlgorithmTestKey
    }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        signature.rawRepresentation == xorWithTestKey(Data(data))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RenamedAlgorithmPublicKey {
        guard var body = buffer.readSSHString(), body.readData(length: body.readableBytes) != nil else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return RenamedAlgorithmPublicKey()
    }
}

struct RenamedAlgorithmSignature: NIOSSHSignatureProtocol {
    // Matches the algorithm name, not the key blob type: RFC 8332 types the signature blob with the
    // negotiated algorithm.
    static let signaturePrefix = "alg-x"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> RenamedAlgorithmSignature {
        guard var body = buffer.readSSHString(), let data = body.readData(length: body.readableBytes) else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return RenamedAlgorithmSignature(rawRepresentation: data)
    }
}

struct RenamedAlgorithmPrivateKey: NIOSSHPrivateKeyProtocol {
    // The private key's prefix is what a server offers, so it is the algorithm name.
    static let keyPrefix = "alg-x"

    var publicKey: NIOSSHPublicKeyProtocol {
        RenamedAlgorithmPublicKey()
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        RenamedAlgorithmSignature(rawRepresentation: xorWithTestKey(Data(data)))
    }
}

/// A host key type that does not implement `hostKeyAlgorithmNames`, i.e. every custom type written
/// against NIOSSH before this member existed.
struct PlainPrefixPublicKey: NIOSSHPublicKeyProtocol {
    static let publicKeyPrefix = "plain-prefix"

    var rawRepresentation: Data {
        renamedAlgorithmTestKey
    }

    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
        signature.rawRepresentation == xorWithTestKey(Data(data))
    }

    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> PlainPrefixPublicKey {
        guard var body = buffer.readSSHString(), body.readData(length: body.readableBytes) != nil else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return PlainPrefixPublicKey()
    }
}

struct PlainPrefixSignature: NIOSSHSignatureProtocol {
    static let signaturePrefix = "plain-prefix"

    let rawRepresentation: Data

    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeSSHString(self.rawRepresentation)
    }

    static func read(from buffer: inout ByteBuffer) throws -> PlainPrefixSignature {
        guard var body = buffer.readSSHString(), let data = body.readData(length: body.readableBytes) else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return PlainPrefixSignature(rawRepresentation: data)
    }
}

// MARK: - Tests

final class CustomHostKeyAlgorithmNamesTests: XCTestCase {
    override func setUp() {
        NIOSSHAlgorithms.unregisterAlgorithms()
    }

    override func tearDown() {
        NIOSSHAlgorithms.unregisterAlgorithms()
    }

    // MARK: The KEXINIT offer

    func testCustomKeyIsOfferedUnderItsAlgorithmNameAndNotItsBlobPrefix() {
        NIOSSHAlgorithms.register(publicKey: RenamedAlgorithmPublicKey.self, signature: RenamedAlgorithmSignature.self)

        let offer = SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms

        // Positive and negative together: the negative below can only go stale in silence if nothing
        // asserts that the type reached the offer at all.
        XCTAssertTrue(offer.contains(Substring(RenamedAlgorithmPublicKey.hostKeyAlgorithmNames[0])),
                      "expected the algorithm name in the offer, got \(offer)")
        XCTAssertFalse(offer.contains(Substring(RenamedAlgorithmPublicKey.publicKeyPrefix)),
                       "the key blob type must not be offered as an algorithm name, got \(offer)")
    }

    func testCustomKeyWithoutTheOverrideIsStillOfferedUnderItsBlobPrefix() {
        NIOSSHAlgorithms.register(publicKey: PlainPrefixPublicKey.self, signature: PlainPrefixSignature.self)

        let offer = SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms

        XCTAssertTrue(offer.contains(Substring(PlainPrefixPublicKey.publicKeyPrefix)),
                      "expected the blob prefix in the offer, got \(offer)")
        XCTAssertEqual(offer.filter { $0 == Substring(PlainPrefixPublicKey.publicKeyPrefix) }.count, 1,
                       "the prefix must appear exactly once, got \(offer)")
        XCTAssertEqual(offer.count, SSHKeyExchangeStateMachine.bundledServerHostKeyAlgorithms.count + 1,
                       "a type without the override must contribute exactly one name, got \(offer)")
    }

    func testKnownAlgorithmsCarriesBothTheBlobPrefixAndTheAlgorithmName() {
        NIOSSHAlgorithms.register(publicKey: RenamedAlgorithmPublicKey.self, signature: RenamedAlgorithmSignature.self)

        let known = NIOSSHPublicKey.knownAlgorithms.map { String(decoding: $0, as: UTF8.self) }

        XCTAssertTrue(known.contains(RenamedAlgorithmPublicKey.hostKeyAlgorithmNames[0]), "\(known)")
        // The blob prefix stays: it is the identifier the key blob itself carries.
        XCTAssertTrue(known.contains(RenamedAlgorithmPublicKey.publicKeyPrefix), "\(known)")
    }

    func testKnownAlgorithmsDoesNotDuplicateAPrefixThatIsAlsoAnAlgorithmName() {
        NIOSSHAlgorithms.register(publicKey: PlainPrefixPublicKey.self, signature: PlainPrefixSignature.self)

        let known = NIOSSHPublicKey.knownAlgorithms.map { String(decoding: $0, as: UTF8.self) }

        XCTAssertEqual(known.filter { $0 == PlainPrefixPublicKey.publicKeyPrefix }.count, 1, "\(known)")
    }

    func testTheDefaultForAKeyWithoutTheOverrideIsItsBlobPrefix() {
        XCTAssertEqual(PlainPrefixPublicKey.hostKeyAlgorithmNames, [PlainPrefixPublicKey.publicKeyPrefix])
    }

    // MARK: The identity check on the KEX reply

    func testANegotiatedAlgorithmNameAcceptsAHostKeyBlobOfADifferentType() throws {
        NIOSSHAlgorithms.register(publicKey: RenamedAlgorithmPublicKey.self, signature: RenamedAlgorithmSignature.self)

        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            keyExchangeAlgorithms: SSHKeyExchangeStateMachine.bundledKeyExchangeImplementations,
            transportProtectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        // The server offers exactly one host key algorithm, `alg-x`, so the handshake can only
        // succeed if the client offered that name too.
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [NIOSSHPrivateKey(custom: RenamedAlgorithmPrivateKey())],
                                userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            keyExchangeAlgorithms: SSHKeyExchangeStateMachine.bundledKeyExchangeImplementations,
            transportProtectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        XCTAssertNil(try server.handle(keyExchange: clientMessage))

        let ecdhInit = try XCTUnwrap(try client.handle(keyExchange: serverMessage)?.first).asKeyExchangeInit()
        client.send(keyExchangeInit: ecdhInit)

        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, Substring(RenamedAlgorithmPrivateKey.keyPrefix))

        let ecdhReply = try XCTUnwrap(try server.handle(keyExchangeInit: ecdhInit)?.first).asKeyExchangeReply()

        // The blob the server sends is typed with the key's blob prefix, not with the negotiated
        // algorithm name. That is the point of the test.
        XCTAssertTrue(ecdhReply.hostKey.keyPrefix.elementsEqual(RenamedAlgorithmPublicKey.publicKeyPrefix.utf8))

        XCTAssertNoThrow(try server.send(keyExchangeReply: ecdhReply))
        _ = server.sendNewKeys()

        // The client must not reject the reply just because the blob type is not the negotiated name.
        let response = try client.handle(keyExchangeReply: ecdhReply).wait()
        XCTAssertEqual(response?.count, 1)
    }

    func testANegotiatedAlgorithmNameStillRejectsAnUnrelatedHostKeyBlob() throws {
        NIOSSHAlgorithms.register(publicKey: RenamedAlgorithmPublicKey.self, signature: RenamedAlgorithmSignature.self)

        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        var client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())),
            remoteVersion: Constants.version,
            keyExchangeAlgorithms: SSHKeyExchangeStateMachine.bundledKeyExchangeImplementations,
            transportProtectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        var server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: [NIOSSHPrivateKey(custom: RenamedAlgorithmPrivateKey())],
                                userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            keyExchangeAlgorithms: SSHKeyExchangeStateMachine.bundledKeyExchangeImplementations,
            transportProtectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )

        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        XCTAssertNil(try server.handle(keyExchange: clientMessage))
        let ecdhInit = try XCTUnwrap(try client.handle(keyExchange: serverMessage)?.first).asKeyExchangeInit()
        client.send(keyExchangeInit: ecdhInit)
        let ecdhReply = try XCTUnwrap(try server.handle(keyExchangeInit: ecdhInit)?.first).asKeyExchangeReply()

        // Swap in an ed25519 host key, whose name is neither `alg-x` nor `blob-x`.
        let impostor = SSHMessage.KeyExchangeECDHReplyMessage(hostKey: NIOSSHPrivateKey(ed25519Key: .init()).publicKey,
                                                              publicKey: ecdhReply.publicKey,
                                                              signature: ecdhReply.signature)

        XCTAssertThrowsError(try client.handle(keyExchangeReply: impostor)) { error in
            guard let error = error as? NIOSSHError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(error.type, .invalidHostKeyForKeyExchange, "Unexpected error: \(error)")
        }
    }
}

// MARK: - Helpers

private extension SSHMessage {
    func asKeyExchangeInit() throws -> SSHMessage.KeyExchangeECDHInitMessage {
        guard case .keyExchangeInit(let message) = self else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return message
    }

    func asKeyExchangeReply() throws -> SSHMessage.KeyExchangeECDHReplyMessage {
        guard case .keyExchangeReply(let message) = self else {
            throw CustomHostKeyTestError.malformedBlob
        }
        return message
    }
}
