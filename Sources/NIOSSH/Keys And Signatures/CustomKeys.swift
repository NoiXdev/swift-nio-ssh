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

import Foundation
import NIO

/// A signature is a mathematical scheme for verifying the authenticity of digital messages or documents.
///
/// This protocol can be implemented by a type that represents such a signature to NIOSSH.
///
/// - See: https://en.wikipedia.org/wiki/Digital_signature
public protocol NIOSSHSignatureProtocol {
    /// An identifier that represents the type of signature used in an SSH packet.
    /// This identifier MUST be unique to the signature implementation.
    /// The returned value MUST NOT overlap with other signature implementations or a specifications that the signature does not implement.
    static var signaturePrefix: String { get }

    /// The raw reprentation of this signature as a blob.
    var rawRepresentation: Data { get }

    /// Serializes and writes the signature to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads this Signature from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

internal extension NIOSSHSignatureProtocol {
    var signaturePrefix: String {
        Self.signaturePrefix
    }
}

public protocol NIOSSHPublicKeyProtocol {
    /// An identifier that represents the type of public key used in an SSH packet.
    /// This identifier MUST be unique to the public key implementation.
    /// The returned value MUST NOT overlap with other public key implementations or a specifications that the public key does not implement.
    static var publicKeyPrefix: String { get }

    /// The host key algorithm names under which this key type is offered and negotiated during key exchange.
    ///
    /// RFC 8332 separates the algorithm name negotiated in key exchange from the key blob type that
    /// identifies the key on the wire. An RSA host key negotiated as `rsa-sha2-256` or `rsa-sha2-512`
    /// still arrives in a blob typed `ssh-rsa`, so for such a type the two identifiers differ and both
    /// are needed: `publicKeyPrefix` reads and writes the blob, these names are what appears in
    /// SSH_MSG_KEXINIT and in `NIOSSHError.invalidHostKeyForKeyExchange`.
    ///
    /// Implementing this is optional. The default is `[publicKeyPrefix]`, which is the correct answer
    /// for every key type whose algorithm name and blob type coincide -- including all of the types
    /// bundled with NIOSSH.
    static var hostKeyAlgorithmNames: [String] { get }

    /// The raw reprentation of this publc key as a blob.
    var rawRepresentation: Data { get }

    /// Verifies that `signature` is the result of signing `data` using the private key that this public key is derived from.
    func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool

    /// Serializes and writes the public key to the buffer. The calling function SHOULD NOT keep track of the size of the written blob.
    /// If the result is not a fixed size, the serialized format SHOULD include a length.
    func write(to buffer: inout ByteBuffer) -> Int

    /// Reads this Public Key from the buffer using the same format implemented in `write(to:)`
    static func read(from buffer: inout ByteBuffer) throws -> Self
}

public extension NIOSSHPublicKeyProtocol {
    static var hostKeyAlgorithmNames: [String] {
        [Self.publicKeyPrefix]
    }
}

internal extension NIOSSHPublicKeyProtocol {
    var publicKeyPrefix: String {
        Self.publicKeyPrefix
    }
}

public protocol NIOSSHPrivateKeyProtocol {
    /// An identifier that represents the type of private key used in an SSH packet.
    /// This identifier MUST be unique to the private key implementation.
    /// The returned value MUST NOT overlap with other private key implementations or a specifications that the private key does not implement.
    static var keyPrefix: String { get }

    /// A public key instance that is able to verify signatures that are created using this private key.
    var publicKey: NIOSSHPublicKeyProtocol { get }

    /// Creates a signature, proving that `data` has been sent by the holder of this private key, and can be verified by `publicKey`.
    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol
}

internal extension NIOSSHPrivateKeyProtocol {
    var keyPrefix: String {
        Self.keyPrefix
    }
}
