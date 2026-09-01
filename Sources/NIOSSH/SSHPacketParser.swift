//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

struct SSHPacketParser {
    enum State {
        case initialized
        case cleartextWaitingForLength
        case cleartextWaitingForBytes(UInt32)
        case encryptedWaitingForLength(NIOSSHTransportProtection)
        case encryptedWaitingForBytes(UInt32, NIOSSHTransportProtection)
    }

    private var buffer: ByteBuffer
    private var state: State
    private var sequenceNumber: UInt32 = 0
    private let maximumPacketSize: Int
    internal static let defaultMaximumPacketSize = 1 << 17

    /// Testing only: the number of bytes we can discard from this buffer.
    internal var _discardableBytes: Int {
        self.buffer.readerIndex
    }

    /// Whether this parser reads for a server. RFC 4253 §4.2 lets only the
    /// SERVER send lines before its identification string, so a client-side
    /// parser skips such lines and a server-side parser treats the first line
    /// as the version — and lets `validateBanner` reject a client that sent
    /// anything else. No default on purpose: a forgotten argument must not
    /// quietly make a server tolerant.
    private let isServer: Bool

    init(isServer: Bool, allocator: ByteBufferAllocator, maximumPacketSize: Int = defaultMaximumPacketSize) {
        self.isServer = isServer
        // Assert that users don't provide a packet size lower than allowed by spec
        precondition(maximumPacketSize >= 32768, "Maximum Packet Size is below minimum requirement as specified by RFC 4254")
        precondition(maximumPacketSize <= (1 << 24), "Maximum Packet Size is set abnormally high")

        self.buffer = allocator.buffer(capacity: 0)
        self.state = .initialized
        self.maximumPacketSize = maximumPacketSize
    }

    mutating func append(bytes: inout ByteBuffer) {
        self.buffer.writeBuffer(&bytes)
    }

    /// Encryption schemes can be added to a packet parser whenever encryption is negotiated.
    /// They must be added monotonically, and may only be added once, while the parser is in an
    /// idle state.
    mutating func addEncryption(_ protection: NIOSSHTransportProtection) {
        switch self.state {
        case .cleartextWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .encryptedWaitingForLength:
            self.state = .encryptedWaitingForLength(protection)
        case .cleartextWaitingForBytes, .initialized, .encryptedWaitingForBytes:
            preconditionFailure("Adding encryption in invalid state: \(self.state)")
        }
    }

    mutating func nextPacket() throws -> SSHMessage? {
        // This parser has a slightly strange strategy: we leave the packet length field in the buffer until we're done.
        // This is necessary because some transport protection schemes need the length field for MACing purposes, and can
        // benefit from us maintaining the state instead of having to do it themselves.
        defer {
            self.reclaimBytes()
        }

        switch self.state {
        case .initialized:
            if let version = try self.readVersion() {
                self.state = .cleartextWaitingForLength
                return .version(version)
            }
            return nil
        case .cleartextWaitingForLength:
            if let length = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self) {
                if length >= self.maximumPacketSize {
                    throw NIOSSHError.invalidEncryptedPacketLength
                }

                if let message = try self.parsePlaintext(length: length) {
                    self.state = .cleartextWaitingForLength
                    self.sequenceNumber = self.sequenceNumber &+ 1
                    return message
                }
                self.state = .cleartextWaitingForBytes(length)
                return nil
            }
            return nil
        case .cleartextWaitingForBytes(let length):
            if let message = try self.parsePlaintext(length: length) {
                self.state = .cleartextWaitingForLength
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            return nil
        case .encryptedWaitingForLength(let protection):
            guard let length = try self.decryptLength(protection: protection) else {
                return nil
            }

            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            self.state = .encryptedWaitingForBytes(length, protection)
            return nil
        case .encryptedWaitingForBytes(let length, let protection):
            if let message = try self.parseCiphertext(length: length, protection: protection) {
                self.state = .encryptedWaitingForLength(protection)
                self.sequenceNumber = self.sequenceNumber &+ 1
                return message
            }
            return nil
        }
    }

    private mutating func reclaimBytes() {
        if self.buffer.readerIndex > 1024, self.buffer.readerIndex > (self.buffer.readableBytes / 2) {
            self.buffer.discardReadBytes()
        }
    }

    internal static let maximumAllowedVersionSize = 4096
    private mutating func readVersion() throws -> String? {
        // Looking for a complete SSH version string, potentially with pre-lines
        let slice = self.buffer.readableBytesView

        // Prevent the consumed bytes for a version from exceeding the defined maximum allowed size
        // In practice, if SSH version packets come anywhere near this it's already likely an attack
        // More data cannot be blindly regarded as malicious though, since this might contain multiple packets
        let maxIndex = slice.index(slice.startIndex, offsetBy: min(slice.count, Self.maximumAllowedVersionSize))

        var lastLineEndIndex: ByteBufferView.Index?
        
        for index in slice.startIndex ..< slice.endIndex {
            if index > maxIndex {
                // Does not account for `CRLF`
                throw NIOSSHError.excessiveVersionLength
            }

            if slice[index] == 10 { // Found a line ending
                let lineStartIndex = lastLineEndIndex?.advanced(by: 1) ?? slice.startIndex
                let lineSlice = slice[lineStartIndex..<index]
                
                // A client keeps skipping until it sees the line that looks like
                // an SSH version (any SSH version, not just 2.0). A server takes
                // the first line, whatever it is: a client is not allowed to send
                // a preamble, and validation downstream rejects what is not "SSH-".
                let isVersionLine = lineSlice.count >= 4 && lineSlice.starts(with: "SSH-".utf8)
                if self.isServer || isVersionLine {
                    // Found the SSH version line. Only THIS line is the version:
                    // RFC 4253 §4.2 lets a server send other lines first, and
                    // they are not part of V_S. The version string feeds the
                    // key-exchange hash, so returning the preamble with it makes
                    // the client hash something the server never signed.
                    var version = String(decoding: lineSlice, as: UTF8.self)
                    // Consume everything up to and including this line's \n,
                    // preamble included, so nothing lingers before the first packet.
                    self.buffer.moveReaderIndex(forwardBy: slice.startIndex.distance(to: index).advanced(by: 1))
                    // Remove the trailing \r if present (but keep \n removal logic for consistency)
                    if version.last == "\r" {
                        version.removeLast()
                    }
                    return version
                }
                
                lastLineEndIndex = index
            }
        }

        return nil
    }

    private mutating func decryptLength(protection: NIOSSHTransportProtection) throws -> UInt32? {
        let blockSize = protection.cipherBlockSize
        guard self.buffer.readableBytes >= blockSize else {
            return nil
        }

        try protection.decryptFirstBlock(&self.buffer)

        // This force unwrap is safe because we must have a block size, and a block size is always going to be more than 4 bytes.
        let packetLength = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self)!
        let decryptedLength = packetLength + UInt32(protection.macBytes)

        if decryptedLength >= self.maximumPacketSize {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        return decryptedLength
    }

    private mutating func parsePlaintext(length: UInt32) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            // We have enough length. Skip over the frame length now.
            buffer.moveReaderIndex(forwardBy: MemoryLayout<UInt32>.size)

            var content = try buffer.sliceContentFromPadding()
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }

    private mutating func parseCiphertext(length: UInt32, protection: NIOSSHTransportProtection) throws -> SSHMessage? {
        try self.buffer.rewindReaderOnError { buffer in
            guard var buffer = buffer.readSlice(length: Int(length) + MemoryLayout<UInt32>.size) else {
                return nil
            }

            var content = try protection.decryptAndVerifyRemainingPacket(&buffer, sequenceNumber: sequenceNumber)
            guard let message = try content.readSSHMessage(), content.readableBytes == 0, buffer.readableBytes == 0 else {
                // Throw this error if the content wasn't exactly the right length for the message.
                throw NIOSSHError.invalidPacketFormat
            }

            return message
        }
    }
}

private extension ByteBuffer {
    /// Given a ByteBuffer that is exactly the size of a packet with padding (i.e. the padding byte is first),
    /// slices out the part of the packet that is content and returns it, while moving the reader index over the entire
    /// packet.
    mutating func sliceContentFromPadding() throws -> ByteBuffer {
        guard let paddingLength = self.readInteger(as: UInt8.self) else {
            throw NIOSSHError.insufficientPadding
        }

        guard let contentSlice = self.readSlice(length: self.readableBytes - Int(paddingLength)) else {
            throw NIOSSHError.excessPadding
        }

        guard self.readerIndex + Int(paddingLength) == self.writerIndex else {
            throw NIOSSHError.invalidPacketFormat
        }

        self.moveReaderIndex(forwardBy: Int(paddingLength))

        return contentSlice
    }
}
