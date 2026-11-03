/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.common.SSHPacket
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.method.AuthPublickey

/**
 * SSHJ builds the session-bound challenge; an external provider signs that exact challenge. The
 * provider returns an RFC 4253 SSH signature blob, already including its algorithm name.
 */
class ExternalSshAuth(
  publicKey: PublicKey,
  private val signer: (ByteArray, String) -> ByteArray,
) :
  AuthPublickey(
    object : KeyProvider {
      override fun getPublic(): PublicKey = publicKey

      override fun getPrivate(): PrivateKey =
        throw IOException("External SSH credentials have no exportable private key")

      override fun getType(): KeyType = KeyType.fromKey(publicKey)
    }
  ) {
  private val algorithmType = KeyType.fromKey(publicKey)

  override fun putSig(reqBuf: SSHPacket): SSHPacket {
    val algorithm =
      getPublicKeyAlgorithm(algorithmType)?.keyAlgorithm
        ?: throw UserAuthException("No compatible SSH signature algorithm")
    val challenge =
      Buffer.PlainBuffer().putString(params.transport.sessionID).putBuffer(reqBuf).compactData
    val signature =
      try {
        signer(challenge, algorithm)
      } catch (error: Exception) {
        throw UserAuthException("External SSH signing failed", error)
      } finally {
        challenge.fill(0)
      }
    validateExternalSshSignature(signature, algorithm)
    // The provider's response is already a complete SSH signature: string(name) + string(bytes).
    return reqBuf.putString(signature)
  }
}

/** Reject provider errors, unexpected algorithms and malformed or trailing signature bytes. */
fun validateExternalSshSignature(signature: ByteArray, expectedAlgorithm: String) {
  require(signature.size in 9..16384) { "Invalid external SSH signature length" }
  val buffer = ByteBuffer.wrap(signature)
  fun readString(): ByteArray {
    require(buffer.remaining() >= 4) { "Malformed external SSH signature" }
    val size = buffer.int
    require(size > 0 && size <= buffer.remaining()) { "Malformed external SSH signature" }
    return ByteArray(size).also { buffer.get(it) }
  }
  val algorithm = String(readString(), StandardCharsets.US_ASCII)
  require(algorithm == expectedAlgorithm) {
    "SSH signature algorithm mismatch: expected " + expectedAlgorithm + ", got " + algorithm
  }
  readString()
  require(!buffer.hasRemaining()) { "External SSH signature contains trailing bytes" }
}
