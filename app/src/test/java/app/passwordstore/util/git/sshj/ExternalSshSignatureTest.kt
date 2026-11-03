/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertFailsWith

class ExternalSshSignatureTest {
  private fun blob(name: String, bytes: ByteArray = byteArrayOf(1, 2)): ByteArray {
    val algorithm = name.toByteArray(Charsets.US_ASCII)
    return ByteBuffer.allocate(4 + algorithm.size + 4 + bytes.size)
      .putInt(algorithm.size).put(algorithm).putInt(bytes.size).put(bytes).array()
  }

  @Test fun acceptsEd25519AndRsaSha2() {
    validateExternalSshSignature(blob("ssh-ed25519"), "ssh-ed25519")
    validateExternalSshSignature(blob("rsa-sha2-512"), "rsa-sha2-512")
  }
  @Test fun rejectsAlgorithmSubstitution() {
    assertFailsWith<IllegalArgumentException> {
      validateExternalSshSignature(blob("ssh-rsa"), "rsa-sha2-256")
    }
  }
  @Test fun rejectsTruncation() {
    assertFailsWith<IllegalArgumentException> {
      validateExternalSshSignature(blob("ssh-ed25519").dropLast(1).toByteArray(), "ssh-ed25519")
    }
  }
  @Test fun rejectsTrailingBytes() {
    assertFailsWith<IllegalArgumentException> {
      validateExternalSshSignature(blob("ssh-ed25519") + byteArrayOf(42), "ssh-ed25519")
    }
  }
  @Test fun rejectsEmptySignature() {
    assertFailsWith<IllegalArgumentException> {
      validateExternalSshSignature(blob("ssh-ed25519", byteArrayOf()), "ssh-ed25519")
    }
  }
}
