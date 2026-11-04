/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import java.security.Provider
import java.security.Security
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ExternalSshPublicKeyTest {
  private val ed25519Key =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"

  @Test
  fun ed25519KeySelectionWorksBeforeTheFirstSshConnection() {
    val original = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
    val originalPosition =
      Security.getProviders().indexOfFirst { it.name == BouncyCastleProvider.PROVIDER_NAME } + 1
    try {
      // Reproduce Android's "BC" provider existing without Ed25519 support.
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
      @Suppress("DEPRECATION")
      val trimmedAndroidBc =
        object : Provider(BouncyCastleProvider.PROVIDER_NAME, 1.0, "Trimmed Android BC") {}
      Security.insertProviderAt(trimmedAndroidBc, 1)

      assertEquals(ed25519Key, normalizeExternalSshPublicKey(ed25519Key))
      assertIs<BouncyCastleProvider>(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
      if (original != null) Security.insertProviderAt(original, originalPosition)
    }
  }

  @Test
  fun reconnectAcceptsTheSameProviderKey() {
    normalizeExternalSshPublicKey(ed25519Key)
    val keyWithComment = "$ed25519Key user@token"
    assertEquals(
      toSshPublicKey(requireMatchingExternalSshPublicKey(ed25519Key, keyWithComment)),
      ed25519Key,
    )
  }

  @Test
  fun changedProviderKeyIsRejectedInsteadOfSilentlyAuthenticating() {
    normalizeExternalSshPublicKey(ed25519Key)
    val replacementKey =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEPNwCPSLV+eEH0aBpNFfTXR0Q630hxyEZL1b13kBmXT"
    assertFailsWith<java.io.IOException> {
      requireMatchingExternalSshPublicKey(ed25519Key, replacementKey)
    }
  }

  @Test
  fun rejectsKeyTypeThatDisagreesWithTheEncodedKey() {
    assertFailsWith<IllegalArgumentException> {
      normalizeExternalSshPublicKey(ed25519Key.replaceFirst("ssh-ed25519", "ssh-rsa"))
    }
  }

  @Test
  fun rejectsMalformedProviderKey() {
    assertFails { normalizeExternalSshPublicKey("ssh-ed25519 not-a-base64-key") }
  }
}
