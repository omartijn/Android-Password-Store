/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SshConnectionCleanupTest {
  @Test
  fun failedAuthenticationAlwaysClosesThePartiallyOpenedConnection() {
    val failure = IOException("Provider signing cancelled")
    var closed = false
    val result =
      assertFailsWith<IOException> {
        closeOnFailure({ throw failure }) { closed = true }
      }
    assertSame(failure, result)
    assertTrue(closed)
  }

  @Test
  fun cleanupFailureDoesNotMaskAuthenticationError() {
    val failure = IOException("Authentication failed")
    val cleanupFailure = IOException("Failed to close SSH client")
    val result =
      assertFailsWith<IOException> {
        closeOnFailure({ throw failure }) { throw cleanupFailure }
      }
    assertSame(failure, result)
    assertEquals(listOf(cleanupFailure), result.suppressed.toList())
  }

  @Test
  fun successfulAuthenticationKeepsConnectionOpen() {
    var closed = false
    val result = closeOnFailure({ "connected" }) { closed = true }
    assertEquals("connected", result)
    assertTrue(!closed)
  }
}
