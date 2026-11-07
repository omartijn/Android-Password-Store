/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git

import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking

/** Test the coroutine lifetime policy without relying on Robolectric's service/resource stubs. */
class InteractiveGitForegroundServiceTest {
  @Test
  fun successfulTransferReleasesForegroundProtection(): Unit = runBlocking {
    var active = false
    val result =
      withForegroundLease(
        start = { active = true },
        stop = { active = false },
        operation = {
          assertTrue(active)
          "git completed"
        },
      )

    assertEquals("git completed", result)
    assertTrue(!active)
  }

  @Test
  fun providerFailureReleasesForegroundProtection(): Unit = runBlocking {
    var active = false
    val failure = IOException("Provider signing failed")
    val thrown =
      assertFailsWith<IOException> {
        withForegroundLease(
          start = { active = true },
          stop = { active = false },
          operation = { throw failure },
        )
      }

    assertSame(failure, thrown)
    assertTrue(!active)
  }

  @Test
  fun partiallyFailedServiceStartIsAlsoCleanedUp(): Unit = runBlocking {
    var active = false
    var ranGit = false
    assertFailsWith<IOException> {
      withForegroundLease(
        start = {
          active = true
          throw IOException("Foreground service not allowed")
        },
        stop = { active = false },
        operation = { ranGit = true },
      )
    }

    assertTrue(!active)
    assertTrue(!ranGit)
  }

  @Test
  fun cancellationStillReleasesForegroundProtection(): Unit = runBlocking {
    var active = false
    assertFailsWith<CancellationException> {
      withForegroundLease(
        start = { active = true },
        stop = { active = false },
        operation = { throw CancellationException("Activity destroyed") },
      )
    }
    assertTrue(!active)
  }
}
