/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.Intent
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class ExternalSshApiBackendTest {
  private fun reply(code: Int) = Intent().putExtra(ExternalSshProtocol.RESULT, code)

  private fun prompt(): PendingIntent =
    PendingIntent.getActivity(
      RuntimeEnvironment.getApplication(),
      233,
      Intent("external-ssh-prompt"),
      PendingIntent.FLAG_IMMUTABLE,
    )

  private fun fake(fn: suspend (Intent) -> Intent) =
    ExternalSshApiBackend(
      object : ExternalSshExecutor {
        override fun providers() = listOf(ExternalSshApiBackend.Provider("provider", "Test"))

        override suspend fun execute(provider: String, request: Intent): Intent {
          assertEquals("provider", provider)
          return fn(request)
        }
      }
    )

  private fun handler(answer: Intent?): OpenPgpApiBackend.InteractionHandler =
    OpenPgpApiBackend.InteractionHandler {
      if (answer == null) OpenPgpApiBackend.InteractionResult.Cancelled
      else OpenPgpApiBackend.InteractionResult.Completed(answer)
    }

  private fun signature(name: String): ByteArray {
    val alg = name.toByteArray(Charsets.US_ASCII)
    return ByteBuffer.allocate(4 + alg.size + 4 + 2)
      .putInt(alg.size)
      .put(alg)
      .putInt(2)
      .put(byteArrayOf(1, 2))
      .array()
  }

  @Test
  fun chooserContinuesWithReturnedIntentThroughTwoPrompts(): Unit = runBlocking {
    val requests = mutableListOf<Intent>()
    val api = fake { req ->
      requests += req
      if (requests.size <= 2)
        reply(ExternalSshProtocol.INTERACTION_REQUIRED)
          .putExtra(ExternalSshProtocol.PENDING_INTENT, prompt())
      else
        reply(ExternalSshProtocol.SUCCESS)
          .putExtra(ExternalSshProtocol.KEY_ID, req.getStringExtra(ExternalSshProtocol.KEY_ID))
    }
    val continued =
      Intent(ExternalSshProtocol.SELECT_KEY).putExtra(ExternalSshProtocol.KEY_ID, "key-id")
    val result = api.selectKey("provider", handler(continued))
    assertEquals(
      "key-id",
      assertIs<OpenPgpApiBackend.OperationResult.Success<ExternalSshApiBackend.Selection>>(result)
        .value
        .keyId,
    )
    assertEquals(3, requests.size)
    assertEquals(continued, requests[2])
  }

  @Test
  fun cancellationStopsSigning(): Unit = runBlocking {
    var calls = 0
    val api = fake {
      calls++
      reply(ExternalSshProtocol.INTERACTION_REQUIRED)
        .putExtra(ExternalSshProtocol.PENDING_INTENT, prompt())
    }
    assertIs<OpenPgpApiBackend.OperationResult.Cancelled>(
      api.sign("provider", "1", byteArrayOf(1), "ssh-ed25519", handler(null))
    )
    assertEquals(1, calls)
  }

  @Test
  fun repeatedProviderPromptsAreBounded(): Unit = runBlocking {
    var calls = 0
    val api = fake {
      calls++
      reply(ExternalSshProtocol.INTERACTION_REQUIRED)
        .putExtra(ExternalSshProtocol.PENDING_INTENT, prompt())
    }
    assertIs<OpenPgpApiBackend.OperationResult.Failure>(
      api.selectKey("provider", handler(Intent(ExternalSshProtocol.SELECT_KEY)))
    )
    assertEquals(6, calls)
  }

  @Test
  fun selectedRsaHashAndSignatureArePreserved(): Unit = runBlocking {
    var hash = -1
    val signed = signature("rsa-sha2-512")
    val api = fake { request ->
      hash = request.getIntExtra(ExternalSshProtocol.HASH, -1)
      assertContentEquals(
        byteArrayOf(7, 8),
        request.getByteArrayExtra(ExternalSshProtocol.CHALLENGE),
      )
      reply(ExternalSshProtocol.SUCCESS).putExtra(ExternalSshProtocol.SIGNATURE, signed)
    }
    val result = api.sign("provider", "1", byteArrayOf(7, 8), "rsa-sha2-512", handler(null))
    assertContentEquals(
      signed,
      assertIs<OpenPgpApiBackend.OperationResult.Success<ByteArray>>(result).value,
    )
    assertEquals(4, hash)
  }

  @Test
  fun invalidSignatureFailsClosed(): Unit = runBlocking {
    val api = fake {
      reply(ExternalSshProtocol.SUCCESS)
        .putExtra(ExternalSshProtocol.SIGNATURE, signature("ssh-rsa"))
    }
    assertIs<OpenPgpApiBackend.OperationResult.Failure>(
      api.sign("provider", "1", byteArrayOf(1), "rsa-sha2-256", handler(null))
    )
  }

  @Test
  fun removedProviderFailsWithoutAttemptingToSign(): Unit = runBlocking {
    var called = false
    val api =
      ExternalSshApiBackend(
        object : ExternalSshExecutor {
          override fun providers() = emptyList<ExternalSshApiBackend.Provider>()

          override suspend fun execute(provider: String, request: Intent): Intent {
            called = true
            return reply(ExternalSshProtocol.SUCCESS)
          }
        }
      )
    assertIs<OpenPgpApiBackend.OperationResult.Failure>(
      api.sign("missing", "key", byteArrayOf(1), "ssh-ed25519", handler(null))
    )
    assertTrue(!called)
  }

  @Test
  fun providerReinstallAllowsTheNextPublicKeyRequest(): Unit = runBlocking {
    var installed = false
    var calls = 0
    val api =
      ExternalSshApiBackend(
        object : ExternalSshExecutor {
          override fun providers() =
            if (installed) listOf(ExternalSshApiBackend.Provider("provider", "Test"))
            else emptyList()

          override suspend fun execute(provider: String, request: Intent): Intent {
            calls++
            assertEquals(ExternalSshProtocol.GET_SSH_PUBLIC_KEY, request.action)
            return reply(ExternalSshProtocol.SUCCESS)
              .putExtra(ExternalSshProtocol.PUBLIC_KEY, "ssh-ed25519 public-key")
          }
        }
      )

    assertIs<OpenPgpApiBackend.OperationResult.Failure>(
      api.publicKey("provider", "key", handler(null))
    )
    assertEquals(0, calls)
    installed = true
    val result = api.publicKey("provider", "key", handler(null))
    assertEquals(
      "ssh-ed25519 public-key",
      assertIs<OpenPgpApiBackend.OperationResult.Success<String>>(result).value,
    )
    assertEquals(1, calls)
  }

  @Test
  fun blockingBinderResponseIsTimedOutAndWorkerIsInterrupted(): Unit = runBlocking {
    val started = CountDownLatch(1)
    val finished = CountDownLatch(1)
    val executor = BoundedExternalSshCalls(timeoutMs = 250L, maxConcurrentCalls = 1)

    val error =
      kotlin.test.assertFailsWith<IOException> {
        executor.execute {
          started.countDown()
          try {
            Thread.sleep(10_000)
          } finally {
            finished.countDown()
          }
          Intent()
        }
      }

    assertTrue(error.message.orEmpty().contains("Timed out waiting for SSH provider response"))
    assertTrue(started.await(1, TimeUnit.SECONDS))
    // Binder itself may not cooperate with interruption, but the bounded pool ensures
    // no unbounded worker growth. This simulated blocking call *does* cooperate.
    assertTrue(finished.await(2, TimeUnit.SECONDS))
  }

  @Test
  fun unsupportedAlgorithmNeverContactsProvider(): Unit = runBlocking {
    var called = false
    val api = fake {
      called = true
      reply(ExternalSshProtocol.SUCCESS)
    }
    assertIs<OpenPgpApiBackend.OperationResult.Failure>(
      api.sign("provider", "1", byteArrayOf(1), "ssh-dss", handler(null))
    )
    assertTrue(!called)
  }
}
