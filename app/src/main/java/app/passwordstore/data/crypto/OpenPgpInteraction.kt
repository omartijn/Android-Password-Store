/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.app.Activity
import android.app.PendingIntent
import androidx.activity.ComponentActivity
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts.StartIntentSenderForResult
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * Makes a foreground OpenPGP interaction handler available only to the coroutine tree that owns it.
 *
 * This is deliberately coroutine-scoped rather than process-global. Credential-provider metadata
 * scans can run concurrently with a foreground assertion and must never consume that assertion's
 * provider interaction.
 */
@Singleton
class OpenPgpInteractionCoordinator @Inject constructor() {

  private val currentHandler = ThreadLocal<OpenPgpApiBackend.InteractionHandler?>()

  suspend fun <T> withHandler(
    handler: OpenPgpApiBackend.InteractionHandler,
    block: suspend () -> T,
  ): T = withContext(currentHandler.asContextElement(handler)) { block() }

  suspend fun interact(pendingIntent: PendingIntent): OpenPgpApiBackend.InteractionResult {
    val handler = currentHandler.get() ?: return OpenPgpApiBackend.InteractionResult.Cancelled
    return handler.interact(pendingIntent)
  }
}

/** Activity Result API bridge used by password and Credential Provider activities. */
class OpenPgpActivityInteractionHandler(
  activity: ComponentActivity,
  private val onOrphanedResult: (() -> Unit)? = null,
) : OpenPgpApiBackend.InteractionHandler {

  private val waiting =
    AtomicReference<
      kotlinx.coroutines.CancellableContinuation<OpenPgpApiBackend.InteractionResult>?
    >(
      null
    )

  private val launcher =
    activity.registerForActivityResult(StartIntentSenderForResult()) { result ->
      val continuation = waiting.getAndSet(null)
      if (continuation == null) {
        // Android can deliver a saved ActivityResult after recreating the Activity, but the
        // original coroutine/continuation belongs to the destroyed instance. Never mistake
        // that stale result for a successful current operation.
        onOrphanedResult?.invoke()
        return@registerForActivityResult
      }
      if (!continuation.isActive) return@registerForActivityResult
      if (result.resultCode == Activity.RESULT_OK) {
        continuation.resume(OpenPgpApiBackend.InteractionResult.Completed(result.data))
      } else {
        continuation.resume(OpenPgpApiBackend.InteractionResult.Cancelled)
      }
    }

  override suspend fun interact(pendingIntent: PendingIntent): OpenPgpApiBackend.InteractionResult =
    suspendCancellableCoroutine { continuation ->
      check(waiting.compareAndSet(null, continuation)) {
        "Another OpenPGP provider interaction is already active"
      }
      continuation.invokeOnCancellation { waiting.compareAndSet(continuation, null) }
      try {
        launcher.launch(IntentSenderRequest.Builder(pendingIntent.intentSender).build())
      } catch (error: Throwable) {
        if (waiting.compareAndSet(continuation, null) && continuation.isActive) {
          continuation.resumeWithException(error)
        }
      }
    }
}
