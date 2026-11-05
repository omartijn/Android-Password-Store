/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import app.passwordstore.R
import app.passwordstore.ui.main.LaunchActivity
import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * Foreground execution protection for a user-initiated, interactive Git transfer.
 *
 * External SSH providers open their own Activity for PIN/NFC interaction, taking Password Store out
 * of the foreground. Some Android network policies tear down its TCP sockets at that point. This
 * service owns no Git state: the existing Activity/JGit/SSHJ stack still performs the transfer, and
 * the service is held only until that operation finishes.
 */
class InteractiveGitForegroundService : Service() {
  internal val foregroundReady = CompletableDeferred<Unit>()

  inner class LocalBinder : Binder() {
    val service: InteractiveGitForegroundService
      get() = this@InteractiveGitForegroundService
  }

  private val localBinder = LocalBinder()

  override fun onBind(intent: Intent?): IBinder = localBinder

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    try {
      val manager = getSystemService(NotificationManager::class.java)
      manager.createNotificationChannel(
        NotificationChannel(
          CHANNEL_ID,
          getString(R.string.git_foreground_channel),
          NotificationManager.IMPORTANCE_LOW,
        )
      )
      val openApp =
        PendingIntent.getActivity(
          this,
          0,
          Intent(this, LaunchActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
          PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
      val notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
          .setSmallIcon(R.drawable.ic_cloud_sync_48dp)
          .setContentTitle(getString(R.string.git_foreground_title))
          .setContentText(getString(R.string.git_foreground_description))
          .setContentIntent(openApp)
          .setCategory(NotificationCompat.CATEGORY_PROGRESS)
          .setOnlyAlertOnce(true)
          .setOngoing(true)
          .setSilent(true)
          .build()

      ServiceCompat.startForeground(
        this,
        NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
      )
      foregroundReady.complete(Unit)
    } catch (error: Exception) {
      foregroundReady.completeExceptionally(error)
      stopSelf(startId)
    }
    // Never restore an orphaned service after process death: the old Git operation is gone.
    return START_NOT_STICKY
  }

  override fun onDestroy() {
    if (!foregroundReady.isCompleted) {
      foregroundReady.completeExceptionally(IOException("Interactive Git service stopped"))
    }
    super.onDestroy()
  }

  override fun onTimeout(startId: Int, fgsType: Int) {
    stopSelf(startId)
  }

  companion object {
    internal const val CHANNEL_ID = "interactive_git_sync"
    internal const val NOTIFICATION_ID = 2431
  }
}

/**
 * A foreground lease is always released, including failure to start partway through the
 * acquisition and coroutine cancellation. The caller controls the actual service operations.
 */
internal suspend fun <T> withForegroundLease(
  start: suspend () -> Unit,
  stop: suspend () -> Unit,
  operation: suspend () -> T,
): T =
  try {
    start()
    operation()
  } finally {
    withContext(NonCancellable) { stop() }
  }

/**
 * Start while the Git Activity is visible, and wait until Android has acknowledged foreground
 * service promotion before opening the SSH connection or launching the provider's PIN/NFC UI.
 *
 * Binding is used solely as a readiness handshake. Always unbind and stop the started service
 * (including coroutine cancellation) to avoid leaving a long-lived notification behind.
 */
internal suspend fun <T> withInteractiveGitForeground(
  context: Context,
  operation: suspend () -> T,
): T {
  val application = context.applicationContext
  return withContext(Dispatchers.Main.immediate) {
    val serviceIntent = Intent(application, InteractiveGitForegroundService::class.java)
    val connected = CompletableDeferred<InteractiveGitForegroundService>()
    val connection =
      object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
          val local = binder as? InteractiveGitForegroundService.LocalBinder
          if (local == null) {
            connected.completeExceptionally(IOException("Unexpected interactive Git binder"))
          } else {
            connected.complete(local.service)
          }
        }

        override fun onServiceDisconnected(name: ComponentName) {
          if (!connected.isCompleted) {
            connected.completeExceptionally(IOException("Interactive Git service disconnected"))
          }
        }
      }

    var started = false
    var bound = false
    withForegroundLease(
      start = {
        ContextCompat.startForegroundService(application, serviceIntent)
        started = true
        bound = application.bindService(serviceIntent, connection, Context.BIND_AUTO_CREATE)
        if (!bound) throw IOException("Unable to bind interactive Git foreground service")
        try {
          withTimeout(10_000L) { connected.await().foregroundReady.await() }
        } catch (error: TimeoutCancellationException) {
          throw IOException("Timed out starting interactive Git foreground service", error)
        }
      },
      stop = {
        try {
          if (bound) application.unbindService(connection)
        } finally {
          if (started) application.stopService(serviceIntent)
        }
      },
      operation = operation,
    )
  }
}
