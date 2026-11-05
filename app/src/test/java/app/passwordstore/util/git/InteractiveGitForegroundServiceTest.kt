/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git

import android.app.NotificationManager
import android.app.Service
import android.content.ComponentName
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class InteractiveGitForegroundServiceTest {

  @Test
  fun serviceBecomesForegroundBeforeGitMayStart(): Unit = runBlocking {
    val controller = Robolectric.buildService(InteractiveGitForegroundService::class.java).create()
    val service = controller.get()
    try {
      assertEquals(Service.START_NOT_STICKY, service.onStartCommand(null, 0, 1))
      // Also propagates a foreground-service promotion failure rather than allowing SSH
      // to connect without protection.
      service.foregroundReady.await()
      val notifications = service.getSystemService(NotificationManager::class.java)
      assertNotNull(
        notifications.getNotificationChannel(InteractiveGitForegroundService.CHANNEL_ID)
      )
    } finally {
      controller.destroy()
    }
  }

  @Test
  @Suppress("DEPRECATION")
  fun manifestDeclaresTheRequiredDataSyncForegroundType() {
    val application = RuntimeEnvironment.getApplication()
    val info =
      application.packageManager.getServiceInfo(
        ComponentName(application, InteractiveGitForegroundService::class.java),
        PackageManager.GET_META_DATA,
      )
    assertTrue(info.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC != 0)
  }
}
