/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.settings

import androidx.core.content.edit
import app.passwordstore.data.crypto.ExternalSshKey
import com.github.ivanshafran.sharedpreferencesmock.SPMockBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class ExternalSshSettingsTest {
  @get:Rule val tempFolder = TemporaryFolder()

  @Test
  fun existingModeRemainsTheDefault() {
    val prefs = SPMockBuilder().createSharedPreferences()
    val settings =
      GitSettings(prefs, SPMockBuilder().createSharedPreferences(), tempFolder.root.path)
    assertEquals(AuthMode.SshKey, settings.authMode)
    assertNull(settings.externalSshKey)
  }

  @Test
  fun externalSelectionDoesNotOverwriteLocalKeys() {
    val prefs = SPMockBuilder().createSharedPreferences()
    prefs.edit {
      putString(PreferenceKeys.GIT_REMOTE_KEY_TYPE, "imported")
      putLong(PreferenceKeys.SSH_PGP_KEY_ID, 123L)
    }
    val settings =
      GitSettings(prefs, SPMockBuilder().createSharedPreferences(), tempFolder.root.path)
    val key = ExternalSshKey("org.openkeychain", "77", "ssh-ed25519 AAAA")
    settings.saveExternalSshKey(key)
    assertEquals(key, settings.externalSshKey)
    assertIs<GitSettings.UpdateConnectionSettingsResult.Valid>(
      settings.updateConnectionSettingsIfValid(
        AuthMode.SshKey,
        AuthMode.ExternalSsh,
        "ssh://git@example.com/repo.git",
      )
    )
    assertEquals(AuthMode.ExternalSsh, settings.authMode)
    assertIs<GitSettings.UpdateConnectionSettingsResult.Valid>(
      settings.updateConnectionSettingsIfValid(
        AuthMode.ExternalSsh,
        AuthMode.SshKey,
        "ssh://git@example.com/repo.git",
      )
    )
    assertEquals(key, settings.externalSshKey)
    assertEquals("imported", prefs.getString(PreferenceKeys.GIT_REMOTE_KEY_TYPE, null))
    assertEquals(123L, prefs.getLong(PreferenceKeys.SSH_PGP_KEY_ID, 0L))
  }

  @Test
  fun stagedProviderKeyIsNotPersistedUntilValidSave() {
    val prefs = SPMockBuilder().createSharedPreferences()
    val settings =
      GitSettings(prefs, SPMockBuilder().createSharedPreferences(), tempFolder.root.path)
    val original = ExternalSshKey("original.provider", "first", "ssh-ed25519 original")
    val replacement = ExternalSshKey("new.provider", "second", "ssh-ed25519 replacement")
    settings.saveExternalSshKey(original)

    // Cancelling the chooser, leaving the Activity, or invalid URL validation must not
    // persist the staged key: the only write occurs on a successful Save.
    assertEquals(original, settings.externalSshKey)
    assertIs<GitSettings.UpdateConnectionSettingsResult.AuthModeMismatch>(
      settings.updateConnectionSettingsIfValid(
        AuthMode.SshKey,
        AuthMode.ExternalSsh,
        "https://example.com/repo.git",
        selectedExternalSshKey = replacement,
      )
    )
    assertEquals(original, settings.externalSshKey)
    assertEquals(AuthMode.SshKey, settings.authMode)

    assertIs<GitSettings.UpdateConnectionSettingsResult.Valid>(
      settings.updateConnectionSettingsIfValid(
        AuthMode.SshKey,
        AuthMode.ExternalSsh,
        "ssh://git@example.com/repo.git",
        selectedExternalSshKey = replacement,
      )
    )
    assertEquals(replacement, settings.externalSshKey)
    assertEquals(AuthMode.ExternalSsh, settings.authMode)
  }

  @Test
  fun externalSshIsRejectedForHttps() {
    val settings =
      GitSettings(
        SPMockBuilder().createSharedPreferences(),
        SPMockBuilder().createSharedPreferences(),
        tempFolder.root.path,
      )
    assertIs<GitSettings.UpdateConnectionSettingsResult.AuthModeMismatch>(
      settings.updateConnectionSettingsIfValid(
        AuthMode.SshKey,
        AuthMode.ExternalSsh,
        "https://example.com/repo.git",
      )
    )
    assertEquals(AuthMode.SshKey, settings.authMode)
  }
}
