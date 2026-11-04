/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.git.config

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import android.view.View
import androidx.core.os.postDelayed
import androidx.core.view.isVisible
import androidx.core.widget.doOnTextChanged
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.data.crypto.ExternalSshApiBackend
import app.passwordstore.data.crypto.ExternalSshKey
import app.passwordstore.data.crypto.OpenPgpApiBackend
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.ActivityGitCloneBinding
import app.passwordstore.ui.dialogs.BasicBottomSheet
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.git.sshj.normalizeExternalSshPublicKey
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.Protocol
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

/**
 * Activity that encompasses both the initial clone as well as editing the server config for future
 * changes.
 */
class GitServerConfigActivity : BaseGitActivity() {

  private val binding by viewBinding(ActivityGitCloneBinding::inflate)

  private val sshProviderBackend by
    lazy(LazyThreadSafetyMode.NONE) {
      ExternalSshApiBackend(applicationContext)
    }

  private lateinit var oldAuthMode: AuthMode
  private lateinit var newAuthMode: AuthMode
  private var stagedExternalSshKey: ExternalSshKey? = null
  private var selectingExternalSshKey = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdgeView(binding.root)
    val isClone = intent?.extras?.getBoolean("cloning") ?: false
    if (isClone) {
      binding.saveButton.text = getString(R.string.clone_button)
    }
    setContentView(binding.root)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)

    oldAuthMode = gitSettings.authMode
    newAuthMode =
      savedInstanceState?.getString(STATE_AUTH_MODE)?.let(AuthMode::fromString)
        ?: gitSettings.authMode
    stagedExternalSshKey = savedInstanceState?.let { state ->
      val provider = state.getString(STATE_PROVIDER_PACKAGE)
      val keyId = state.getString(STATE_PROVIDER_KEY_ID)
      val publicKey = state.getString(STATE_PROVIDER_PUBLIC_KEY)
      if (provider != null && keyId != null && publicKey != null)
        ExternalSshKey(provider, keyId, publicKey)
      else null
    }

    binding.authModeGroup.apply {
      when (newAuthMode) {
        AuthMode.SshKey -> check(binding.authModeSshKey.id)
        AuthMode.ExternalSsh -> check(binding.authModeExternalSsh.id)
        AuthMode.Password -> check(binding.authModePassword.id)
        AuthMode.None -> clearChecked()
      }
      addOnButtonCheckedListener { _, _, _ ->
        if (checkedButtonIds.isEmpty()) {
          newAuthMode = AuthMode.None
        } else {
          when (checkedButtonId) {
            binding.authModeSshKey.id -> newAuthMode = AuthMode.SshKey
            binding.authModeExternalSsh.id -> newAuthMode = AuthMode.ExternalSsh
            binding.authModePassword.id -> newAuthMode = AuthMode.Password
            View.NO_ID -> newAuthMode = AuthMode.None
          }
        }
        updateExternalSshKeyButton()
      }
    }

    binding.selectExternalSshKey.setOnClickListener { selectExternalSshKey() }
    updateExternalSshKeyButton()

    binding.serverUrl.setText(
      gitSettings.url.also {
        if (it.isNullOrEmpty()) return@also
        setAuthModes(it.startsWith("http://") || it.startsWith("https://"))
      }
    )

    binding.serverUrl.doOnTextChanged { text, _, _, _ ->
      if (text.isNullOrEmpty()) return@doOnTextChanged
      setAuthModes(text.startsWith("http://") || text.startsWith("https://"))
    }

    binding.clearHostKeyButton.isVisible = gitSettings.hasSavedHostKey()
    binding.clearHostKeyButton.setOnClickListener {
      gitSettings.clearSavedHostKey()
      Snackbar.make(
          binding.root,
          getString(R.string.clear_saved_host_key_success),
          Snackbar.LENGTH_LONG,
        )
        .show()
      it.isVisible = false
    }

    binding.showServerResponse.isChecked = gitSettings.showSshServerResponse
    binding.showServerResponse.visibility =
      gitSettings.url.let {
        if (it.isNullOrEmpty() || !it.startsWith("http://") && !it.startsWith("https://"))
          View.VISIBLE
        else View.GONE
      }
    binding.showServerResponse.setOnCheckedChangeListener { _, isChecked ->
      gitSettings.showSshServerResponse = isChecked
    }

    binding.saveButton.setOnClickListener {
      val newUrl = binding.serverUrl.text.toString().trim()
      if (newUrl.startsWith("git://")) {
        BasicBottomSheet.Builder(this)
          .setTitleRes(R.string.git_scheme_disallowed_title)
          .setMessageRes(R.string.git_scheme_disallowed_message)
          .setPositiveButtonClickListener {}
          .build()
          .show(supportFragmentManager, "SSH_SCHEME_WARNING")
        return@setOnClickListener
      }
      if (
        newAuthMode == AuthMode.ExternalSsh &&
          (stagedExternalSshKey ?: gitSettings.externalSshKey) == null
      ) {
        showExternalSshError(getString(R.string.external_ssh_select_key_first))
        return@setOnClickListener
      }
      when (
        val updateResult =
          gitSettings.updateConnectionSettingsIfValid(
            oldAuthMode = oldAuthMode,
            newAuthMode = newAuthMode,
            newUrl = newUrl,
            selectedExternalSshKey = stagedExternalSshKey,
          )
      ) {
        GitSettings.UpdateConnectionSettingsResult.FailedToParseUrl -> {
          Snackbar.make(
              binding.root,
              getString(R.string.git_server_config_save_error),
              Snackbar.LENGTH_LONG,
            )
            .show()
        }
        is GitSettings.UpdateConnectionSettingsResult.MissingUsername -> {
          when (updateResult.newProtocol) {
            Protocol.Https ->
              BasicBottomSheet.Builder(this)
                .setTitleRes(R.string.ssh_scheme_needed_title)
                .setMessageRes(R.string.git_server_config_save_missing_username_https)
                .setPositiveButtonClickListener {}
                .build()
                .show(supportFragmentManager, "HTTPS_MISSING_USERNAME")
            Protocol.Ssh ->
              BasicBottomSheet.Builder(this)
                .setTitleRes(R.string.ssh_scheme_needed_title)
                .setMessageRes(R.string.git_server_config_save_missing_username_ssh)
                .setPositiveButtonClickListener {}
                .build()
                .show(supportFragmentManager, "SSH_MISSING_USERNAME")
          }
        }
        GitSettings.UpdateConnectionSettingsResult.Valid -> {
          stagedExternalSshKey = null
          if (isClone && PasswordRepository.repository == null) PasswordRepository.initialize()
          if (!isClone) {
            Snackbar.make(
                binding.root,
                getString(R.string.git_server_config_save_success),
                Snackbar.LENGTH_SHORT,
              )
              .show()
            Handler(Looper.getMainLooper()).postDelayed(500) { finish() }
          } else {
            cloneRepository()
          }
        }
        is GitSettings.UpdateConnectionSettingsResult.AuthModeMismatch -> {
          val message =
            getString(
              R.string.git_server_config_save_auth_mode_mismatch,
              updateResult.newProtocol,
              updateResult.validModes.joinToString(", "),
            )
          Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG).show()
        }
      }
    }

    // The old Activity's coroutine cannot be resumed after recreation. The restored
    // ActivityResult launcher may receive a stale provider result with no waiting continuation,
    // so explicitly offer retry instead of silently ignoring an unfinished selection.
    if (savedInstanceState?.getBoolean(STATE_SELECTING_KEY) == true) {
      binding.root.post {
        if (!isFinishing) {
          showExternalSshError(getString(R.string.external_ssh_selection_interrupted))
        }
      }
    }
  }

  override fun onSaveInstanceState(outState: Bundle) {
    outState.putString(STATE_AUTH_MODE, newAuthMode.pref)
    outState.putBoolean(STATE_SELECTING_KEY, selectingExternalSshKey)
    stagedExternalSshKey?.let { key ->
      outState.putString(STATE_PROVIDER_PACKAGE, key.providerPackage)
      outState.putString(STATE_PROVIDER_KEY_ID, key.keyId)
      outState.putString(STATE_PROVIDER_PUBLIC_KEY, key.publicKey)
    }
    super.onSaveInstanceState(outState)
  }

  override fun onRestoreInstanceState(savedInstanceState: Bundle) {
    super.onRestoreInstanceState(savedInstanceState)
    // Text and button selections are restored by Android after onCreate.
    setAuthModes(binding.serverUrl.text.toString().startsWith("http"))
    updateExternalSshKeyButton()
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    return when (item.itemId) {
      android.R.id.home -> {
        onBackPressedDispatcher.onBackPressed()
        true
      }
      else -> super.onOptionsItemSelected(item)
    }
  }

  private fun updateExternalSshKeyButton() {
    binding.selectExternalSshKey.isVisible =
      newAuthMode == AuthMode.ExternalSsh && !binding.serverUrl.text.toString().startsWith("http")
    val selected = stagedExternalSshKey ?: gitSettings.externalSshKey
    binding.selectExternalSshKey.text =
      selected?.let { getString(R.string.external_ssh_key_selected, it.keyId) }
        ?: getString(R.string.external_ssh_select_key)
  }

  private fun selectExternalSshKey() {
    val providers = sshProviderBackend.providers()
    if (providers.isEmpty()) {
      showExternalSshError(getString(R.string.external_ssh_no_provider))
      return
    }
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.external_ssh_select_provider)
      .setItems(providers.map { it.label + " (" + it.packageName + ")" }.toTypedArray()) {
        _,
        selected ->
        val provider = providers[selected]
        setExternalSshSelectionBusy(true)
        lifecycleScope.launch {
          try {
            when (
              val key =
                sshProviderBackend.selectKey(
                  provider.packageName,
                  externalSshInteractionHandler,
                )
            ) {
              is OpenPgpApiBackend.OperationResult.Success -> {
                when (
                  val publicKey =
                    sshProviderBackend.publicKey(
                      provider.packageName,
                      key.value.keyId,
                      externalSshInteractionHandler,
                    )
                ) {
                  is OpenPgpApiBackend.OperationResult.Success -> {
                    val normalized = normalizeExternalSshPublicKey(publicKey.value)
                    stagedExternalSshKey =
                      ExternalSshKey(provider.packageName, key.value.keyId, normalized)
                    updateExternalSshKeyButton()
                  }
                  OpenPgpApiBackend.OperationResult.Cancelled -> Unit
                  is OpenPgpApiBackend.OperationResult.Failure ->
                    showExternalSshError(publicKey.error.message ?: getString(R.string.error))
                  is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
                    showExternalSshError(getString(R.string.openpgp_provider_interaction_failed))
                }
              }
              OpenPgpApiBackend.OperationResult.Cancelled -> Unit
              is OpenPgpApiBackend.OperationResult.Failure ->
                showExternalSshError(key.error.message ?: getString(R.string.error))
              is OpenPgpApiBackend.OperationResult.UserInteractionRequired ->
                showExternalSshError(getString(R.string.openpgp_provider_interaction_failed))
            }
          } catch (error: CancellationException) {
            throw error
          } catch (error: Exception) {
            showExternalSshError(error.message ?: getString(R.string.error))
          } finally {
            setExternalSshSelectionBusy(false)
          }
        }
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }

  private fun setExternalSshSelectionBusy(busy: Boolean) {
    selectingExternalSshKey = busy
    binding.selectExternalSshKey.isEnabled = !busy
    binding.saveButton.isEnabled = !busy
  }

  private fun showExternalSshError(message: String) {
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.external_ssh_select_provider)
      .setMessage(message)
      .setPositiveButton(R.string.dialog_ok, null)
      .show()
  }

  private fun setAuthModes(isHttps: Boolean) =
    with(binding) {
      if (isHttps) {
        authModeSshKey.isVisible = false
        authModeExternalSsh.isVisible = false
        selectExternalSshKey.isVisible = false
        authModePassword.isVisible = true
        showServerResponse.visibility = View.GONE
        gitSettings.showSshServerResponse = true
        if (authModeGroup.checkedButtonId != authModePassword.id) authModeGroup.clearChecked()
      } else {
        authModeSshKey.isVisible = true
        authModeExternalSsh.isVisible = true
        authModePassword.isVisible = true
        showServerResponse.visibility = View.VISIBLE
        showServerResponse.isChecked = gitSettings.showSshServerResponse
        if (authModeGroup.checkedButtonId == View.NO_ID) authModeGroup.check(authModeSshKey.id)
        updateExternalSshKeyButton()
      }
    }

  /** Clones the repository, the directory exists, deletes it */
  private fun cloneRepository() {
    val localDir =
      requireNotNull(PasswordRepository.getRepositoryDirectory()) {
        "Repository directory must be set before cloning"
      }
    val localDirFiles = localDir.listFiles() ?: emptyArray()
    // Warn if non-empty folder unless it's a just-initialized store that has just a .git folder
    if (
      localDir.exists() &&
        localDirFiles.isNotEmpty() &&
        !(localDirFiles.size == 1 && localDirFiles[0].name == ".git")
    ) {
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.dialog_delete_title)
        .setMessage(resources.getString(R.string.dialog_delete_msg, localDir.toString()))
        .setCancelable(false)
        .setPositiveButton(R.string.dialog_delete) { dialog, _ ->
          runCatching {
            lifecycleScope.launch {
              val snackbar =
                snackbar(
                  message = getString(R.string.delete_directory_progress_text),
                  length = Snackbar.LENGTH_INDEFINITE,
                )
              withContext(dispatcherProvider.io()) {
                localDir.deleteRecursively()
                localDir.mkdirs()
              }
              snackbar.dismiss()
              launchGitOperation(GitOp.CLONE)
                .fold(
                  success = {
                    setResult(RESULT_OK)
                    finish()
                  },
                  failure = { err -> promptOnErrorHandler(err) { finish() } },
                )
            }
          }
            .onErr { e ->
              e.printStackTrace()
              MaterialAlertDialogBuilder(this).setMessage(e.message).show()
            }
          dialog.cancel()
        }
        .setNegativeButton(R.string.dialog_do_not_delete) { dialog, _ -> dialog.cancel() }
        .show()
    } else {
      runCatching {
        // Silently delete & replace the lone .git folder if it exists
        if (localDir.exists() && localDirFiles.size == 1 && localDirFiles[0].name == ".git") {
          localDir.deleteRecursively()
        }
      }
        .onErr { e ->
          logcat(ERROR) { e.asLog() }
          MaterialAlertDialogBuilder(this).setMessage(e.message).show()
        }
      lifecycleScope.launch {
        launchGitOperation(GitOp.CLONE)
          .fold(
            success = {
              setResult(RESULT_OK)
              finish()
            },
            failure = { promptOnErrorHandler(it) },
          )
      }
    }
  }

  companion object {
    private const val STATE_AUTH_MODE = "git_config_auth_mode"
    private const val STATE_SELECTING_KEY = "git_config_selecting_external_ssh_key"
    private const val STATE_PROVIDER_PACKAGE = "git_config_external_ssh_provider"
    private const val STATE_PROVIDER_KEY_ID = "git_config_external_ssh_key_id"
    private const val STATE_PROVIDER_PUBLIC_KEY = "git_config_external_ssh_public_key"

    fun createCloneIntent(context: Context): Intent {
      return Intent(context, GitServerConfigActivity::class.java).apply {
        putExtra("cloning", true)
      }
    }
  }
}
