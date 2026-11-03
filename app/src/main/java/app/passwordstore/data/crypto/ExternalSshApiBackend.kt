/*
 * Copyright © 2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.crypto

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ResolveInfo
import android.os.IBinder
import app.passwordstore.util.git.sshj.validateExternalSshSignature
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.IOException
import java.util.concurrent.TimeoutException
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.openintents.ssh.authentication.ISshAuthenticationService
import org.openintents.ssh.authentication.SshAuthenticationApiError

/** OpenKeychain's SSH Authentication API is distinct from its OpenPGP encryption API. */
internal object ExternalSshProtocol {
  const val SERVICE = "org.openintents.ssh.authentication.ISshAuthenticationService"
  const val SELECT_KEY = "org.openintents.ssh.action.SELECT_KEY"
  const val GET_SSH_PUBLIC_KEY = "org.openintents.ssh.action.GET_SSH_PUBLIC_KEY"
  const val SIGN = "org.openintents.ssh.action.SIGN"
  const val VERSION = "api_version"
  const val RESULT = "result_code"
  const val KEY_ID = "key_id"
  const val DESCRIPTION = "key_description"
  const val PUBLIC_KEY = "ssh_public_key"
  const val CHALLENGE = "challenge"
  const val HASH = "hash_algorithm"
  const val SIGNATURE = "signature"
  const val PENDING_INTENT = "intent"
  const val ERROR = "error"
  const val SUCCESS = 1
  const val INTERACTION_REQUIRED = 2

  // Hash values are defined by the provider API; the selected SSH algorithm determines RSA hash.
  fun hashFor(sshAlgorithm: String): Int? =
    when (sshAlgorithm) {
      "ssh-rsa" -> 0
      "rsa-sha2-256",
      "ecdsa-sha2-nistp256" -> 2
      "ecdsa-sha2-nistp384" -> 3
      "rsa-sha2-512",
      "ecdsa-sha2-nistp521",
      "ssh-ed25519" -> 4
      else -> null
    }
}

data class ExternalSshKey(
  val providerPackage: String,
  val keyId: String,
  val publicKey: String,
)

/**
 * Small adapter for provider-owned SSH keys. No private key, PIN, or key password is stored here.
 *
 * Reuses the existing Activity Result bridge and result semantics of OpenPgpApiBackend, but
 * deliberately does not confuse the SSH signing protocol with the OpenPGP decrypt protocol.
 */
class ExternalSshApiBackend internal constructor(private val executor: ExternalSshExecutor) {
  @Inject
  constructor(@ApplicationContext context: Context) : this(BinderExternalSshExecutor(context))

  data class Provider(val packageName: String, val label: String)

  data class Selection(val keyId: String, val description: String)

  fun providers(): List<Provider> = executor.providers()

  suspend fun selectKey(
    provider: String,
    handler: OpenPgpApiBackend.InteractionHandler,
  ): OpenPgpApiBackend.OperationResult<Selection> =
    execute(provider, Intent(ExternalSshProtocol.SELECT_KEY), handler) { response ->
      val keyId =
        response.getStringExtra(ExternalSshProtocol.KEY_ID)?.takeIf {
          it.isNotBlank() && it.length <= 256
        } ?: throw IOException("SSH provider returned no valid key ID")
      Selection(keyId, response.getStringExtra(ExternalSshProtocol.DESCRIPTION).orEmpty())
    }

  suspend fun publicKey(
    provider: String,
    keyId: String,
    handler: OpenPgpApiBackend.InteractionHandler,
  ): OpenPgpApiBackend.OperationResult<String> =
    execute(
      provider,
      Intent(ExternalSshProtocol.GET_SSH_PUBLIC_KEY).putExtra(ExternalSshProtocol.KEY_ID, keyId),
      handler,
    ) { response ->
      response.getStringExtra(ExternalSshProtocol.PUBLIC_KEY)?.takeIf { it.length in 1..8192 }
        ?: throw IOException("SSH provider returned no valid public key")
    }

  suspend fun sign(
    provider: String,
    keyId: String,
    challenge: ByteArray,
    sshAlgorithm: String,
    handler: OpenPgpApiBackend.InteractionHandler,
  ): OpenPgpApiBackend.OperationResult<ByteArray> {
    val hash =
      ExternalSshProtocol.hashFor(sshAlgorithm)
        ?: return OpenPgpApiBackend.OperationResult.Failure(
          IOException("Unsupported external SSH signature algorithm: " + sshAlgorithm)
        )
    return execute(
      provider,
      Intent(ExternalSshProtocol.SIGN)
        .putExtra(ExternalSshProtocol.KEY_ID, keyId)
        .putExtra(ExternalSshProtocol.CHALLENGE, challenge)
        .putExtra(ExternalSshProtocol.HASH, hash),
      handler,
    ) { response ->
      response.getByteArrayExtra(ExternalSshProtocol.SIGNATURE)?.also {
        validateExternalSshSignature(it, sshAlgorithm)
      } ?: throw IOException("SSH provider returned no signature")
    }
  }

  private suspend fun <T> execute(
    provider: String,
    initialRequest: Intent,
    handler: OpenPgpApiBackend.InteractionHandler,
    parse: (Intent) -> T,
  ): OpenPgpApiBackend.OperationResult<T> {
    if (executor.providers().none { it.packageName == provider })
      return OpenPgpApiBackend.OperationResult.Failure(
        IOException("Selected SSH provider is unavailable: " + provider)
      )
    var request = initialRequest.putExtra(ExternalSshProtocol.VERSION, 1)
    repeat(MAX_INTERACTION_ROUNDS + 1) { round ->
      val result =
        try {
          executor.execute(provider, request)
        } catch (error: CancellationException) {
          throw error
        } catch (error: Throwable) {
          return OpenPgpApiBackend.OperationResult.Failure(error)
        }
      result.setExtrasClassLoader(SshAuthenticationApiError::class.java.classLoader)
      when (result.getIntExtra(ExternalSshProtocol.RESULT, 0)) {
        ExternalSshProtocol.SUCCESS ->
          return try {
            OpenPgpApiBackend.OperationResult.Success(parse(result))
          } catch (error: Throwable) {
            OpenPgpApiBackend.OperationResult.Failure(error)
          }
        ExternalSshProtocol.INTERACTION_REQUIRED -> {
          if (round == MAX_INTERACTION_ROUNDS)
            return OpenPgpApiBackend.OperationResult.Failure(
              IOException("SSH provider exceeded the user interaction limit")
            )
          @Suppress("DEPRECATION")
          val prompt =
            result.getParcelableExtra<PendingIntent>(ExternalSshProtocol.PENDING_INTENT)
              ?: return OpenPgpApiBackend.OperationResult.Failure(
                IOException("SSH provider requested interaction without a PendingIntent")
              )
          val interaction =
            try {
              withTimeoutOrNull(USER_INTERACTION_TIMEOUT_MS) {
                withContext(Dispatchers.Main.immediate) { handler.interact(prompt) }
              }
                ?: return OpenPgpApiBackend.OperationResult.Failure(
                  TimeoutException("Timed out waiting for SSH hardware-token interaction")
                )
            } catch (error: CancellationException) {
              throw error
            } catch (error: Throwable) {
              return OpenPgpApiBackend.OperationResult.Failure(error)
            }
          when (interaction) {
            is OpenPgpApiBackend.InteractionResult.Completed -> {
              // The provider returns the request augmented with key selection or PIN/NFC state.
              request = interaction.data ?: request
              request.putExtra(ExternalSshProtocol.VERSION, 1)
            }
            OpenPgpApiBackend.InteractionResult.Cancelled ->
              return OpenPgpApiBackend.OperationResult.Cancelled
          }
        }
        else -> {
          @Suppress("DEPRECATION")
          val error =
            result.getParcelableExtra<SshAuthenticationApiError>(ExternalSshProtocol.ERROR)
          return OpenPgpApiBackend.OperationResult.Failure(
            IOException(
              error?.message?.takeIf { it.isNotBlank() }
                ?: "SSH provider failed (error " + (error?.error?.toString() ?: "unknown") + ")"
            )
          )
        }
      }
    }
    return OpenPgpApiBackend.OperationResult.Failure(IOException("SSH provider did not complete"))
  }

  private companion object {
    const val MAX_INTERACTION_ROUNDS = 5
    const val USER_INTERACTION_TIMEOUT_MS = 180_000L
  }
}

internal interface ExternalSshExecutor {
  fun providers(): List<ExternalSshApiBackend.Provider>

  suspend fun execute(provider: String, request: Intent): Intent
}

internal class BinderExternalSshExecutor(private val context: Context) : ExternalSshExecutor {
  @Suppress("DEPRECATION")
  override fun providers(): List<ExternalSshApiBackend.Provider> =
    context.packageManager
      .queryIntentServices(Intent(ExternalSshProtocol.SERVICE), 0)
      .mapNotNull(::providerInfo)
      .distinctBy { it.packageName }

  private fun providerInfo(info: ResolveInfo): ExternalSshApiBackend.Provider? {
    val service = info.serviceInfo ?: return null
    return ExternalSshApiBackend.Provider(
      service.packageName,
      info.loadLabel(context.packageManager).toString(),
    )
  }

  override suspend fun execute(provider: String, request: Intent): Intent =
    withContext(Dispatchers.IO) {
      val pending = CompletableDeferred<ISshAuthenticationService>()
      val connection =
        object : ServiceConnection {
          override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            pending.complete(ISshAuthenticationService.Stub.asInterface(binder))
          }

          override fun onServiceDisconnected(name: ComponentName) {
            if (!pending.isCompleted)
              pending.completeExceptionally(IOException("SSH provider disconnected"))
          }
        }
      var bound = false
      try {
        bound =
          context.bindService(
            Intent(ExternalSshProtocol.SERVICE).setPackage(provider),
            connection,
            Context.BIND_AUTO_CREATE,
          )
        if (!bound) throw IOException("Could not bind to SSH provider: " + provider)
        val service =
          withTimeoutOrNull(15_000L) { pending.await() }
            ?: throw IOException("Timed out connecting to SSH provider: " + provider)
        service.execute(request)
      } finally {
        if (bound) context.unbindService(connection)
      }
    }
}
