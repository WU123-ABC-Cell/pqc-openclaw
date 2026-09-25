package ai.openclaw.app.gateway

import ai.openclaw.app.SecurePrefs
import android.content.Context
import android.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.MessageDigest

/** Persistent ML-DSA-65 identity used to register this Android node with PQC gateways. */
@Serializable
data class DeviceIdentity(
  val deviceId: String,
  val publicKeyRawBase64: String,
  val privateKeyRawBase64: String,
  val createdAtMs: Long,
)

/** Owns device identity generation, persistence, and auth payload signatures. */
class DeviceIdentityStore private constructor(
  context: Context,
  private val prefs: SecurePrefs,
  private val identityWriter: ((String) -> Boolean)? = null,
) {
  constructor(context: Context) : this(context, SecurePrefs(context))

  private val json = Json { ignoreUnknownKeys = true }
  private val legacyIdentityFile = File(context.filesDir, "openclaw/identity/device.json")

  @Volatile private var cachedIdentity: DeviceIdentity? = null

  /** Loads the persisted identity or creates one, repairing old device-id drift. */
  @Synchronized
  fun loadOrCreate(): DeviceIdentity {
    cachedIdentity?.let { return it }
    val existing = load()
    if (existing != null) {
      val derived = deriveDeviceId(existing.publicKeyRawBase64)
      if (derived != null && derived != existing.deviceId) {
        val updated = existing.copy(deviceId = derived)
        save(updated)
        check(load() == updated) { "Failed to verify persisted device identity" }
        retireLegacyIdentity()
        cachedIdentity = updated
        return updated
      }
      retireLegacyIdentity()
      cachedIdentity = existing
      return existing
    }
    val fresh = generate()
    save(fresh)
    check(load() == fresh) { "Failed to verify persisted device identity" }
    retireLegacyIdentity()
    cachedIdentity = fresh
    return fresh
  }

  /** Signs gateway connect payload text with the persisted ML-DSA-65 private key. */
  fun signPayload(
    payload: String,
    identity: DeviceIdentity,
  ): String? =
    try {
      val rawPrivate = Base64.decode(identity.privateKeyRawBase64, Base64.DEFAULT)
      val privateKey =
        org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters(
          org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
          rawPrivate,
        )
      val signer =
        org.bouncycastle.crypto.signers
          .MLDSASigner()
      signer.init(
        true,
        org.bouncycastle.crypto.params.ParametersWithRandom(
          privateKey,
          java.security.SecureRandom(),
        ),
      )
      val payloadBytes = payload.toByteArray(Charsets.UTF_8)
      signer.update(payloadBytes, 0, payloadBytes.size)
      val signature = signer.generateSignature()
      check(signature.size == MLDSA65_SIGNATURE_BYTES)
      base64UrlEncode(signature)
    } catch (e: Throwable) {
      android.util.Log.e("DeviceAuth", "signPayload FAILED: ${e.javaClass.simpleName}: ${e.message}", e)
      null
    }

  /** Verifies a signature against the persisted public key for debug diagnostics. */
  fun verifySelfSignature(
    payload: String,
    signatureBase64Url: String,
    identity: DeviceIdentity,
  ): Boolean =
    try {
      val rawPublicKey = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      val pubKey =
        org.bouncycastle.crypto.params.MLDSAPublicKeyParameters(
          org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
          rawPublicKey,
        )
      val sigBytes = base64UrlDecode(signatureBase64Url)
      val verifier =
        org.bouncycastle.crypto.signers
          .MLDSASigner()
      verifier.init(false, pubKey)
      val payloadBytes = payload.toByteArray(Charsets.UTF_8)
      verifier.update(payloadBytes, 0, payloadBytes.size)
      verifier.verifySignature(sigBytes)
    } catch (e: Throwable) {
      android.util.Log.e("DeviceAuth", "self-verify exception: ${e.message}", e)
      false
    }

  /** Decodes gateway URL-safe base64 signatures, accepting unpadded input. */
  private fun base64UrlDecode(input: String): ByteArray {
    val normalized = input.replace('-', '+').replace('_', '/')
    // Android Base64 expects padded input; gateway signatures are URL-safe
    // unpadded strings.
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return Base64.decode(padded, Base64.DEFAULT)
  }

  /** Returns the public key in the gateway's unpadded URL-safe base64 format. */
  fun publicKeyBase64Url(identity: DeviceIdentity): String? =
    try {
      val raw = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      base64UrlEncode(raw)
    } catch (_: Throwable) {
      null
    }

  private fun load(): DeviceIdentity? = readIdentity(prefs.getString(identityKey))

  private fun readIdentity(raw: String?): DeviceIdentity? {
    return try {
      if (raw == null) return null
      val decoded = json.decodeFromString(DeviceIdentity.serializer(), raw)
      if (decoded.deviceId.isBlank() ||
        decoded.publicKeyRawBase64.isBlank() ||
        decoded.privateKeyRawBase64.isBlank()
      ) {
        null
      } else {
        normalizeAndValidate(decoded)
      }
    } catch (_: Throwable) {
      null
    }
  }

  private fun retireLegacyIdentity() {
    if (!legacyIdentityFile.exists()) return
    // Legacy files contain Ed25519 keys and cannot authenticate to the ML-DSA-only gateway.
    // The caller reaches this point only after a new ML-DSA identity was synchronously
    // persisted and read back, so a storage failure can never destroy the only identity.
    check(legacyIdentityFile.delete() || !legacyIdentityFile.exists()) {
      "Failed to retire legacy Ed25519 device identity"
    }
  }

  private fun save(identity: DeviceIdentity) {
    val encoded = json.encodeToString(DeviceIdentity.serializer(), identity)
    check(identityWriter?.invoke(encoded) ?: prefs.putStringSynchronously(identityKey, encoded)) {
      "Failed to persist device identity"
    }
  }

  private fun generate(): DeviceIdentity {
    // Use BC's FIPS 204 lightweight API directly to avoid JCA provider issues with R8.
    val kpGen =
      org.bouncycastle.crypto.generators
        .MLDSAKeyPairGenerator()
    kpGen.init(
      org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters(
        java.security.SecureRandom(),
        org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
      ),
    )
    val kp = kpGen.generateKeyPair()
    val pubKey = kp.public as org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
    val privKey = kp.private as org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
    val rawPublic = pubKey.encoded
    val rawPrivate = privKey.encoded
    check(rawPublic.size == MLDSA65_PUBLIC_KEY_BYTES)
    check(rawPrivate.size == MLDSA65_PRIVATE_KEY_BYTES)
    val deviceId = sha256Hex(rawPublic)
    return DeviceIdentity(
      deviceId = deviceId,
      publicKeyRawBase64 = Base64.encodeToString(rawPublic, Base64.NO_WRAP),
      privateKeyRawBase64 = Base64.encodeToString(rawPrivate, Base64.NO_WRAP),
      createdAtMs = System.currentTimeMillis(),
    )
  }

  private fun normalizeAndValidate(identity: DeviceIdentity): DeviceIdentity? =
    try {
      val rawPublic = Base64.decode(identity.publicKeyRawBase64, Base64.DEFAULT)
      val rawPrivate = Base64.decode(identity.privateKeyRawBase64, Base64.DEFAULT)
      if (rawPublic.size != MLDSA65_PUBLIC_KEY_BYTES || rawPrivate.size != MLDSA65_PRIVATE_KEY_BYTES) {
        return null
      }
      val privateKey =
        org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters(
          org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65,
          rawPrivate,
        )
      if (!privateKey.publicKeyParameters.encoded.contentEquals(rawPublic)) {
        return null
      }
      identity.copy(deviceId = sha256Hex(rawPublic))
    } catch (_: Throwable) {
      null
    }

  /** Re-derives the stable device id from the raw ML-DSA-65 public key bytes. */
  private fun deriveDeviceId(publicKeyRawBase64: String): String? =
    try {
      val raw = Base64.decode(publicKeyRawBase64, Base64.DEFAULT)
      raw.takeIf { it.size == MLDSA65_PUBLIC_KEY_BYTES }?.let(::sha256Hex)
    } catch (_: Throwable) {
      null
    }

  private fun sha256Hex(data: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(data)
    val out = CharArray(digest.size * 2)
    var i = 0
    for (byte in digest) {
      val v = byte.toInt() and 0xff
      out[i++] = HEX[v ushr 4]
      out[i++] = HEX[v and 0x0f]
    }
    return String(out)
  }

  private fun base64UrlEncode(data: ByteArray): String =
    Base64.encodeToString(
      data,
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

  companion object {
    private const val identityKey = "device.identity.mldsa65"
    private const val MLDSA65_PUBLIC_KEY_BYTES = 1952
    private const val MLDSA65_PRIVATE_KEY_BYTES = 4032
    private const val MLDSA65_SIGNATURE_BYTES = 3309
    private val HEX = "0123456789abcdef".toCharArray()

    internal fun withPrefs(
      context: Context,
      prefs: SecurePrefs,
      identityWriter: ((String) -> Boolean)? = null,
    ): DeviceIdentityStore = DeviceIdentityStore(context, prefs, identityWriter)
  }
}
